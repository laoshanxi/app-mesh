##################################################################################
# App Mesh Docker Container:
#  docker container, accept parameters as bellow format:
#  1. Run docker container and register a long running application
#     docker run -d laoshanxi/appmesh ping github.com
#  2. Run docker container and excute an external cmd
#     docker run -d laoshanxi/appmesh appc ls
#  3. Run with root permission (for AI remote execution, pip install, etc.)
#     docker run -d -e APPMESH_RUN_AS_ROOT=true laoshanxi/appmesh
##################################################################################
FROM laoshanxi/appmesh:build_ubuntu22@sha256:0aa512205f0efe6a83a63817cc9580219203971754af2da536d5e0fce34aa277 AS build_stage
WORKDIR /workspace
RUN bash -c 'git clone --depth 1 https://github.com/laoshanxi/app-mesh.git && \
    cd app-mesh && \
    cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl -B build -G Ninja && \
    cmake --build build --target pack --parallel'

FROM python:3.13.7-slim-bookworm@sha256:adafcc17694d715c905b4c7bebd96907a1fd5cf183395f0ebc4d3428bd22d92d
ARG AM_UID="482"
ARG AM_GID="482"
# not enable exec user in container
ENV APPMESH_BaseConfig_DisableExecUser=true
# not only listen 127.0.0.1
ENV APPMESH_REST_RestListenAddress=0.0.0.0
COPY --from=build_stage /workspace/app-mesh/build/appmesh*.deb .
COPY --from=build_stage /workspace/app-mesh/script/pack/docker-entrypoint.sh /opt/appmesh/script/
RUN bash -c "ls && apt-get update && \
	apt-get install -y --no-install-recommends tini gosu && \
	apt-get install -y ./appmesh*.deb && \
	pip3 install --break-system-packages --no-cache-dir appmesh && \
	rm -f ./appmesh*.deb && apt-get clean && \
	rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /var/tmp/* \
		/usr/share/doc /usr/share/man /usr/share/locale /usr/share/info \
		/var/lib/dpkg/info/*.md5sums && \
	rm -rf /opt/appmesh/apps/ping.yaml /opt/appmesh/ssl/cfssl* && \
	(groupadd -r -g $AM_GID appmesh && useradd -m -r -u $AM_UID -g appmesh appmesh) || true && \
	ln -s /opt/appmesh/script/docker-entrypoint.sh /entrypoint.sh && \
	touch /opt/appmesh/appmesh.pid && \
	(id -u appmesh >/dev/null 2>&1 && chown -R appmesh:appmesh /opt/appmesh/) || true && \
	ldd /usr/local/bin/appc && /usr/local/bin/appc -v && /opt/appmesh/bin/appsvc -v"
EXPOSE 6060
# USER is determined at runtime by docker-entrypoint.sh via gosu:
#   default: drops to 'appmesh' user (secure)
#   APPMESH_RUN_AS_ROOT=true: stays as root (for pip/apt/AI execution)
WORKDIR /opt/appmesh/work/
ENTRYPOINT ["tini", "--", "/entrypoint.sh"]
STOPSIGNAL SIGTERM
