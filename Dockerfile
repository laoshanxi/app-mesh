##################################################################################
# App Mesh Docker Container:
#  docker container, accept parameters as bellow format:
#  1. Run docker container and register a long running application
#     docker run -d laoshanxi/appmesh ping github.com
#  2. Run docker container and excute an external cmd
#     docker run -d laoshanxi/appmesh appc ls
##################################################################################
FROM laoshanxi/appmesh:build_ubuntu22 AS build_stage
WORKDIR /workspace
RUN bash -c 'git clone https://github.com/laoshanxi/app-mesh.git && \
    cd app-mesh && mkdir build && cd build && \
    cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl .. && \
    make -j"$(nproc)" && make pack'

FROM python:3.13.7-slim-bookworm
ARG AM_UID="482"
ARG AM_GID="482"
# not enable exec user in container
ENV APPMESH_BaseConfig_DisableExecUser=true
# not only listen 127.0.0.1
ENV APPMESH_REST_RestListenAddress=0.0.0.0
COPY --from=build_stage /workspace/app-mesh/build/appmesh*.deb .
RUN bash -c "ls && apt-get update && \
	apt-get install -y tini && \
	apt-get install -y ./appmesh*.deb && \
	pip3 install --break-system-packages --no-cache-dir appmesh && \
	rm -f ./appmesh*.deb && apt-get clean && rm -rf /var/lib/apt/lists/* && \
	rm -rf /opt/appmesh/apps/ping.yaml /opt/appmesh/ssl/cfssl* /opt/appmesh/apps/backup.yaml && \
	groupadd -r -g $AM_GID appmesh && useradd -m -r -u $AM_UID -g appmesh appmesh && \
	ln -s /opt/appmesh/script/entrypoint.sh /entrypoint.sh && \
	touch /opt/appmesh/appmesh.pid && \
	chown -R appmesh:appmesh /opt/appmesh/ && \
	. /usr/local/bin/appc -v && /opt/appmesh/bin/appsvc -v"
EXPOSE 6060
USER appmesh
WORKDIR /opt/appmesh/work/
ENTRYPOINT ["tini", "--", "/entrypoint.sh"]
STOPSIGNAL SIGTERM
