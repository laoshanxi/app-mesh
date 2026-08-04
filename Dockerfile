# syntax=docker/dockerfile:1
##################################################################################
# App Mesh Docker Container:
#  docker container, accept parameters as bellow format:
#  1. Run docker container and register a long running application
#     docker run -d laoshanxi/appmesh ping github.com
#  2. Run docker container and excute an external cmd
#     docker run -d laoshanxi/appmesh appm ls
#  3. Run with root permission (for AI remote execution, pip install, etc.)
#     docker run -d -e APPMESH_RUN_AS_ROOT=true laoshanxi/appmesh
#  Build targets:
#     appmesh    - default runtime without llm-agent
#     llm_agent  - optional runtime with llm-agent app and requirements
##################################################################################
FROM laoshanxi/appmesh:build_ubuntu22 AS build_stage
WORKDIR /workspace
RUN bash -c 'git clone --depth 1 https://github.com/laoshanxi/app-mesh.git && \
    cd app-mesh && \
    cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl -B build -G Ninja && \
    cmake --build build --target pack --parallel'

FROM python:slim-bookworm AS runtime_base
ARG AM_UID="482"
ARG AM_GID="482"
# not enable exec user in container
ENV APPMESH_BaseConfig_DisableExecUser=true
# not only listen 127.0.0.1
ENV APPMESH_REST_RestListenAddress=0.0.0.0
COPY --from=build_stage /workspace/app-mesh/script/pack/docker-entrypoint.sh /opt/appmesh/script/
RUN --mount=type=bind,from=build_stage,source=/workspace/app-mesh/build,target=/tmp/build \
	apt-get update && \
	apt-get install -y --no-install-recommends tini /tmp/build/appmesh*.deb && \
	pip3 install --break-system-packages --no-cache-dir appmesh && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /var/cache/* /var/tmp/* \
		/usr/share/doc /usr/share/man /usr/share/locale /usr/share/info \
		/var/lib/dpkg/info/*.md5sums && \
	rm -rf /opt/appmesh/apps/ping.yaml /opt/appmesh/apps/llm-agent.yaml \
		/opt/appmesh/lib/llm-agent /opt/appmesh/ssl/cfssl* && \
	(groupadd -r -g $AM_GID appmesh && useradd -m -r -u $AM_UID -g appmesh appmesh) || true && \
	ln -s /opt/appmesh/script/docker-entrypoint.sh /entrypoint.sh && \
	touch /opt/appmesh/appmesh.pid && \
	(id -u appmesh >/dev/null 2>&1 && chown -R appmesh:appmesh /opt/appmesh/) || true && \
	ldd /usr/local/bin/appm && /usr/local/bin/appm -V && /opt/appmesh/bin/appmesh -V
EXPOSE 6060
# USER is determined at runtime by docker-entrypoint.sh via setpriv:
#   default: drops to 'appmesh' user (secure)
#   APPMESH_RUN_AS_ROOT=true: stays as root (for pip/apt/AI execution)
WORKDIR /opt/appmesh/work/
ENTRYPOINT ["tini", "--", "/entrypoint.sh"]
STOPSIGNAL SIGTERM

FROM runtime_base AS llm_agent
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/sdk/llm-agent/llm_agent/ /opt/appmesh/lib/llm-agent/llm_agent/
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/sdk/llm-agent/requirements.txt /opt/appmesh/lib/llm-agent/requirements.txt
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/sdk/llm-agent/config/llm-agent.yaml /opt/appmesh/apps/llm-agent.yaml
# Optional llm-agent deps; includes Claude Code.
RUN pip3 install --break-system-packages --no-cache-dir -r /opt/appmesh/lib/llm-agent/requirements.txt

FROM runtime_base AS appmesh
