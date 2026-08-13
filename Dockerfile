# syntax=docker/dockerfile:1
##################################################################################
# App Mesh Docker Container:
#  1. Run the daemon and register a long-running startup command
#     docker run -d laoshanxi/appmesh ping github.com
#  2. Run a native one-shot command after the "appm" marker
#     docker run --rm laoshanxi/appmesh appm ls
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
ARG APPMESH_ID=482
# Native processes keep the fixed container identity.
ENV APPMESH_BaseConfig_DisableExecUser=true
# Listen on all container interfaces.
ENV APPMESH_REST_RestListenAddress=0.0.0.0
COPY --chmod=0755 --from=build_stage /workspace/app-mesh/script/pack/docker-entrypoint.sh /opt/appmesh/script/
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
	groupadd -r -g "$APPMESH_ID" appmesh && \
	useradd -m -r -u "$APPMESH_ID" -g appmesh appmesh && \
	touch /opt/appmesh/appmesh.pid && \
	chown -R appmesh:appmesh /opt/appmesh && \
	ldd /usr/local/bin/appm && /usr/local/bin/appm -V && /opt/appmesh/bin/appmesh -V
EXPOSE 6060
# Native managed processes inherit this identity.
# docker_image applications use their image's USER.
USER ${APPMESH_ID}:${APPMESH_ID}
WORKDIR /opt/appmesh/work/
ENTRYPOINT ["tini", "--", "/opt/appmesh/script/docker-entrypoint.sh"]
STOPSIGNAL SIGTERM

FROM runtime_base AS llm_agent
# Build-time package installation; the published target resets to appmesh below.
USER root
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/sdk/llm-agent/llm_agent/ /opt/appmesh/lib/llm-agent/llm_agent/
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/sdk/llm-agent/requirements.txt /opt/appmesh/lib/llm-agent/requirements.txt
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/sdk/llm-agent/config/llm-agent.yaml /opt/appmesh/apps/llm-agent.yaml
# Optional llm-agent deps; includes Claude Code.
RUN pip3 install --break-system-packages --no-cache-dir -r /opt/appmesh/lib/llm-agent/requirements.txt
USER ${APPMESH_ID}:${APPMESH_ID}

FROM runtime_base AS appmesh
