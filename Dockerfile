# syntax=docker/dockerfile:1
##################################################################################
# App Mesh Docker Container:
#  1. Run the daemon and register a long-running startup command
#     docker run -d laoshanxi/appmesh ping github.com
#  2. Run a native one-shot command after the "appm" marker
#     docker run --rm laoshanxi/appmesh appm /opt/appmesh/bin/appm -V
#     Protected API requests such as `appm ls` require an
#     interactive login or an explicitly supplied bearer token.
#  Build targets:
#     appmesh    - default runtime without llm-agent
#     llm_agent  - optional runtime with llm-agent app and requirements
#     mcp_server - optional runtime with the MCP server (src/integrations/mcp-server)
##################################################################################
FROM laoshanxi/appmesh:build_ubuntu22 AS build_stage
WORKDIR /workspace/app-mesh
# Build the checked-out workflow revision from the Docker context. Cloning the
# default branch here could publish a different commit than the triggering SHA.
COPY . .
RUN cmake -DOPENSSL_ROOT_DIR=/usr/local/ssl -B build -G Ninja && \
    cmake --build build --target pack --parallel

FROM python:slim-bookworm AS runtime_base
ARG APPMESH_ID=482
# Native processes keep the fixed container identity.
ENV APPMESH_BaseConfig_DisableExecUser=true
# Listen on all container interfaces.
ENV APPMESH_REST_RestListenAddress=0.0.0.0
# TLS uses the packaged ssl/ directory like a native install. Install-time
# certificates are deleted; the entrypoint regenerates them on first boot.
ENV APPMESH_AUTH_MODE=builtin
COPY --chmod=0755 --from=build_stage /workspace/app-mesh/script/pack/docker-entrypoint.sh /opt/appmesh/script/
# CACHE_EPOCH busts the install layer: a stage bind-mount's content is not part
# of the cache key, so pass a new value when the build stage output changes.
ARG CACHE_EPOCH=0
RUN --mount=type=bind,from=build_stage,source=/workspace/app-mesh/build,target=/tmp/build \
	echo "cache epoch ${CACHE_EPOCH}" && \
	apt-get update && \
	apt-get install -y --no-install-recommends tini /tmp/build/appmesh*.deb && \
	pip3 install --break-system-packages --no-cache-dir appmesh && \
	apt-get clean && \
	rm -rf /var/lib/apt/lists/* /var/cache/* /var/tmp/* \
		/usr/share/doc /usr/share/man /usr/share/locale /usr/share/info \
		/var/lib/dpkg/info/*.md5sums && \
	rm -rf /opt/appmesh/apps/ping.yaml /opt/appmesh/apps/llm-agent.yaml \
		/opt/appmesh/lib/llm-agent /opt/appmesh/ssl/cfssl* && \
	find /opt/appmesh/work -mindepth 1 -maxdepth 1 -exec rm -rf -- '{}' + && \
	rm -f /opt/appmesh/ssl/ca.pem /opt/appmesh/ssl/ca-key.pem \
		/opt/appmesh/ssl/server.pem /opt/appmesh/ssl/server-key.pem \
		/opt/appmesh/ssl/client.pem /opt/appmesh/ssl/client-key.pem \
		/opt/appmesh/ssl/*.csr && \
	groupadd -r -g "$APPMESH_ID" appmesh && \
	useradd -m -r -u "$APPMESH_ID" -g appmesh appmesh && \
	install -d -m 0700 -o appmesh -g appmesh /opt/appmesh/work && \
	install -d -m 0700 -o appmesh -g appmesh /opt/appmesh/ssl && \
	# Shared with followers (read-only volume) for cluster authorization replication.
	# work/auth is created here so install never manufactures a root-owned intermediate.
	install -d -m 0700 -o appmesh -g appmesh /opt/appmesh/work/auth && \
	install -d -m 0755 -o appmesh -g appmesh /opt/appmesh/work/auth/replication && \
	install -m 0640 -o appmesh -g appmesh /dev/null /opt/appmesh/appmesh.pid && \
	chown root:appmesh /opt/appmesh/config/authorization.yaml && \
	chmod 0640 /opt/appmesh/config/authorization.yaml && \
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
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/apps/llm-agent/llm_agent/ /opt/appmesh/lib/llm-agent/llm_agent/
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/apps/llm-agent/requirements.txt /opt/appmesh/lib/llm-agent/requirements.txt
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/apps/llm-agent/config/llm-agent.yaml /opt/appmesh/apps/llm-agent.yaml
# Optional llm-agent deps; includes Claude Code.
RUN pip3 install --break-system-packages --no-cache-dir -r /opt/appmesh/lib/llm-agent/requirements.txt && \
    # This image runs the agent: auto-start the App on boot.
    sed -i 's/^enabled: false$/enabled: true/' /opt/appmesh/apps/llm-agent.yaml && \
    grep -q '^enabled: true$' /opt/appmesh/apps/llm-agent.yaml
USER ${APPMESH_ID}:${APPMESH_ID}

# MCP server runtime (src/integrations/mcp-server): Streamable HTTP on 6071,
# an OAuth resource server fronting the engine. Configuration is
# environment-driven (see src/integrations/mcp-server/README.md).
FROM runtime_base AS mcp_server
USER root
COPY --from=build_stage --chown=appmesh:appmesh /workspace/app-mesh/src/integrations/mcp-server/ /opt/appmesh/integrations/mcp-server/
RUN pip3 install --break-system-packages --no-cache-dir -r /opt/appmesh/integrations/mcp-server/requirements.txt && \
    python3 -c "import fastmcp, appmesh"
USER ${APPMESH_ID}:${APPMESH_ID}
WORKDIR /opt/appmesh/integrations/mcp-server
EXPOSE 6071
ENTRYPOINT ["tini", "--", "python3", "appmesh_server.py"]

FROM runtime_base AS appmesh
