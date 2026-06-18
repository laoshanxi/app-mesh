# src/sdk/llm-agent/CMakeLists.txt
# =============================================================================
# llm-agent — the LLM agent runtime (Python). Packaging only: there is nothing to
# compile. We ship the `llm_agent` package under <prefix>/lib/llm-agent and register
# the Scenario A App so the daemon auto-loads it (like the other pre-installed apps).
# =============================================================================

set(LLMAGENT_SRC "${CMAKE_CURRENT_SOURCE_DIR}")

# 1. The Python package (so `python3 -m llm_agent` resolves from working_dir).
install(
    DIRECTORY "${LLMAGENT_SRC}/llm_agent"
    DESTINATION "lib/llm-agent"
    COMPONENT configs
    FILES_MATCHING PATTERN "*.py"
)

# 1b. requirements.txt — shipped so the Docker image (and operators) can install deps
#     via `pip install -r <prefix>/lib/llm-agent/requirements.txt` (single source of truth).
install(FILES "${LLMAGENT_SRC}/requirements.txt"
    DESTINATION "lib/llm-agent"
    COMPONENT configs
)

# 2. The Scenario A App definition → apps/ (auto-loaded by the daemon).
#    The committed yaml's working_dir (/opt/appmesh/lib/llm-agent) is the install
#    location of the package above for the packaged distribution (nfpm relocates the
#    build prefix to /opt/appmesh). We deliberately do NOT rewrite it at install time:
#    during `make pack` CMAKE_INSTALL_PREFIX is a throwaway staging dir, so baking it in
#    would point working_dir at a path that exists only on the build host. A source
#    install to a custom prefix adjusts the yaml's working_dir by hand (see its comment).
install(FILES "${LLMAGENT_SRC}/config/llm-agent.yaml"
    DESTINATION "apps"
    COMPONENT configs
)

# Scenario B worker template, example tool, and examples are operator-deployed by
# hand (per-session worker, demo tool), so they are documentation/templates — not
# auto-registered here. See config/llm-agent-worker.yaml and examples/.
