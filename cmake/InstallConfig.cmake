# =============================================================================
# Install Rules & Layout
# =============================================================================

set(SRC ${CMAKE_SOURCE_DIR})
set(DST ${CMAKE_INSTALL_PREFIX})

# Repo-native authentication configuration is installed on every platform.
# Prepared third-party Dex executables remain outside the CMake install graph
# and are copied into the package by the platform packaging script.
set(APPMESH_INSTALL_AUTH_CONFIG ON)

# Configuration Files (Root)
install(FILES
    "${SRC}/src/daemon/config.yaml"
    "${SRC}/src/daemon/security/authorization.yaml"
    "${SRC}/src/daemon/security/oidc.yaml"
    DESTINATION "${DST}/config"
    COMPONENT configs
)

# Project and dependency notices are package contents. Prepared runtime
# components add their own exact upstream license beside these files later.
install(FILES
    "${SRC}/LICENSE"
    "${SRC}/NOTICE"
    DESTINATION "${DST}/share/licenses/appmesh"
    COMPONENT configs
)
install(DIRECTORY "${SRC}/THIRD_PARTY_LICENSES/"
    DESTINATION "${DST}/share/licenses/third-party"
    COMPONENT configs
)

if(APPMESH_INSTALL_AUTH_CONFIG)
    install(FILES
        "${SRC}/src/daemon/security/auth-stack.yaml"
        DESTINATION "${DST}/config"
        COMPONENT configs
    )
endif()

# Scripts (script/)
install(FILES
    "${SRC}/script/pack/grafana_infinity.html"
    "${SRC}/src/daemon/rest/openapi.yaml"
    "${SRC}/src/daemon/rest/index.html"
    $<$<BOOL:${UNIX}>:${SRC}/src/cli/bash_completion.sh>
    $<$<BOOL:${UNIX}>:${SRC}/src/cli/container_monitor.py>
    $<$<BOOL:${UNIX}>:${SRC}/src/cli/appmesh_agent.py>
    DESTINATION "${DST}/script"
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
    COMPONENT scripts
)

# Service Files
install(PROGRAMS
    "${SRC}/script/pack/appmesh.systemd.service"
    "${SRC}/script/pack/appmesh.initd.sh"
    "${SRC}/script/pack/setup.sh"
    DESTINATION "${DST}/script"
    COMPONENT scripts)

# Docker/Prometheus configs
if(UNIX)
    install(DIRECTORY "${SRC}/script/docker/"
        DESTINATION "${DST}/script"
        COMPONENT scripts
        FILES_MATCHING PATTERN "*.yml" PATTERN "*.yaml"
    )
endif()

# SSL Scripts (ssl/)
# PROGRAMS, not FILES: docker-entrypoint.sh requires the executable bit.
install(PROGRAMS "${SRC}/script/ssl/generate_ssl_cert.sh" DESTINATION "${DST}/ssl" COMPONENT scripts)
