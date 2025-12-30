# =============================================================================
# Install Rules & Layout
# =============================================================================

set(SRC ${CMAKE_SOURCE_DIR})
set(DST ${CMAKE_INSTALL_PREFIX})

# Configuration Files (Root)
install(FILES
    "${SRC}/src/daemon/config.yaml"
    "${SRC}/src/daemon/security/security.yaml"
    "${SRC}/src/daemon/security/oauth2.yaml"
    "${SRC}/src/sdk/agent/pkg/cloud/consul.yaml"
    DESTINATION "${DST}/config"
    COMPONENT configs
)

# Application Configs (apps/)
install(
    DIRECTORY "${SRC}/script/apps/"
    DESTINATION "${DST}/apps"
    COMPONENT configs
    FILES_MATCHING PATTERN "*.yaml"
)

if(WIN32)
    install(CODE [[
        set(_apps_dir "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/${DST}/apps")
        message(STATUS "Patching Windows app configs in: ${_apps_dir}")
        file(GLOB _app_yamls "${_apps_dir}/*.yaml")
        foreach(_yml IN LISTS _app_yamls)
            file(READ "${_yml}" _content)
            # Simple + reliable replacement
            string(REPLACE "python3" "python.exe" _content "${_content}")
            file(WRITE "${_yml}" "${_content}")
            message(STATUS "Patched (Windows): ${_yml}")
        endforeach()
    ]] COMPONENT configs)
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

# OS-Specific Service Files
if(APPLE)
    install(FILES
        "${SRC}/script/pack/appmesh.launchd.plist"
        "${SRC}/script/pack/appmesh.initd.sh"
        "${SRC}/script/pack/entrypoint.sh"
        "${SRC}/script/pack/setup.sh"
        DESTINATION "${DST}/script"
        COMPONENT scripts)
    install(PROGRAMS "${SRC}/script/pack/post_install.sh" DESTINATION "${CMAKE_BINARY_DIR}/pkg_scripts" RENAME postinstall COMPONENT scripts)
    install(PROGRAMS "${SRC}/script/pack/pre_uninstall.sh" DESTINATION "${CMAKE_BINARY_DIR}/pkg_scripts" RENAME preuninstall COMPONENT scripts)
    install(PROGRAMS "${SRC}/script/pack/post_uninstall.sh" DESTINATION "${CMAKE_BINARY_DIR}/pkg_scripts" RENAME postuninstall COMPONENT scripts)
elseif(UNIX)
    install(PROGRAMS 
        "${SRC}/script/pack/appmesh.systemd.service"
        "${SRC}/script/pack/appmesh.initd.sh"
        "${SRC}/script/pack/entrypoint.sh"
        "${SRC}/script/pack/setup.sh"
        DESTINATION "${DST}/script"
        COMPONENT scripts)
endif()

# Docker/Prometheus configs
if(UNIX)
    install(DIRECTORY "${SRC}/script/docker/"
        DESTINATION "${DST}/script"
        COMPONENT scripts
        FILES_MATCHING PATTERN "*.yml" PATTERN "*.yaml"
    )
endif()

# SSL Scripts and Binaries (ssl/)
if(WIN32)
    install(FILES "${SRC}/script/ssl/generate_ssl_cert.ps1" DESTINATION "${DST}/ssl" COMPONENT scripts)
else()
    install(FILES "${SRC}/script/ssl/generate_ssl_cert.sh" DESTINATION "${DST}/ssl" COMPONENT scripts)
    # TODO: macOS ssl can not work with pure openssl 
    if(APPLE)
        foreach(bin cfssl cfssljson)
            install(PROGRAMS "/usr/local/bin/${bin}" DESTINATION "${DST}/ssl" COMPONENT scripts)
        endforeach()
    endif()
endif()

# Python tool (bin/)
install(DIRECTORY "${SRC}/src/sdk/python/"
    DESTINATION "${DST}/bin"
    COMPONENT binaries
    FILES_MATCHING PATTERN "py_*.py"
    PERMISSIONS OWNER_EXECUTE OWNER_WRITE OWNER_READ GROUP_READ GROUP_EXECUTE WORLD_READ WORLD_EXECUTE
)

# Windows: NSSM Service Manager
if(WIN32)
    file(TO_CMAKE_PATH "$ENV{ChocolateyInstall}/lib/nssm/tools/nssm.exe" NSSM_EXE)
    install(PROGRAMS "${NSSM_EXE}" DESTINATION "${DST}/bin" COMPONENT binaries)
endif()
