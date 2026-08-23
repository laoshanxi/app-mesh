# =============================================================================
# Install Rules & Layout
# =============================================================================

set(SRC ${CMAKE_SOURCE_DIR})
set(DST ${CMAKE_INSTALL_PREFIX})

# Repo-native authentication configuration is installed for Linux and macOS
# packages. Prepared third-party executables remain outside the CMake install
# graph. Windows keeps external-issuer-only deployments.
set(APPMESH_INSTALL_AUTH_CONFIG OFF)
if(UNIX)
    set(APPMESH_INSTALL_AUTH_CONFIG ON)
endif()

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
        "${SRC}/src/auth/dex.yaml"
        DESTINATION "${DST}/config"
        COMPONENT configs
    )
endif()

# Application Configs (apps/). The auth System Apps ship only where the
# bundled auth stack is installed.
set(APPS_EXCLUDE_AUTH PATTERN "auth-*.yaml" EXCLUDE)
if(APPMESH_INSTALL_AUTH_CONFIG)
    set(APPS_EXCLUDE_AUTH "")
endif()
install(
    DIRECTORY "${SRC}/script/apps/"
    DESTINATION "${DST}/apps"
    COMPONENT configs
    FILES_MATCHING PATTERN "*.yaml" ${APPS_EXCLUDE_AUTH}
)

if(WIN32)
    install(CODE [[
        set(_apps_dir "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/apps")
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
    install(PROGRAMS
        "${SRC}/script/pack/appmesh.launchd.plist"
        "${SRC}/script/pack/appmesh.initd.sh"
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
        "${SRC}/script/pack/setup.sh"
        DESTINATION "${DST}/script"
        COMPONENT scripts)
else()
    # Windows is external-issuer-only: setup.ps1 covers the setup.sh surface
    # that applies there (issuer/routing/TLS into work/config/oidc.yaml).
    install(PROGRAMS "${SRC}/script/pack/setup.ps1"
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
    # openssl.exe and runtime DLLs (or copy cfssl is also fine)
    find_program(OPENSSL_EXECUTABLE NAMES openssl REQUIRED)
    get_filename_component(OPENSSL_BIN_DIR "${OPENSSL_EXECUTABLE}" DIRECTORY)
    install(PROGRAMS "${OPENSSL_BIN_DIR}/openssl.exe" DESTINATION "${DST}/bin" COMPONENT runtime)
    file(GLOB OPENSSL_RUNTIME_DLLS
        "${OPENSSL_BIN_DIR}/libssl*.dll"
        "${OPENSSL_BIN_DIR}/libcrypto*.dll"
    )
    install(FILES ${OPENSSL_RUNTIME_DLLS} DESTINATION "${DST}/bin" COMPONENT runtime)
else()
    # PROGRAMS, not FILES: docker-entrypoint.sh requires the executable bit.
    install(PROGRAMS "${SRC}/script/ssl/generate_ssl_cert.sh" DESTINATION "${DST}/ssl" COMPONENT scripts)
    # TODO: macOS ssl can not work with pure openssl 
    if(APPLE)
        foreach(bin cfssl cfssljson)
            # cfssl lives at /usr/local/bin by bootstrap contract (install_build_deps*.sh pin GOBIN)
            install(PROGRAMS "/usr/local/bin/${bin}" DESTINATION "${DST}/ssl" COMPONENT scripts)
        endforeach()
    endif()
endif()

# Python tool (bin/)
install(PROGRAMS
    "${SRC}/src/sdk/python/py_exec.py"
    "${SRC}/src/sdk/python/py_task.py"
    DESTINATION "${DST}/bin"
    COMPONENT binaries
)

if(APPMESH_INSTALL_AUTH_CONFIG)
    install(PROGRAMS
        "${SRC}/src/auth/appmesh-auth.sh"
        DESTINATION "${DST}/script"
        COMPONENT scripts
    )
endif()

# Windows: NSSM Service Manager
if(WIN32)
    file(TO_CMAKE_PATH "$ENV{ChocolateyInstall}/lib/nssm/tools/nssm.exe" NSSM_EXE)
    install(PROGRAMS "${NSSM_EXE}" DESTINATION "${DST}/bin" COMPONENT binaries)
endif()
