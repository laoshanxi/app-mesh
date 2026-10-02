# =============================================================================
# Windows App Definition Patch
# =============================================================================
# App definitions (apps/*.yaml) are installed by their owning directories under
# src/apps/. Install rules run in declaration order, so this file must be
# included after add_subdirectory(src): the patch reads the installed copies.
# =============================================================================

if(WIN32)
    install(CODE [[
        set(_apps_dir "$ENV{DESTDIR}${CMAKE_INSTALL_PREFIX}/apps")
        message(STATUS "Patching Windows app configs in: ${_apps_dir}")
        file(GLOB _app_yamls "${_apps_dir}/*.yaml")
        foreach(_yml IN LISTS _app_yamls)
            file(READ "${_yml}" _content)
            # Simple + reliable replacement
            string(REPLACE "python3" "python.exe" _content "${_content}")
            get_filename_component(_app_name "${_yml}" NAME)
            if(_app_name STREQUAL "identity.yaml" OR _app_name STREQUAL "dexuser.yaml")
                # Like the daemon-generated agent App, select the native launcher
                # for Windows while keeping the same System App definition.
                string(REPLACE
                    "../../script/appmesh-auth.sh"
                    "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File ../../script/appmesh-auth.ps1"
                    _content "${_content}")
            endif()
            file(WRITE "${_yml}" "${_content}")
            message(STATUS "Patched (Windows): ${_yml}")
        endforeach()
    ]] COMPONENT configs)
endif()
