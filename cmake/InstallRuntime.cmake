# cmake/InstallRuntime.cmake

# Windows Implementation
function(_install_runtime_win32 target)
    install(TARGETS ${target}
        RUNTIME_DEPENDENCIES
            # Directories for search libraries (vcpkg already involve from toolchain file)
            DIRECTORIES
                "C:/local/bin"

            # Exclude Windows System DLLs (Kernel32, User32, etc.)
            PRE_EXCLUDE_REGEXES
                "api-ms-.*"
                "ext-ms-.*"
            POST_EXCLUDE_REGEXES
                ".*[Ww]indows[/\\\\][Ss]ystem32.*"
                ".*[Ww]indows[/\\\\][Ss]y[Ss][Ww]o[Ww]64.*"
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime
    )
endfunction()

# macOS Implementation
function(_install_runtime_apple target allowed_prefixes)
    # TODO: macOS packed extra OS libraries
    # Default whitelist: only collect from Homebrew, not system libraries
    if(NOT allowed_prefixes)
        set(allowed_prefixes
            "/opt/homebrew/"
            "/usr/local/"
            "${CMAKE_BINARY_DIR}/"
        )
    endif()

    # Set RPATH for the target
    set_target_properties(${target} PROPERTIES
        INSTALL_RPATH "@executable_path/../${CMAKE_INSTALL_LIBDIR}"
        BUILD_WITH_INSTALL_RPATH FALSE
        INSTALL_RPATH_USE_LINK_PATH FALSE
    )

    # Install executable
    install(TARGETS ${target}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime
    )

    # Values used by the install-time fixup script below.
    install(CODE "
        set(_target_name \"${target}\")
        set(_target_file \"$<TARGET_FILE:${target}>\")
        set(_target_file_name \"$<TARGET_FILE_NAME:${target}>\")
        set(_allowed_prefixes \"${allowed_prefixes}\")
        set(_install_bindir \"${CMAKE_INSTALL_BINDIR}\")
        set(_install_libdir \"${CMAKE_INSTALL_LIBDIR}\")
    " COMPONENT Runtime)

    # Collect dependencies, copy libraries, and fix install names
    install(CODE [=[
        set(_executable_path "${CMAKE_INSTALL_PREFIX}/${_install_bindir}/${_target_file_name}")
        set(_lib_dest "${CMAKE_INSTALL_PREFIX}/${_install_libdir}")

        # Initialize list of files that need their dependencies fixed
        # We start with the main executable
        set(_files_to_fix "${_executable_path}")

        message(STATUS "[install_runtime] Processing: ${_executable_path}")

        file(GET_RUNTIME_DEPENDENCIES
            EXECUTABLES "${_target_file}"
            RESOLVED_DEPENDENCIES_VAR _r_deps
            UNRESOLVED_DEPENDENCIES_VAR _u_deps

            # Exclude system pseudo-libs
            PRE_EXCLUDE_REGEXES
                "^/usr/lib/.*"
                "^/System/.*"
                "^/Library/.*"
                "libSystem\\..*"
                "libc\\+\\+\\..*"
                "libobjc\\..*"

            POST_EXCLUDE_REGEXES
                "^/usr/lib/.*"
                "^/System/.*"
                "^/Library/.*"
        )

        # Track which libraries we've already processed (for deduplication)
        set(_processed_libs "")
        # Track mapping: resolved_path|library_name
        set(_lib_mappings "")

        # Filter and copy only libraries matching the whitelist
        foreach(_file IN LISTS _r_deps)
            set(_should_copy FALSE)

            foreach(_prefix IN LISTS _allowed_prefixes)
                string(FIND "${_file}" "${_prefix}" _pos)
                if(_pos EQUAL 0)
                    set(_should_copy TRUE)
                    break()
                endif()
            endforeach()

            if(_should_copy)
                # Get the library name as referenced by the binary
                get_filename_component(_dep_name "${_file}" NAME)

                # Skip if already processed
                if("${_dep_name}" IN_LIST _processed_libs)
                    continue()
                endif()
                list(APPEND _processed_libs "${_dep_name}")

                # Resolve symlink to actual file
                get_filename_component(_real_file "${_file}" REALPATH)

                message(STATUS "[install_runtime] Copying: ${_dep_name} (from ${_real_file})")

                # Copy the library
                file(INSTALL
                    DESTINATION "${_lib_dest}"
                    TYPE FILE
                    RENAME "${_dep_name}"
                    FILES "${_real_file}"
                )

                # Fix the ID of the library itself
                execute_process(
                    COMMAND install_name_tool -id "@rpath/${_dep_name}" "${_lib_dest}/${_dep_name}"
                    ERROR_QUIET
                )

                # Add this new library to the list of files that need to be inspected and fixed
                list(APPEND _files_to_fix "${_lib_dest}/${_dep_name}")

                # Store mapping: RealPath|LibName
                list(APPEND _lib_mappings "${_file}|${_dep_name}")
            endif()
        endforeach()

        # Loop over BOTH the executable AND all copied libraries to fix their dependencies
        foreach(_target_file IN LISTS _files_to_fix)

            # specific message for debugging
            # message(STATUS "[install_runtime] Inspecting dependencies for: ${_target_file}")

            execute_process(
                COMMAND otool -L "${_target_file}"
                OUTPUT_VARIABLE _otool_out
                ERROR_VARIABLE _otool_err
            )

            foreach(_mapping IN LISTS _lib_mappings)
                string(REPLACE "|" ";" _parts "${_mapping}")
                list(GET _parts 0 _resolved_path)
                list(GET _parts 1 _dep_name)

                # Match: whitespace + path ending with libname + space + '('
                string(REGEX MATCH "[ \t]([^ \t\n\r]+/${_dep_name}) \\(" _match_line "${_otool_out}")

                if(_match_line)
                    string(REGEX REPLACE "[ \t]([^ \t\n\r]+/${_dep_name}) \\(" "\\1" _change_from "${_match_line}")

                    # Only rewrite if it's not already using @rpath
                    string(FIND "${_change_from}" "@rpath" _rpath_pos)
                    if(_rpath_pos EQUAL -1)
                        message(STATUS "[install_runtime] Fixing ${_target_file}: ${_change_from} -> @rpath/${_dep_name}")
                        execute_process(
                            COMMAND install_name_tool -change "${_change_from}" "@rpath/${_dep_name}" "${_target_file}"
                            ERROR_QUIET
                        )
                    endif()
                endif()
            endforeach()

            # Ensure every file has the correct RPATH so it can find its neighbors
            execute_process(
                COMMAND install_name_tool -add_rpath "@loader_path/" "${_target_file}"
                ERROR_QUIET
            )
        endforeach()

        # Ensure the main executable also has the loader path to the lib dir
        execute_process(
            COMMAND install_name_tool -add_rpath "@executable_path/../${_install_libdir}" "${_executable_path}"
            ERROR_QUIET
        )

        if(_u_deps)
            message(STATUS "[install_runtime] Unresolved dependencies (expected): ${_u_deps}")
        endif()

        message(STATUS "[install_runtime] Completed: ${_target_name}")
    ]=] COMPONENT Runtime)
endfunction()

# Linux Implementation
function(_install_runtime_linux target)
    # Set RPATH for the target - $ORIGIN allows relocation
    set_target_properties(${target} PROPERTIES
        INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}"
        BUILD_WITH_INSTALL_RPATH FALSE
        INSTALL_RPATH_USE_LINK_PATH FALSE
    )

    # Bundle every dependency the platform does not ship. Distro packages
    # (apt/dpkg) install into system paths, so no prefix filter applies here.
    # LIBRARY also sets the destination and component of the bundled libraries.
    install(TARGETS ${target}
        RUNTIME_DEPENDENCIES
            # Source builds install their dependencies here; bundled libraries
            # have no RUNPATH, so transitive dependencies need this search path.
            DIRECTORIES
                "/usr/local/lib"
                "/usr/local/ssl/lib"
            # Exclude the loader and the glibc / C++ / zlib runtimes
            PRE_EXCLUDE_REGEXES
                "ld-linux.*"
                "linux-vdso.*"
            POST_EXCLUDE_REGEXES
                ".*/lib(c|m|dl|pthread|rt|resolv|nsl|util|anl|mvec)[.]so.*"
                ".*/lib(gcc_s|stdc[+][+]|atomic|z)[.]so.*"
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime
    )
endfunction()

# ==============================================================================
# install_runtime Function
# ==============================================================================
function(install_runtime)
    set(options)
    set(oneValueArgs TARGET)
    set(multiValueArgs ALLOWED_PREFIXES)
    cmake_parse_arguments(IR "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT IR_TARGET)
        message(FATAL_ERROR "install_runtime(): TARGET is required")
    endif()

    if(NOT TARGET ${IR_TARGET})
        message(FATAL_ERROR "install_runtime(): target '${IR_TARGET}' not found")
    endif()

    if(WIN32)
        _install_runtime_win32(${IR_TARGET})
    elseif(APPLE)
        _install_runtime_apple(${IR_TARGET} "${IR_ALLOWED_PREFIXES}")
    else()
        _install_runtime_linux(${IR_TARGET})
    endif()
endfunction()
