# cmake/InstallRuntime.cmake

# Linux Implementation
function(_install_runtime_linux target allowed_prefixes)
    # Default whitelist if not provided
    if(NOT allowed_prefixes)
        set(allowed_prefixes
            "/usr/local/"
            "${CMAKE_BINARY_DIR}/"
        )
    endif()

    # Convert list to pipe-separated string for passing into install(CODE)
    string(REPLACE ";" "|" _prefixes_escaped "${allowed_prefixes}")

    # Set RPATH for the target - $ORIGIN allows relocation
    set_target_properties(${target} PROPERTIES
        INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}"
        BUILD_WITH_INSTALL_RPATH FALSE
        INSTALL_RPATH_USE_LINK_PATH FALSE
    )

    # Install executable
    install(TARGETS ${target}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime
    )

    # Use install(CODE) with whitelist filtering
    install(CODE "
        if(POLICY CMP0057)
            cmake_policy(SET CMP0057 NEW) # Set policy to support IN_LIST
        endif()

        set(_allowed_prefixes \"${_prefixes_escaped}\")
        string(REPLACE \"|\" \";\" _allowed_prefixes \"\${_allowed_prefixes}\")

        file(GET_RUNTIME_DEPENDENCIES
            EXECUTABLES \"$<TARGET_FILE:${target}>\"
            RESOLVED_DEPENDENCIES_VAR _r_deps
            UNRESOLVED_DEPENDENCIES_VAR _u_deps

            # Exclude loader / system pseudo-libs
            PRE_EXCLUDE_REGEXES
                \"ld-linux.*\"
                \"linux-vdso.*\"

            POST_EXCLUDE_REGEXES
                \"^/lib/.*\"
                \"^/lib64/.*\"
                \"^/usr/lib/.*\"
                \"^/usr/lib64/.*\"
        )

        # Track processed libraries for deduplication
        set(_processed_libs \"\")

        # Filter and copy only libraries matching the whitelist
        foreach(_file IN LISTS _r_deps)
            set(_should_copy FALSE)

            foreach(_prefix IN LISTS _allowed_prefixes)
                string(TOLOWER \"\${_file}\" _file_lower)
                string(TOLOWER \"\${_prefix}\" _prefix_lower)
                string(FIND \"\${_file_lower}\" \"\${_prefix_lower}\" _pos)
                if(_pos EQUAL 0)
                    set(_should_copy TRUE)
                    break()
                endif()
            endforeach()

            if(_should_copy)
                # Get the library name
                get_filename_component(_dep_name \"\${_file}\" NAME)

                # Skip if already processed
                if(\"\${_dep_name}\" IN_LIST _processed_libs)
                    continue()
                endif()
                list(APPEND _processed_libs \"\${_dep_name}\")

                # Resolve the symlink to the actual physical file path
                get_filename_component(_real_file \"\${_file}\" REALPATH)

                message(STATUS \"[install_runtime] Copying: \${_dep_name}\")

                # Copy with the link name (not the versioned name)
                file(INSTALL
                    DESTINATION \"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}\"
                    TYPE FILE
                    RENAME \"\${_dep_name}\"
                    FILES \"\${_real_file}\"
                    FOLLOW_SYMLINK_CHAIN
                )
            endif()
        endforeach()

        if(_u_deps)
            message(STATUS \"[install_runtime] Unresolved dependencies (expected): \${_u_deps}\")
        endif()
    ")
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

    _install_runtime_linux(${IR_TARGET} "${IR_ALLOWED_PREFIXES}")
endfunction()
