# cmake/CopyDLLs.cmake

# Whitelist: Only copy DLLs found within these project-specific directories (case-insensitive check).
set(ALLOWED_DLL_PREFIXES 
    "C:/local/bin/" 
    "C:/vcpkg/installed/x64-windows/bin/"
    # Add other local project paths if necessary
)

function(copy_runtime_dependencies target_name)
    if(WIN32)
        get_target_property(linked_libs ${target_name} LINK_LIBRARIES)
        
        foreach(lib ${linked_libs})
            if(TARGET ${lib})
                get_target_property(target_type ${lib} TYPE)
                
                # 1. Skip non-file-producing targets
                if(target_type STREQUAL "INTERFACE_LIBRARY")
                    continue()
                endif()
                
                get_target_property(is_imported ${lib} IMPORTED)
                
                # We only process targets that are shared/module libraries or imported
                if(is_imported OR target_type STREQUAL "SHARED_LIBRARY" OR target_type STREQUAL "MODULE_LIBRARY")
                    
                    # --- CRITICAL FIX: Use $<TARGET_FILE:lib> for DLL Path ---
                    # This generator expression should resolve to the DLL path for imported targets.
                    set(DLL_PATH "$<TARGET_FILE:${lib}>")
                    
                    # --------------------------------------------------------
                    # --- Path Filtering Logic (Runs at Configuration Time) ---
                    # --------------------------------------------------------
                    
                    set(is_allowed_path FALSE)
                    
                    # We need the static path for filtering, not the generator expression
                    get_target_property(imported_location ${lib} IMPORTED_LOCATION_RELWITHDEBINFO)
                    if(NOT imported_location)
                        get_target_property(imported_location ${lib} IMPORTED_LOCATION)
                    endif()
                    
                    if(imported_location)
                        # Normalize and lower case for robust comparison
                        string(REPLACE "\\" "/" imported_location_slashes "${imported_location}")
                        
                        foreach(prefix ${ALLOWED_DLL_PREFIXES})
                            string(TOLOWER "${imported_location_slashes}" lower_location)
                            string(TOLOWER "${prefix}" lower_prefix)

                            if(lower_location MATCHES "^${lower_prefix}")
                                set(is_allowed_path TRUE)
                                break()
                            endif()
                        endforeach()
                    else()
                        # If IMPORTED_LOCATION is not set, it might be a locally built SHARED_LIBRARY.
                        # Assume local project files are allowed if they are SHARED_LIBRARY.
                        if(target_type STREQUAL "SHARED_LIBRARY" OR target_type STREQUAL "MODULE_LIBRARY")
                            set(is_allowed_path TRUE)
                        endif()
                    endif()
                    
                    if(NOT is_allowed_path)
                        message(STATUS "Skipping external DLL ${lib}: Path not in ALLOWED_DLL_PREFIXES or IMPORTED_LOCATION missing.")
                        continue()
                    endif()
                    # --------------------------------------------------------
                    
                    # Get target output directory
                    # get_target_property(OUTPUT_DIR ${target_name} RUNTIME_OUTPUT_DIRECTORY)
                    # if(NOT OUTPUT_DIR)
                    #     set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/gen/$<CONFIG>")
                    # endif()
                    set(OUTPUT_DIR "${CMAKE_BINARY_DIR}/gen/$<CONFIG>")

                    # Add POST_BUILD command to copy the DLL
                    add_custom_command(
                        TARGET ${target_name} POST_BUILD
                        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                        "${DLL_PATH}"
                        "${OUTPUT_DIR}/"
                        COMMENT "Copying runtime dependency ${lib} DLL to $<CONFIG> directory"
                    )
                endif()
            endif()
        endforeach()
    endif()
endfunction()