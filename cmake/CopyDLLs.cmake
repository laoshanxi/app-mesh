# cmake/CopyDLLs.cmake

# Whitelist: Only copy DLLs found within these project-specific directories (case-insensitive check).
set(ALLOWED_DLL_PREFIXES 
    "C:/local/bin/"
    "C:/vcpkg/installed/x64-windows/bin/"
    # Add other local project paths if necessary
)

function(_ir_get_transitive_deps target out_var)
  set(processed_targets "")
  set(targets_to_visit ${target})
  set(all_deps "")

  while(targets_to_visit)
    list(POP_FRONT targets_to_visit current_target)
    if(NOT TARGET "${current_target}" OR "${current_target}" IN_LIST processed_targets)
      continue()
    endif()
    list(APPEND processed_targets ${current_target})

    get_target_property(libs ${current_target} LINK_LIBRARIES)
    get_target_property(iface_libs ${current_target} INTERFACE_LINK_LIBRARIES)
    
    foreach(lib IN LISTS libs iface_libs)
      if(NOT lib)
        continue()
      endif()
      
      # Clean up generator expressions
      string(REGEX REPLACE "\\$<.*:([^>]+)>" "\\1" clean_lib "${lib}")
      
      if(TARGET "${clean_lib}")
        list(APPEND all_deps "${clean_lib}")
        list(APPEND targets_to_visit "${clean_lib}")
      elseif(EXISTS "${clean_lib}")
          # Get the actual file path (resolving symlinks) 
          get_filename_component(real_path "${clean_lib}" REALPATH)
          get_filename_component(ext "${real_path}" EXT)
          
          # Match .so, .dylib, or versioned .so (e.g., .so.1) [cite: 3]
          if(WIN32 AND ext STREQUAL ".dll")
              list(APPEND all_deps "${real_path}")
          elseif(NOT WIN32 AND (ext STREQUAL ".so" OR real_path MATCHES "\.so\."))
              list(APPEND all_deps "${real_path}")
          endif()
      endif()
    endforeach()
  endwhile()
  
  if(all_deps)
    list(REMOVE_DUPLICATES all_deps)
  endif()
  set(${out_var} ${all_deps} PARENT_SCOPE)
endfunction()

function(copy_runtime_dependencies target_name)
    if(NOT WIN32)
        return()
    endif()

    # Retrieve all libraries linked to the target
    # get_target_property(linked_libs ${target_name} LINK_LIBRARIES)
    _ir_get_transitive_deps(${target_name} linked_libs)
    
    foreach(lib ${linked_libs})
        if(TARGET ${lib})
            get_target_property(target_type ${lib} TYPE)
            
            # 1. Skip non-file-producing targets (Interface Libraries)
            if(target_type STREQUAL "INTERFACE_LIBRARY")
                continue()
            endif()
            
            get_target_property(is_imported ${lib} IMPORTED)
            
            # Process only shared/module libraries or imported targets
            if(is_imported OR target_type STREQUAL "SHARED_LIBRARY" OR target_type STREQUAL "MODULE_LIBRARY")
                
                # Use generator expression for the actual DLL path at build time
                set(DLL_PATH "$<TARGET_FILE:${lib}>")
                
                # --- Path Filtering Logic (Configuration Time) ---
                set(is_allowed_path FALSE)
                
                # Attempt to find the static path for filtering
                get_target_property(imported_location ${lib} IMPORTED_LOCATION_RELWITHDEBINFO)
                if(NOT imported_location)
                    get_target_property(imported_location ${lib} IMPORTED_LOCATION)
                endif()
                
                if(imported_location)
                    # Normalize slashes for robust path comparison
                    string(REPLACE "\\" "/" imported_location_slashes "${imported_location}")
                    string(TOLOWER "${imported_location_slashes}" lower_location)
                    
                    foreach(prefix ${ALLOWED_DLL_PREFIXES})
                        string(TOLOWER "${prefix}" lower_prefix)

                        # Check if the DLL path starts with an allowed prefix
                        if(lower_location MATCHES "^${lower_prefix}")
                            set(is_allowed_path TRUE)
                            break()
                        endif()
                    endforeach()
                else()
                    # Assume locally built SHARED_LIBRARY files are allowed
                    if(target_type STREQUAL "SHARED_LIBRARY" OR target_type STREQUAL "MODULE_LIBRARY")
                        set(is_allowed_path TRUE)
                    endif()
                endif()
                
                # Skip the DLL if it doesn't meet the whitelist criteria
                if(NOT is_allowed_path)
                    message(STATUS "Skipping external DLL ${lib}: Path not in ALLOWED_DLL_PREFIXES or IMPORTED_LOCATION missing.")
                    continue()
                endif()
                
                # Define output directory and add the copy command
                set(OUTPUT_DIR "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/$<CONFIG>")

                add_custom_command(
                    TARGET ${target_name} POST_BUILD
                    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${DLL_PATH}" "${OUTPUT_DIR}/"
                    COMMAND ${CMAKE_COMMAND} -E echo "Copy [${lib}] from [${DLL_PATH}] to [${OUTPUT_DIR}]"
                    VERBATIM
                )
            endif()
        endif()
    endforeach()
endfunction()
