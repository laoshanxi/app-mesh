# cmake/InstallRuntime.cmake

# TODO: copy library version may not match link file name

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

function(install_runtime target)

    # --- Install the main target executable itself ---
    if(TARGET ${target})
        install(TARGETS ${target}
                RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
                LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
                ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
                COMPONENT Runtime)
    endif()

    # On Windows, simply copy "app-mesh\build\src\daemon\RelWithDebInfo\*.dll"
    if(WIN32)
        install(DIRECTORY "$<TARGET_FILE_DIR:${target}>/"
                DESTINATION ${CMAKE_INSTALL_BINDIR}
                FILES_MATCHING 
                PATTERN "*.dll")
    endif()

    # 1. Get and install all transitive dependencies
    _ir_get_transitive_deps(${target} all_deps)

    foreach(lib IN LISTS all_deps)
        if(TARGET "${lib}")
            get_target_property(type "${lib}" TYPE)
            if(type STREQUAL "SHARED_LIBRARY")
                if(WIN32)
                    install(FILES "$<TARGET_FILE:${lib}>" DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
                else()
                    install(FILES "$<TARGET_FILE:${lib}>" DESTINATION ${CMAKE_INSTALL_LIBDIR} COMPONENT Runtime)
                endif()
            endif()
        else()
            # ${lib} is now the REALPATH from the helper function
            if(WIN32)
                install(FILES "${lib}" DESTINATION ${CMAKE_INSTALL_BINDIR} COMPONENT Runtime)
            else()
                # Get the filename of the original dependency (e.g., libyaml-cpp.so.0.8)
                # and the actual file (libyaml-cpp.so.0.8.0)
                get_filename_component(lib_name "${lib}" NAME)
                
                install(FILES "${lib}" 
                        DESTINATION ${CMAKE_INSTALL_LIBDIR} 
                        COMPONENT Runtime)
                
                # Simple Fix: If the app looks for libyaml-cpp.so.0.8, 
                # ensure that specific filename exists in the destination.
                # You can use RENAME if you want to force the specific version name:
                # install(FILES "${lib}" DESTINATION ${libdir} RENAME "libyaml-cpp.so.0.8")
            endif()
        endif()
    endforeach()

endfunction()
