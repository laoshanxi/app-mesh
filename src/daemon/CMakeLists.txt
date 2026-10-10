# src/daemon/CMakeLists.txt
add_subdirectory(application)
add_subdirectory(process)
add_subdirectory(rest)
add_subdirectory(security)

# --- Define Executable ---
aux_source_directory(. SRC_LIST)
add_executable(appmesh ${SRC_LIST})
add_executable(${PROJECT_NAME}::appmesh ALIAS appmesh)

# --- Linking ---
target_link_libraries(appmesh
  PRIVATE
    Threads::Threads
    rest
    application
    security
    process
    prometheus
    common
)

target_link_libraries(appmesh PUBLIC websockets_shared)

install_runtime(TARGET appmesh)
