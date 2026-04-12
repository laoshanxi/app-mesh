# src/daemon/CMakeLists.txt
add_subdirectory(application)
add_subdirectory(process)
add_subdirectory(rest)
add_subdirectory(security)

# --- Define Executable ---
aux_source_directory(. SRC_LIST)
add_executable(appsvc ${SRC_LIST})
add_executable(${PROJECT_NAME}::appsvc ALIAS appsvc)

# --- Linking ---
target_link_libraries(appsvc
  PRIVATE
    Threads::Threads
    rest
    security
    application
    process
    prometheus
    common
)

target_link_libraries(appsvc PUBLIC websockets_shared)

install_runtime(TARGET appsvc)
