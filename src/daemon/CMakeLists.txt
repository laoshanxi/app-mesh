# src/daemon/CMakeLists.txt
add_subdirectory(application)
add_subdirectory(process)
add_subdirectory(rest)
add_subdirectory(security)

# --- Define Executable ---
file(GLOB SRC_LIST CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
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

target_link_libraries(appmesh PUBLIC Drogon::Drogon)

install_runtime(TARGET appmesh)
