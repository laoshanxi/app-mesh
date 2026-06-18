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
    security
    application
    process
    prometheus
    common
)

if(CMAKE_CXX_STANDARD GREATER_EQUAL 17)
  if(WIN32)
    target_link_libraries(appmesh PUBLIC unofficial::uwebsockets::uwebsockets)
  else()
    find_library(USOCKETS_LIB NAMES uSockets REQUIRED)
    target_link_libraries(appmesh PUBLIC ${USOCKETS_LIB} ZLIB::ZLIB)
  endif()
else()
  target_link_libraries(appmesh PUBLIC websockets_shared)
endif()

install_runtime(TARGET appmesh)
