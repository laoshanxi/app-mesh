# test/process/CMakeLists.txt
project(test_process)

# Compile the test with the daemon's source files that provide Configuration etc.
# These are needed because process→application→Configuration linkage.
aux_source_directory(${CMAKE_SOURCE_DIR}/src/daemon SRC_DAEMON_MAIN)
# Remove main.cpp from daemon sources (we have our own main)
list(FILTER SRC_DAEMON_MAIN EXCLUDE REGEX "main\\.cpp$")

add_executable(${PROJECT_NAME} main.cpp ${SRC_DAEMON_MAIN})

add_catch_test(${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Threads::Threads
    rest
    security
    application
    process
    prometheus
    common
)

# Same platform-specific libs as daemon
if(CMAKE_CXX_STANDARD GREATER_EQUAL 17)
  if(WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC unofficial::uwebsockets::uwebsockets)
  else()
    find_library(USOCKETS_LIB NAMES uSockets REQUIRED)
    target_link_libraries(${PROJECT_NAME} PUBLIC ${USOCKETS_LIB} ZLIB::ZLIB)
  endif()
else()
  target_link_libraries(${PROJECT_NAME} PUBLIC websockets_shared)
endif()
