# test/security/CMakeLists.txt
##########################################################################
# Unit Test
##########################################################################
project(test_security)

# Compile with the daemon's top-level sources that provide Configuration etc.
# (process→application→Configuration linkage), excluding the daemon main.
aux_source_directory(${CMAKE_SOURCE_DIR}/src/daemon SRC_DAEMON_MAIN)
list(FILTER SRC_DAEMON_MAIN EXCLUDE REGEX "main\\.cpp$")

add_executable(${PROJECT_NAME} main.cpp configuration.cpp request_hardening.cpp authorization_store.cpp
							   ${SRC_DAEMON_MAIN})

add_catch_test(${PROJECT_NAME})

# Configuration pulls in rest/application/process symbols; GNU ld resolves
# static archives in a single left-to-right pass and the daemon libraries
# reference each other, so the cycle is repeated once (portable pre-3.24
# CMake form; ld64 deduplicates the repeat).
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Threads::Threads
    security
    application
    process
    rest
    lwsservice
    security
    application
    process
    rest
    lwsservice
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
