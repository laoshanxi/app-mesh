# test/application/CMakeLists.txt
project(test_application)

# Compile with the daemon's top-level sources that provide Configuration etc.
# (process→application→Configuration linkage), excluding the daemon main.
aux_source_directory(${CMAKE_SOURCE_DIR}/src/daemon SRC_DAEMON_MAIN)
list(FILTER SRC_DAEMON_MAIN EXCLUDE REGEX "main\\.cpp$")

add_executable(${PROJECT_NAME} main.cpp ${SRC_DAEMON_MAIN})

add_catch_test(${PROJECT_NAME})

# The daemon links only because main.cpp references RestHandler before the
# archives are scanned; this test entry point does not. GNU ld resolves static
# archives in a single left-to-right pass and rest <-> application reference
# each other, so the cycle is repeated once (portable pre-3.24 CMake form;
# ld64 deduplicates the repeat).
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Threads::Threads
    application
    process
    rest
    security
    application
    process
    rest
    security
    prometheus
    common
)

# Same transport libs as the daemon
target_link_libraries(${PROJECT_NAME} PUBLIC Drogon::Drogon)
