# test/process/CMakeLists.txt
##########################################################################
# Unit Test
##########################################################################
project(test_process)

add_executable(${PROJECT_NAME} main.cpp sandbox.cpp)

# DockerApiProcess reads Configuration and the owning Application's proof/one-shot
# state; Configuration is compiled only into the daemon executable, so pull the
# single source in directly (same pattern as test_security), and link the
# application/security libraries those reachable functions come from.
target_sources(${PROJECT_NAME} PRIVATE ../../src/daemon/Configuration.cpp ../../src/daemon/Label.cpp
                                       ../../src/daemon/ResourceCollection.cpp ../../src/daemon/DailyLimitation.cpp
                                       ../../src/daemon/ResourceLimitation.cpp)

add_catch_test(${PROJECT_NAME})

##########################################################################
# Link
##########################################################################
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Threads::Threads
    rest
    application
    security
    process
    prometheus
    common
    yaml-cpp::yaml-cpp
    ${OPENSSL_LIBRARIES}
)
