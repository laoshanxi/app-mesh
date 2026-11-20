# test/security/CMakeLists.txt
##########################################################################
# Unit Test
##########################################################################
project(test_security)

add_executable(${PROJECT_NAME} main.cpp authorization_store.cpp configuration.cpp request_hardening.cpp)
# RequestHardening reads Configuration, which only the daemon executable
# compiles; pull the single source in directly instead of a library split.
# Label.cpp comes with it (Configuration owns the label store).
target_sources(${PROJECT_NAME} PRIVATE ../../src/daemon/Configuration.cpp ../../src/daemon/Label.cpp
                                       ../../src/daemon/ResourceCollection.cpp)

add_catch_test(${PROJECT_NAME})

##########################################################################
# Link
##########################################################################
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Threads::Threads
    security
    common
    yaml-cpp::yaml-cpp
    ${OPENSSL_LIBRARIES}
)
