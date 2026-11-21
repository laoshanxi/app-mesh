# test/utility/CMakeLists.txt
##########################################################################
# Unit Test
##########################################################################
project(test_utility)

add_executable(${PROJECT_NAME} main.cpp)

add_catch_test(${PROJECT_NAME})

##########################################################################
# Link
##########################################################################
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Threads::Threads
    Boost::regex
    Boost::system
    Boost::filesystem
    common
)

# Locate packaged policy files (authorization.yaml) from the source tree in tests.
target_compile_definitions(${PROJECT_NAME} PRIVATE
  APPMESH_SOURCE_ROOT="${CMAKE_CURRENT_SOURCE_DIR}/../../"
)
