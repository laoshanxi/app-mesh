# test/process/CMakeLists.txt
##########################################################################
# Unit Test
##########################################################################
project(test_process)

add_executable(${PROJECT_NAME} main.cpp)

add_catch_test(${PROJECT_NAME})

##########################################################################
# Link
##########################################################################
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Threads::Threads
    process
    rest
    common
)
