##########################################################################
# Unit Test
##########################################################################
project(test_datetime)

add_executable(${PROJECT_NAME} main.cpp)

add_catch_test(${PROJECT_NAME})

##########################################################################
# Link
##########################################################################
target_link_libraries(${PROJECT_NAME}
  PRIVATE
    Threads::Threads
    boost_regex
    boost_thread
    boost_system
    boost_date_time
    cpprest
    ACE
    rest
    ${OPENSSL_LIBRARIES}
    security
    application
    process
    prometheus
    common
)
