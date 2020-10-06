##########################################################################
# Unit Test
##########################################################################
add_executable(unittest unit_test.cpp)
add_executable(${PROJECT_NAME}::unittest ALIAS unittest)

##########################################################################
# Link
##########################################################################
target_link_libraries(unittest
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
