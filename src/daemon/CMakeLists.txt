##########################################################################
# sub dir
##########################################################################
add_subdirectory(application)
add_subdirectory(process)
add_subdirectory(rest)
add_subdirectory(security)

##########################################################################
# appsvc
##########################################################################
aux_source_directory(. SRC_LIST)
add_executable(appsvc ${SRC_LIST})
add_executable(${PROJECT_NAME}::appsvc ALIAS appsvc)

##########################################################################
# Link
##########################################################################
target_link_libraries(appsvc
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

##########################################################################
# install
##########################################################################
install(TARGETS appsvc
    RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/bin
)
