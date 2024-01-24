##########################################################################
# appc
##########################################################################
add_subdirectory(client)

aux_source_directory(. SRC_LIST)
add_executable(appc ${SRC_LIST})
add_executable(${PROJECT_NAME}::appc ALIAS appc)

##########################################################################
# Link
##########################################################################
target_link_libraries(appc
  PRIVATE
    client
    Threads::Threads
    ${OPENSSL_LIBRARIES}
    boost_program_options
    common
)

##########################################################################
# install
# https://blog.csdn.net/qq_38410730/article/details/102837401
##########################################################################
install(TARGETS appc
    RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/bin
)
