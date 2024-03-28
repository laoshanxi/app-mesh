##########################################################################
# common
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(common STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::common ALIAS common)

##########################################################################
# Link
##########################################################################
target_link_libraries(common
  PRIVATE
    curlpp ${CURL_LIB} z
    ACE
    ACE_SSL
    log4cpp
    yaml-cpp
    boost_regex
    boost_system
    boost_filesystem
    boost_program_options
    ${OPENSSL_LIBRARIES}
    qrcodegencpp
)
