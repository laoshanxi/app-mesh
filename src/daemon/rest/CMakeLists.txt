##########################################################################
# rest
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(rest STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::rest ALIAS rest)
target_link_libraries(rest ${OPENSSL_LIBRARIES})
