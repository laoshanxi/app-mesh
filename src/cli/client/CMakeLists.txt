##########################################################################
# client
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(client STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::client ALIAS client)
