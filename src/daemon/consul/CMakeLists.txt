##########################################################################
# consul
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(consul STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::consul ALIAS consul)
