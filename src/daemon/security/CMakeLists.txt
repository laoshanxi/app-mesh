##########################################################################
# security
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(security STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::security ALIAS security)
