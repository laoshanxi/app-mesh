##########################################################################
# application
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(application STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::application ALIAS application)
