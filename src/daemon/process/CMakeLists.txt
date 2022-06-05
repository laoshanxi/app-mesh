##########################################################################
# process
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(process STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::process ALIAS process)

##########################################################################
# Link
##########################################################################
target_link_libraries(process
  PRIVATE
    ${OPENSSL_LIBRARIES}
)
