##########################################################################
# rest
##########################################################################
add_subdirectory(protoc)
add_subdirectory(prometheus)

aux_source_directory(. SRC_LIST)
add_library(rest STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::rest ALIAS rest)

##########################################################################
# Link
##########################################################################
target_link_libraries(rest
  PRIVATE
    Boost::regex
    protoc
)
