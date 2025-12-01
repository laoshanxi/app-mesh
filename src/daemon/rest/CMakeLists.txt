##########################################################################
# rest
##########################################################################
add_subdirectory(protoc)
add_subdirectory(prometheus)
if(CMAKE_CXX_STANDARD GREATER_EQUAL 17)
  add_subdirectory(uwebsockets)
endif()

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
if(CMAKE_CXX_STANDARD GREATER_EQUAL 17)
    target_link_libraries(rest PRIVATE uwebsockets)
endif()
