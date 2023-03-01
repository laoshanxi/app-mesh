##########################################################################
# protoc
##########################################################################
aux_source_directory(. SRC_LIST)

add_library(protoc STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::protoc ALIAS protoc)

target_include_directories(protoc
  PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}
)

##########################################################################
# Link
##########################################################################
target_link_libraries(protoc
  PRIVATE
	msgpack-cxx
)
