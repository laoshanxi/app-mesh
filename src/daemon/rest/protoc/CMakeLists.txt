##########################################################################
# protoc buffer
# https://www.fatalerrors.org/a/the-correct-use-of-protobuf-in-cmake.html
# https://www.yht7.com/news/136962
# protoc http_request.proto --cpp_out=./
##########################################################################
# Generate output dir
set(PROTO_META_BASE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
# Find .proto file include dir
list(APPEND PROTO_FLAGS -I${CMAKE_CURRENT_SOURCE_DIR})

file(GLOB PROTOBUF_FILELIST *.proto)
foreach(FIL ${PROTOBUF_FILELIST})
  message(STATUS "Generating: protoc ${PROTO_FLAGS} --cpp_out=${PROTO_META_BASE_DIR} ${FIL}")
  message(STATUS "Generating: protoc ${PROTO_FLAGS} --go_out=${CMAKE_SOURCE_DIR}/src/sdk/agent --go_opt=paths=source_relative ${FIL}")
  execute_process(
    COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} ${PROTO_FLAGS} --cpp_out=${PROTO_META_BASE_DIR} ${FIL}
    COMMAND ${PROTOBUF_PROTOC_EXECUTABLE} ${PROTO_FLAGS} --go_out=${CMAKE_SOURCE_DIR}/src/sdk/agent --go_opt=paths=source_relative ${FIL}
  )
endforeach()

aux_source_directory(. SRC_LIST)

add_library(protoc STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::protoc ALIAS protoc)

target_include_directories(protoc
  PUBLIC
    ${Protobuf_INCLUDE_DIRS}
    ${CMAKE_CURRENT_BINARY_DIR}
)

##########################################################################
# Link
##########################################################################
target_link_libraries(protoc
  PRIVATE
    protobuf
)
