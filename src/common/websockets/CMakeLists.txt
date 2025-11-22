##########################################################################
# libwebsockets
##########################################################################

aux_source_directory(. SRC_LIST)
add_library(libwebsockets ${SRC_LIST})
add_library(${PROJECT_NAME}::libwebsockets ALIAS libwebsockets)

##########################################################################
# Link
##########################################################################
target_link_libraries(libwebsockets
  PUBLIC
    websockets_shared
    uriparser::uriparser
)
