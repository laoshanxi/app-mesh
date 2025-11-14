##########################################################################
# websockets
##########################################################################

aux_source_directory(. SRC_LIST)
add_library(wsockets ${SRC_LIST})
add_library(${PROJECT_NAME}::wsockets ALIAS wsockets)

##########################################################################
# Link
##########################################################################
target_link_libraries(wsockets
  PRIVATE
  websockets_shared
  uriparser::uriparser
)
