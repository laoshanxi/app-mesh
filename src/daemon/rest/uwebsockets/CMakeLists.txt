##########################################################################
# uwebsockets
##########################################################################

aux_source_directory(. SRC_LIST)
add_library(uwebsockets ${SRC_LIST})
add_library(${PROJECT_NAME}::uwebsockets ALIAS uwebsockets)

##########################################################################
# Link
##########################################################################
target_link_libraries(uwebsockets
  PUBLIC
)
