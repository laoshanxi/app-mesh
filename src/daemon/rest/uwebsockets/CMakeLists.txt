##########################################################################
# uwebsockets (Header-only library)
##########################################################################

add_library(uwebsockets INTERFACE)
add_library(${PROJECT_NAME}::uwebsockets ALIAS uwebsockets)

target_sources(uwebsockets
  INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/Adaptor.hpp
)

target_include_directories(uwebsockets
  INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(uwebsockets
  INTERFACE
    uSockets
)
