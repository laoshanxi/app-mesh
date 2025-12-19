# src/common/lwsservice/CMakeLists.txt

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(lwsservice ${SRC_LIST})
add_library(${PROJECT_NAME}::lwsservice ALIAS lwsservice)

# --- Linking ---
target_link_libraries(lwsservice
  PUBLIC
    websockets_shared
    uriparser::uriparser
)
