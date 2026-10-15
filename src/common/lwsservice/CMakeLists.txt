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
    ${OPENSSL_LIBRARIES}
)

# spdlog::spdlog carries SPDLOG_COMPILED_LIB: without it these TUs compile
# their own inline copy of the logger registry, which splits from the shared
# library's registry that the logging setup configures.
target_link_libraries(lwsservice
  PRIVATE
    spdlog::spdlog
)
