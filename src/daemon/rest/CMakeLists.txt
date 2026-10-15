# src/daemon/rest/CMakeLists.txt

# --- Subdirectories ---
add_subdirectory(prometheus)

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(rest STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::rest ALIAS rest)

# --- Linking ---
# spdlog::spdlog carries SPDLOG_COMPILED_LIB: without it these TUs compile
# their own inline copy of the logger registry, which splits from the shared
# library's registry that the logging setup configures - their LOG_* output
# then never reaches server.log.
target_link_libraries(rest
  PRIVATE
    Boost::regex
    spdlog::spdlog
)
