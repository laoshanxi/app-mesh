# src/daemon/application/CMakeLists.txt

# --- Define application library ---
aux_source_directory(. SRC_LIST)
add_library(application STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::application ALIAS application)

# spdlog::spdlog carries SPDLOG_COMPILED_LIB: without it these TUs compile
# their own inline copy of the logger registry, which splits from the shared
# library's registry that the logging setup configures - their LOG_* output
# then never reaches server.log.
target_link_libraries(application
  PRIVATE
    spdlog::spdlog
)
