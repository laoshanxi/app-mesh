# src/daemon/rest/CMakeLists.txt

# --- Subdirectories ---
add_subdirectory(prometheus)

# --- Define library ---
aux_source_directory(. SRC_LIST)
aux_source_directory(drogon DROGON_SRC_LIST)
list(APPEND SRC_LIST ${DROGON_SRC_LIST})
add_library(rest STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::rest ALIAS rest)

# --- Linking ---
# spdlog: these sources include spdlog headers directly; without the
# spdlog::spdlog usage requirements (SPDLOG_COMPILED_LIB/SHARED_LIB) the inline
# registry in these objects splits from the shared library's, and runtime
# level changes (DEBUG) never reach the LOG_* macros compiled here.
target_link_libraries(rest
  PRIVATE
    Boost::regex
    spdlog::spdlog
)
target_link_libraries(rest PUBLIC Drogon::Drogon)
