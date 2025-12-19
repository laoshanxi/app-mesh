# src/daemon/rest/CMakeLists.txt

# --- Subdirectories ---
add_subdirectory(prometheus)

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(rest STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::rest ALIAS rest)

# --- Linking ---
target_link_libraries(rest
  PRIVATE
    Boost::regex
)
