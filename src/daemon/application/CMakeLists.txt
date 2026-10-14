# src/daemon/application/CMakeLists.txt

# --- Define application library ---
aux_source_directory(. SRC_LIST)
add_library(application STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::application ALIAS application)

# spdlog: keep the inline registry out of these objects (see rest/CMakeLists.txt).
target_link_libraries(application PRIVATE spdlog::spdlog)
