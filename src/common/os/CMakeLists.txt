# src/common/os/CMakeLists.txt

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(os STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::os ALIAS os)
