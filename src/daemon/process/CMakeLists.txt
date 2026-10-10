# src/daemon/process/CMakeLists.txt

file(GLOB SRC_LIST *.cpp)

add_library(process STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::process ALIAS process)
