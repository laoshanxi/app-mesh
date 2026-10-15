# src/daemon/process/CMakeLists.txt

file(GLOB SRC_LIST *.cpp)

add_library(process STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::process ALIAS process)

# spdlog::spdlog carries SPDLOG_COMPILED_LIB: without it these TUs compile
# their own inline copy of the logger registry, which splits from the shared
# library's registry that the logging setup configures - their LOG_* output
# then never reaches server.log.
target_link_libraries(process
  PRIVATE
    spdlog::spdlog
)
