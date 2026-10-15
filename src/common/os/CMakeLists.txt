# src/common/os/CMakeLists.txt

set(OS_SOURCES
    process.cpp
    process_linux.cpp
    sysinfo.cpp
    sysinfo_linux.cpp
    filesystem.cpp
    filesystem_posix.cpp
    filesystem_linux.cpp
    user.cpp
    user_posix.cpp
    chown.cpp
    proc.cpp
    pstree.cpp
    net.cpp
)

add_library(os STATIC ${OS_SOURCES})
add_library(${PROJECT_NAME}::os ALIAS os)

# spdlog::spdlog carries SPDLOG_COMPILED_LIB: without it these TUs compile
# their own inline copy of the logger registry, which splits from the shared
# library's registry that the logging setup configures.
target_link_libraries(os
  PRIVATE
    spdlog::spdlog
)
