# src/common/os/CMakeLists.txt

# Platform-agnostic sources (compiled on all platforms)
set(OS_COMMON_SOURCES
    process.cpp
    sysinfo.cpp
    filesystem.cpp
    user.cpp
    proc.cpp
    pstree.cpp
    net.cpp
)

# Platform-specific sources
if(WIN32)
    set(OS_PLATFORM_SOURCES
        process_windows.cpp
        sysinfo_windows.cpp
        filesystem_windows.cpp
        user_windows.cpp
    )
elseif(APPLE)
    set(OS_PLATFORM_SOURCES
        process_macos.cpp
        sysinfo_macos.cpp
        filesystem_posix.cpp
        filesystem_macos.cpp
        user_posix.cpp
    )
else()
    # Linux and other POSIX systems
    set(OS_PLATFORM_SOURCES
        process_linux.cpp
        sysinfo_linux.cpp
        filesystem_posix.cpp
        filesystem_linux.cpp
        user_posix.cpp
    )
endif()

# chown is Unix-only (has internal #if !defined(_WIN32) guard)
if(NOT WIN32)
    list(APPEND OS_COMMON_SOURCES chown.cpp)
endif()

add_library(os STATIC ${OS_COMMON_SOURCES} ${OS_PLATFORM_SOURCES})
add_library(${PROJECT_NAME}::os ALIAS os)
