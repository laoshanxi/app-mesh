# cmake/WindowsConfig.cmake
# Platform-specific configuration for Windows (MSVC) builds of App-Mesh
# Intended to be included from the top-level CMakeLists.txt BEFORE project()

if(DEFINED WINDOWS_CONFIG_INCLUDED)
    return()
endif()
set(WINDOWS_CONFIG_INCLUDED TRUE)

if(NOT WIN32)
    message(FATAL_ERROR "windows-config.cmake is intended for Windows builds only.")
endif()

# --- UTF-8 encoding ---
add_compile_options("/utf-8")

# Explicitly include vcpkg toolchain
if(NOT CMAKE_TOOLCHAIN_FILE)
    if(EXISTS "C:/vcpkg/scripts/buildsystems/vcpkg.cmake")
        set(CMAKE_TOOLCHAIN_FILE "C:/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE FILEPATH "Vcpkg toolchain file" FORCE)
        include(${CMAKE_TOOLCHAIN_FILE})
        message(STATUS "CMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}")
    endif()
endif()

# --- Local dependencies (C:/local) ---
set(APP_MESH_LOCAL_ROOT "C:/local" CACHE PATH "Root path for local dependencies")

if(EXISTS "${APP_MESH_LOCAL_ROOT}")
    list(PREPEND CMAKE_PREFIX_PATH "${APP_MESH_LOCAL_ROOT}")
    include_directories("${APP_MESH_LOCAL_ROOT}/include")
    link_directories("${APP_MESH_LOCAL_ROOT}/lib")
else()
    message(WARNING "Local dependency root not found: ${APP_MESH_LOCAL_ROOT}")
endif()

# --- Preprocessor definitions ---
add_compile_definitions(
    WIN32
    _WIN32
    _WINDOWS
    NOMINMAX
    NOSEND
    WIN32_LEAN_AND_MEAN
)

# --- Compiler flags ---
# Note: _INIT only applies on first CMake configure
set(CMAKE_CXX_FLAGS_RELEASE_INIT "/O2 /Ob2 /DNDEBUG /MD")
set(CMAKE_C_FLAGS_RELEASE_INIT  "/O2 /Ob2 /DNDEBUG /MD")

# --- Warning suppression ---
# COMPLETE WARNING SUPPRESSION
add_compile_options(
    /w /EHsc
    /wd4242 /wd4244 /wd4267 /wd4371 /wd4820 /wd4866 /wd4868 /wd4701 /wd4702 /wd4710 /wd4711 /wd4996 /wd5045 /wd5204
    /external:anglebrackets /external:W0
)
add_compile_definitions(_WINSOCK_DEPRECATED_NO_WARNINGS)

# --- Diagnostics ---
message(STATUS "App-Mesh Windows config:")
message(STATUS "  toolchain:         ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "  local root:        ${APP_MESH_LOCAL_ROOT}")
message(STATUS "  CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")
