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

# --- vcpkg paths (manual integration) ---
set(VCPKG_ROOT "C:/vcpkg" CACHE PATH "Path to vcpkg root")
set(VCPKG_TRIPLET "x64-windows" CACHE STRING "vcpkg triplet to use")

set(_vcpkg_inc "${VCPKG_ROOT}/installed/${VCPKG_TRIPLET}/include")
set(_vcpkg_lib "${VCPKG_ROOT}/installed/${VCPKG_TRIPLET}/lib")

if(NOT EXISTS "${_vcpkg_inc}")
    message(FATAL_ERROR "vcpkg include directory not found: ${_vcpkg_inc}")
endif()
if(NOT EXISTS "${_vcpkg_lib}")
    message(WARNING "vcpkg lib directory not found: ${_vcpkg_lib}")
endif()

# Global include/lib for legacy compatibility
include_directories("${_vcpkg_inc}")
link_directories("${_vcpkg_lib}")

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
# ⚠️ /W0 is dangerous; consider /W3 + fix warnings in production
add_compile_options(
    /W0
    /external:anglebrackets
    /external:W0
    /wd4244  # signed/unsigned mismatch
    /wd4267  # size_t to smaller int
    /wd4996  # deprecated functions (e.g., strcpy)
)

# --- Diagnostics ---
message(STATUS "App-Mesh Windows config:")
message(STATUS "  vcpkg:      ${VCPKG_ROOT} (${VCPKG_TRIPLET})")
message(STATUS "  local root: ${APP_MESH_LOCAL_ROOT}")
message(STATUS "  CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}")