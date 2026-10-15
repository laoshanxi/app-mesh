# src/common/CMakeLists.txt

# --- Subdirectories ---
add_subdirectory(os)

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(common STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::common ALIAS common)

# --- Linking ---
# spdlog must be PUBLIC on every platform: without the usage requirements
# (SPDLOG_COMPILED_LIB/SPDLOG_SHARED_LIB) reaching every translation unit,
# spdlog 1.17 silently falls back to header-only mode and emits inline
# definitions into each object; mixed with the shared library's import
# symbols that is MSVC LNK2005, and it splits the logger registry (see
# rest/CMakeLists.txt).
target_link_libraries(common PUBLIC spdlog::spdlog)
target_link_libraries(common
  PRIVATE
    yaml-cpp::yaml-cpp
    Boost::regex
    Boost::system
    Boost::program_options
    ${OPENSSL_LIBRARIES}
    uriparser::uriparser
    os
)
# std::filesystem needs libstdc++fs on GCC 8/9
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(common PUBLIC stdc++fs)
endif()
# trantor (bundled with drogon) implements the RestClient transport
target_link_libraries(common PRIVATE Drogon::Drogon)
# jsoncpp types appear in public headers (Utility.h, json.h)
target_link_libraries(common PUBLIC jsoncpp_lib)

# macOS libiconv is not re-exported by libSystem; Utility.cpp uses iconv for
# output encoding detection (glibc/musl provide it inside libc).
if(APPLE)
  target_link_libraries(common PRIVATE iconv)
endif()
