# src/common/CMakeLists.txt

# --- Subdirectories ---
add_subdirectory(os)

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(common STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::common ALIAS common)

# --- Linking ---
if(WIN32)
  # TODO: Windows have link issue, so temprary use header only
  target_link_libraries(common PRIVATE spdlog::spdlog_header_only)
else()
  target_link_libraries(common PUBLIC spdlog::spdlog)
endif()
target_link_libraries(common
  PRIVATE
    ${ACE_LIBRARY}
    yaml-cpp::yaml-cpp
    Boost::regex
    Boost::system
    Boost::filesystem
    Boost::program_options
    ${OPENSSL_LIBRARIES}
    uriparser::uriparser
    os
)
# trantor (bundled with drogon) implements the RestClient transport
target_link_libraries(common PRIVATE Drogon::Drogon)

# macOS libiconv is not re-exported by libSystem; Utility.cpp uses iconv for
# output encoding detection (glibc/musl provide it inside libc).
if(APPLE)
  target_link_libraries(common PRIVATE iconv)
endif()
