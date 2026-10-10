# src/common/CMakeLists.txt

# --- Subdirectories ---
add_subdirectory(os)
add_subdirectory(lwsservice)

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(common STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::common ALIAS common)

# --- Linking ---
target_link_libraries(common PUBLIC spdlog::spdlog)
target_link_libraries(common
  PRIVATE
    ${CURL_LIB}
    ${ZLIB_LIBRARIES} # static libcurl content_encoding needs zlib
    ZLIB::ZLIB # nghttp2
    ${ACE_LIBRARY}
    ${ACE_SSL_LIBRARY}
    yaml-cpp::yaml-cpp
    Boost::regex
    Boost::system
    Boost::filesystem
    Boost::program_options
    ${OPENSSL_LIBRARIES}
    uriparser::uriparser
    os
    lwsservice
)

