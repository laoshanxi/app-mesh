# src/common/CMakeLists.txt

# --- Subdirectories ---
add_subdirectory(os)

if(NOT CMAKE_CXX_STANDARD OR CMAKE_CXX_STANDARD LESS 17)
  message(STATUS "C++ standard less than 17: Adding lwsservice")
  add_subdirectory(lwsservice)
endif()

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
    ${CURL_LIB}
    ZLIB::ZLIB # nghttp2
    ${ACE_LIBRARY}
    ${ACE_SSL_LIBRARY}
    yaml-cpp::yaml-cpp
    Boost::regex
    Boost::system
    Boost::filesystem
    Boost::program_options
    ${OPENSSL_LIBRARIES}
    qrcodegencpp
    uriparser::uriparser
    os
)
if(NOT CMAKE_CXX_STANDARD GREATER_EQUAL 17)
  target_link_libraries(common PRIVATE lwsservice)
endif()
