##########################################################################
# sub dir
##########################################################################
add_subdirectory(os)
add_subdirectory(websockets)

##########################################################################
# common
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(common STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::common ALIAS common)

##########################################################################
# Link
##########################################################################
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
    libwebsockets
    yaml-cpp::yaml-cpp
    Boost::regex
    Boost::system
    Boost::filesystem
    Boost::program_options
    ${OPENSSL_LIBRARIES}
    qrcodegencpp
    os
)
