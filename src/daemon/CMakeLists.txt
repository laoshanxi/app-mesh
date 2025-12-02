##########################################################################
# sub dir
##########################################################################
add_subdirectory(application)
add_subdirectory(process)
add_subdirectory(rest)
add_subdirectory(security)

##########################################################################
# appsvc
##########################################################################
aux_source_directory(. SRC_LIST)
add_executable(appsvc ${SRC_LIST})
add_executable(${PROJECT_NAME}::appsvc ALIAS appsvc)

##########################################################################
# Link
##########################################################################
target_link_libraries(appsvc
  PRIVATE
    Threads::Threads
    rest
    security
    application
    process
    prometheus
    common
  PUBLIC
    websockets_shared
    uriparser::uriparser
)

if(CMAKE_CXX_STANDARD GREATER_EQUAL 17)
  if(WIN32)
    target_link_libraries(appsvc PUBLIC unofficial::uwebsockets::uwebsockets)
  else()
    target_link_libraries(appsvc PUBLIC uSockets)
  endif()
endif()

copy_runtime_dependencies(appsvc)
