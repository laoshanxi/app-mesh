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
copy_runtime_dependencies(appsvc)
