##########################################################################
# ws-client-example.cpp
##########################################################################
add_executable(ws-client-example ws-client-example.cpp)
add_executable(${PROJECT_NAME}::ws-client-example ALIAS ws-client-example)
target_link_libraries(ws-client-example
  PRIVATE
    Threads::Threads
    common
)

##########################################################################
# ws-service-example.cpp
##########################################################################
add_executable(ws-service-example ws-service-example.cpp)
add_executable(${PROJECT_NAME}::ws-service-example ALIAS ws-service-example)
target_link_libraries(ws-service-example
  PRIVATE
    Threads::Threads
    websockets_shared
    ${OPENSSL_LIBRARIES}
)
