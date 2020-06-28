##########################################################################
# appc
##########################################################################
set(SRC_LIST main.cpp ArgumentParser.cpp)
add_executable(appc ${SRC_LIST})

##########################################################################
# Link
##########################################################################
target_link_libraries(appc
  PRIVATE
    Threads::Threads
    ${OPENSSL_LIBRARIES}
    boost_system boost_program_options
    cpprest
    ACE
    log4cpp
    common
)

##########################################################################
# install
# https://blog.csdn.net/qq_38410730/article/details/102837401
##########################################################################
install(TARGETS appc
    RUNTIME DESTINATION ${CMAKE_BINARY_DIR}/bin
)
