# src/auth/CMakeLists.txt

##########################################################################
# password-hash - stdin-only bcrypt helper for appmesh-auth.sh,
# built like the Go agent from the repository's root Go module.
##########################################################################

set(PASSWORD_HASH_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/password-hash")

set(PASSWORD_HASH_BIN "${CMAKE_CURRENT_BINARY_DIR}/password-hash${CMAKE_EXECUTABLE_SUFFIX}")

add_custom_target(password-hash ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}"
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=0 go build
        -trimpath
        -ldflags "-s -w"
        -buildvcs=false
        -o "${PASSWORD_HASH_BIN}"
        .
    WORKING_DIRECTORY "${PASSWORD_HASH_SRC_DIR}"
    COMMENT "Building password-hash helper"
    VERBATIM
)

install(PROGRAMS "${PASSWORD_HASH_BIN}"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Runtime
)
