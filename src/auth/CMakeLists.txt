# src/auth/CMakeLists.txt

##########################################################################
# passhash - stdin-only bcrypt helper for appmesh-auth.sh/.ps1,
# built like the Go agent from the repository's root Go module.
##########################################################################

set(PASSHASH_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/passhash")

set(PASSHASH_BIN "${CMAKE_CURRENT_BINARY_DIR}/passhash${CMAKE_EXECUTABLE_SUFFIX}")

add_custom_target(passhash ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_CURRENT_BINARY_DIR}"
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=0 go build
        -trimpath
        -ldflags "-s -w"
        -buildvcs=false
        -o "${PASSHASH_BIN}"
        .
    WORKING_DIRECTORY "${PASSHASH_SRC_DIR}"
    COMMENT "Building passhash helper"
    VERBATIM
)

install(PROGRAMS "${PASSHASH_BIN}"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Runtime
)
