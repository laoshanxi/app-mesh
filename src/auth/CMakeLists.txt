# src/auth/CMakeLists.txt

##########################################################################
# passhash - stdin-only bcrypt helper for appmesh-auth.sh/.ps1,
# built with cargo like the Rust CLI (appm).
##########################################################################

set(PASSHASH_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/passhash")
set(PASSHASH_BIN "${CMAKE_BINARY_DIR}/cargo-target/release/passhash${CMAKE_EXECUTABLE_SUFFIX}")

add_custom_target(passhash ALL
    COMMAND cargo build --release --target-dir "${CMAKE_BINARY_DIR}/cargo-target"
    WORKING_DIRECTORY "${PASSHASH_SRC_DIR}"
    COMMENT "Building passhash helper"
    VERBATIM
)

install(PROGRAMS "${PASSHASH_BIN}"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Runtime
)

##########################################################################
# dexuser - Dex password user helper for the appmesh-auth.sh add-user and
# delete-user actions. It writes the gRPC wire protocol directly, so the only
# dependency is the protowire package and the binary stays about half the size
# of one built on the gRPC client. Windows runs the CGO-free Dex with memory
# storage, so a user created over gRPC would not survive a restart; the helper
# is not built there.
##########################################################################

if(UNIX)
    set(DEXUSER_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/dexuser")
    set(DEXUSER_BIN "${CMAKE_BINARY_DIR}/dexuser${CMAKE_EXECUTABLE_SUFFIX}")

    add_custom_target(dexuser ALL
        COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=0 go build
            -trimpath
            -buildvcs=false
            -ldflags "-s -w"
            -o "${DEXUSER_BIN}"
            .
        WORKING_DIRECTORY "${DEXUSER_SRC_DIR}"
        COMMENT "Building dexuser helper"
        VERBATIM
    )

    install(PROGRAMS "${DEXUSER_BIN}"
        DESTINATION ${CMAKE_INSTALL_BINDIR}
        COMPONENT Runtime
    )
endif()
