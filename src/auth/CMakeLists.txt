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
