# src/apps/identity/CMakeLists.txt
# =============================================================================
# identity — bundled OpenID Connect authentication service (System App), the
# shared auth-stack launcher (appmesh-auth.sh/.ps1, also run by src/apps/dexuser
# with the admin-ui command), and its passhash helper.
# =============================================================================

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

# The App definition and the Dex config template ship only with the bundled
# auth stack.
if(APPMESH_INSTALL_AUTH_CONFIG)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/identity.yaml"
        DESTINATION "apps"
        COMPONENT configs
    )
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/dex.yaml"
        DESTINATION "config"
        COMPONENT configs
    )
endif()

# Auth-stack launcher: install the platform-native variant.
if(WIN32)
    install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/appmesh-auth.ps1"
        DESTINATION "script"
        COMPONENT scripts
    )
else()
    install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/appmesh-auth.sh"
        DESTINATION "script"
        COMPONENT scripts
    )
endif()

# UI assets served by the daemon and agent.
install(FILES
    "${CMAKE_CURRENT_SOURCE_DIR}/logo.svg"
    "${CMAKE_CURRENT_SOURCE_DIR}/logo-glyph.svg"
    "${CMAKE_CURRENT_SOURCE_DIR}/favicon.png"
    DESTINATION "script"
    COMPONENT scripts
)
