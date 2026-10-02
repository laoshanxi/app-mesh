# src/apps/dexuser/CMakeLists.txt
# dexuser — bundled Dex administration web UI (System App). It runs the shared
# auth-stack launcher (src/apps/identity/appmesh-auth.sh) with the admin-ui
# command; this App has nothing to compile. The bin/dexuser binary is built from
# the Dex fork's examples/example-app by script/bootstrap/install_build_deps*
# and copied into bin/ by script/pack/build_package.*, like the dex server.

if(APPMESH_INSTALL_AUTH_CONFIG)
    install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/dexuser.yaml"
        DESTINATION "apps"
        COMPONENT configs
    )
endif()
