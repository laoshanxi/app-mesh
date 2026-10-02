# src/apps/ping/CMakeLists.txt
# ping — bundled example App definition; there is nothing to compile.

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/ping.yaml"
    DESTINATION "apps"
    COMPONENT configs
)
