# src/CMakeLists.txt

add_subdirectory(common)
add_subdirectory(daemon)
# The passhash helper and bundled authentication assets are cross-platform.
add_subdirectory(auth)
add_subdirectory(sdk)
add_subdirectory(workflow)
