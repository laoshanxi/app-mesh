# src/CMakeLists.txt

add_subdirectory(common)
add_subdirectory(daemon)
# The bundled auth stack (launcher, Dex config, password-hash) is Linux/macOS
# only; Windows packages are external-issuer-only.
if(UNIX)
    add_subdirectory(auth)
endif()
add_subdirectory(sdk)
add_subdirectory(workflow)
