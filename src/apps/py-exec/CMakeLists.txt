# src/apps/py-exec/CMakeLists.txt
# py-exec — execute a Python code string from the run metadata. Script plus its
# bundled App definition; there is nothing to compile.

install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/py_exec.py"
    DESTINATION "bin"
    COMPONENT binaries
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/py-exec.yaml"
    DESTINATION "apps"
    COMPONENT configs
)
