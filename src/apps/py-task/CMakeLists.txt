# src/apps/py-task/CMakeLists.txt
# py-task — execute a Python code string from the task input. Script plus its
# bundled App definition; there is nothing to compile.

install(PROGRAMS "${CMAKE_CURRENT_SOURCE_DIR}/py_task.py"
    DESTINATION "bin"
    COMPONENT binaries
)

install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/py-task.yaml"
    DESTINATION "apps"
    COMPONENT configs
)
