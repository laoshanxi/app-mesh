# src/sdk/python/CMakeLists.txt
##########################################################################
# Python package build (PEP 517 front-end)
# To build the package, run:
#     make wheel
#
# This target uses the supported PEP 517 front-end `python -m build` which
# produces both sdist and wheel artifacts. It requires the `build` package to
# be installed in the Python environment:
#     python3 -m pip install --upgrade build
##########################################################################

find_package(Python3 REQUIRED COMPONENTS Interpreter)
file(REMOVE_RECURSE "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/*")
add_custom_target(wheel
    COMMENT "python package build ${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND ${Python3_EXECUTABLE} -m build --wheel --outdir ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
