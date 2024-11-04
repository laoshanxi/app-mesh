##########################################################################
# Python wheel package build:
#   To build the package, run:
#       make wheel
#
#   Alternatively, you can build with:
#       python3 -m build --wheel --outdir "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}"
#
#   Note: The `build` module must be installed and updated with:
#       python3 -m pip install --upgrade build
##########################################################################

file(REMOVE_RECURSE "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/*.whl")
add_custom_target(wheel
    COMMENT "python wheel build ${CMAKE_CURRENT_SOURCE_DIR}"
    COMMAND python3 setup.py build --build-base=${CMAKE_CURRENT_BINARY_DIR} egg_info --egg-base ${CMAKE_CURRENT_BINARY_DIR} bdist_wheel --dist-dir ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}
	WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
)
