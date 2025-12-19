##########################################################################
# SBOM
# in-order to include Python packages:
#   create venv under home and use pip install appmesh
##########################################################################
add_custom_target(sbom
    COMMENT "Generate SBOM dependency list from ${CMAKE_INSTALL_PREFIX} with configuration file: ${CMAKE_CURRENT_SOURCE_DIR}/syft.yaml"
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/syft_dpkg_generate.sh
    COMMAND syft ${CMAKE_INSTALL_PREFIX}/ -c ${CMAKE_CURRENT_SOURCE_DIR}/syft.yaml --source-name ${PROJECT_NAME} --source-version ${PROJECT_VERSION}
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
