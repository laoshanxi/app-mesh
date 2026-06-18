# src/model-env/CMakeLists.txt

##########################################################################
# Go model-env build (LLM agent model-environment App)
##########################################################################

set(MODELENV_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmd/model-env")

set(MODELENV_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
if(CMAKE_CONFIGURATION_TYPES)
    set(MODELENV_OUTPUT_DIR "${MODELENV_OUTPUT_DIR}/$<CONFIG>")
endif()

set(MODELENV_BIN "${MODELENV_OUTPUT_DIR}/model-env${CMAKE_EXECUTABLE_SUFFIX}")

set(GO_DEBUG_FLAGS "-gcflags=all=-N -l")
set(GO_DEBUG_LDFLAGS "-X main.buildTag=${BUILD_TAG}")

set(GO_RELEASE_FLAGS "-trimpath")
set(GO_RELEASE_LDFLAGS "-s -w -X main.buildTag=${BUILD_TAG}")

add_custom_target(model-env ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${MODELENV_OUTPUT_DIR}"
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=0 go build
        $<$<CONFIG:Debug>:${GO_DEBUG_FLAGS}>
        $<$<NOT:$<CONFIG:Debug>>:${GO_RELEASE_FLAGS}>

        -ldflags "$<$<CONFIG:Debug>:${GO_DEBUG_LDFLAGS}>$<$<NOT:$<CONFIG:Debug>>:${GO_RELEASE_LDFLAGS}>"
        -buildvcs=false
        -o "${MODELENV_BIN}"
        .
    WORKING_DIRECTORY "${MODELENV_SRC_DIR}"
    COMMENT "Building Go model-env ($<IF:$<CONFIG:Debug>,Debug,Release>) - Version: ${PROJECT_VERSION}"
    VERBATIM
    COMMAND_EXPAND_LISTS
)

install(PROGRAMS "${MODELENV_BIN}"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Runtime
)

# Pre-install the Scenario A App definition (ships status:1 / auto-starts on the
# stub backend; an operator reconfigures it per tenant — see config/model-env.yaml).
# The worker and echo-tool templates are intentionally NOT installed (they carry
# placeholder values and would start broken).
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/config/model-env.yaml"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/work/apps"
    COMPONENT Runtime
)
