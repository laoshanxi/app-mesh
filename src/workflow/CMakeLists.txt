# src/workflow/CMakeLists.txt

##########################################################################
# Go wf-engine build
##########################################################################

set(WORKFLOW_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmd/engine")

set(WORKFLOW_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
if(CMAKE_CONFIGURATION_TYPES)
    set(WORKFLOW_OUTPUT_DIR "${WORKFLOW_OUTPUT_DIR}/$<CONFIG>")
endif()

set(WORKFLOW_BIN "${WORKFLOW_OUTPUT_DIR}/wf-engine${CMAKE_EXECUTABLE_SUFFIX}")

set(GO_DEBUG_FLAGS "-gcflags=all=-N -l")
set(GO_DEBUG_LDFLAGS "-X main.buildTag=${BUILD_TAG}")

set(GO_RELEASE_FLAGS "-trimpath")
set(GO_RELEASE_LDFLAGS "-s -w -X main.buildTag=${BUILD_TAG}")

add_custom_target(wf-engine ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${WORKFLOW_OUTPUT_DIR}"
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=0 go build
        $<$<CONFIG:Debug>:${GO_DEBUG_FLAGS}>
        $<$<NOT:$<CONFIG:Debug>>:${GO_RELEASE_FLAGS}>

        -ldflags "$<$<CONFIG:Debug>:${GO_DEBUG_LDFLAGS}>$<$<NOT:$<CONFIG:Debug>>:${GO_RELEASE_LDFLAGS}>"
        -buildvcs=false
        -o "${WORKFLOW_BIN}"
        .
    WORKING_DIRECTORY "${WORKFLOW_SRC_DIR}"
    COMMENT "Building Go wf-engine ($<IF:$<CONFIG:Debug>,Debug,Release>) - Version: ${PROJECT_VERSION}"
    VERBATIM
    COMMAND_EXPAND_LISTS
)

install(PROGRAMS "${WORKFLOW_BIN}"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Runtime
)

# Pre-install the wf-engine App definition so daemon auto-starts it.
install(FILES "${CMAKE_CURRENT_SOURCE_DIR}/config/workflow.yaml"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/work/apps"
    COMPONENT Runtime
)
