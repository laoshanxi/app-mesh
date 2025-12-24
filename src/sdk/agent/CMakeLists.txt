# src/sdk/agent/CMakeLists.txt

##########################################################################
# Golang agent build - Optimized & Debug Friendly
##########################################################################

set(AGENT_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/cmd")

set(AGENT_OUTPUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
if(CMAKE_CONFIGURATION_TYPES)
    set(AGENT_OUTPUT_DIR "${AGENT_OUTPUT_DIR}/$<CONFIG>")
endif()

set(AGENT_BIN "${AGENT_OUTPUT_DIR}/agent${CMAKE_EXECUTABLE_SUFFIX}")

set(GO_BASE_LDFLAGS "-X main.version=${PROJECT_VERSION}")

set(GO_DEBUG_FLAGS "-gcflags=all=-N -l") 
set(GO_DEBUG_LDFLAGS "${GO_BASE_LDFLAGS}")

set(GO_RELEASE_FLAGS "-trimpath")
set(GO_RELEASE_LDFLAGS "-s -w ${GO_BASE_LDFLAGS}")

add_custom_target(agent ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${AGENT_OUTPUT_DIR}"
    COMMAND ${CMAKE_COMMAND} -E env CGO_ENABLED=0 go build
        $<$<CONFIG:Debug>:${GO_DEBUG_FLAGS}>
        $<$<NOT:$<CONFIG:Debug>>:${GO_RELEASE_FLAGS}>
        
        -ldflags "$<$<CONFIG:Debug>:${GO_DEBUG_LDFLAGS}>$<$<NOT:$<CONFIG:Debug>>:${GO_RELEASE_LDFLAGS}>"
        -buildvcs=false
        -o "${AGENT_BIN}"
        .
    WORKING_DIRECTORY "${AGENT_SRC_DIR}"
    BYPRODUCTS "${AGENT_BIN}"
    COMMENT "Building Go agent ($<IF:$<CONFIG:Debug>,Debug,Release>) - Version: ${PROJECT_VERSION}"
    VERBATIM
    COMMAND_EXPAND_LISTS
)

install(PROGRAMS "${AGENT_BIN}"
    DESTINATION ${CMAKE_INSTALL_BINDIR}
    COMPONENT Runtime
)
