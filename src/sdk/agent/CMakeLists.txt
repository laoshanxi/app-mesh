# src/sdk/agent/CMakeLists.txt

##########################################################################
# Golang agent build
##########################################################################
set(AGENT_BIN ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/agent${CMAKE_EXECUTABLE_SUFFIX})
set(AGENT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cmd)

add_custom_target(agent ALL
    COMMAND go build -buildvcs=false -o ${AGENT_BIN} ${AGENT_SRC_DIR}
    WORKING_DIRECTORY ${AGENT_SRC_DIR}
    COMMENT "Golang build agent"
    VERBATIM
)