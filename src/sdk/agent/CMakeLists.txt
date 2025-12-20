# src/sdk/agent/CMakeLists.txt

##########################################################################
# Golang agent build
##########################################################################
set(AGENT_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/cmd)

set(AGENT_OUTPUT_DIR ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
if(CMAKE_CONFIGURATION_TYPES)
    set(AGENT_OUTPUT_DIR ${AGENT_OUTPUT_DIR}/$<CONFIG>)
endif()
set(AGENT_BIN ${AGENT_OUTPUT_DIR}/agent${CMAKE_EXECUTABLE_SUFFIX})

add_custom_target(agent ALL
    COMMAND go build -buildvcs=false -o ${AGENT_BIN} ${AGENT_SRC_DIR}
    WORKING_DIRECTORY ${AGENT_SRC_DIR}
    COMMENT "Golang build agent"
    VERBATIM
)