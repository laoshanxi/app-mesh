# src/sdk/cpp/CMakeLists.txt
##########################################################################
# CPP SDK
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(cppsdk STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::cppsdk ALIAS cppsdk)
