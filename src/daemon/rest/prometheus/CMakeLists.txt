##########################################################################
# prometheus
##########################################################################
aux_source_directory(/usr/local/src/prometheus SRC_LIST)
aux_source_directory(/usr/local/src/prometheus/detail DETAIL_SRC_LIST)

add_library(prometheus STATIC ${SRC_LIST} ${DETAIL_SRC_LIST})
add_library(${PROJECT_NAME}::prometheus ALIAS prometheus)

##########################################################################
# Link
##########################################################################
target_include_directories(prometheus
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)
