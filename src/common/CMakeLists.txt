##########################################################################
# common
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(common STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::common ALIAS common)

##########################################################################
# Link
##########################################################################
target_link_libraries(common
  PRIVATE
    log4cpp
    boost_regex
    cryptopp
)
