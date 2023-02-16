##########################################################################
# ldapcpp
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(ldapplugin STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::ldapplugin ALIAS ldapplugin)

##########################################################################
# Link
##########################################################################
target_link_libraries(ldapplugin
  PRIVATE
    common
    ldapc++
    ldap
    lber
)
