##########################################################################
# ldapcpp
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(ldapcpp STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::ldapcpp ALIAS ldapcpp)

##########################################################################
# Link
##########################################################################
target_link_libraries(ldapcpp
  PRIVATE
    ldap
    lber
)