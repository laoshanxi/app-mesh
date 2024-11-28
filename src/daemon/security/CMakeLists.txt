##########################################################################
# sub dir
##########################################################################
add_subdirectory(ldapplugin)

##########################################################################
# security
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(security STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::security ALIAS security)

##########################################################################
# Link
##########################################################################

if(APPLE)
  target_link_libraries(security
    PRIVATE
      cryptopp
      ldapplugin
      oath
)
else()
  target_link_libraries(security
    PRIVATE
      cryptopp
      rt
      ldapplugin
      oath
  )
endif()
