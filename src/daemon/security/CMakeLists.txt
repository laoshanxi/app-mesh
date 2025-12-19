# src/daemon/security/CMakeLists.txt

if (NOT WIN32)
  add_subdirectory(ldapplugin)
endif()

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(security STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::security ALIAS security)

# --- Linking ---
if(APPLE)
  target_link_libraries(security
    PRIVATE
      cryptopp
      ldapplugin
)
elseif(WIN32)
  target_link_libraries(security
    PRIVATE
      cryptopp::cryptopp
  )
else()
  target_link_libraries(security
    PRIVATE
      cryptopp
      rt
      ldapplugin
  )
endif()
