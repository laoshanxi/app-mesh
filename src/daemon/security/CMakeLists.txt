# src/daemon/security/CMakeLists.txt

# --- Define library ---
aux_source_directory(. SRC_LIST)
add_library(security STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::security ALIAS security)

# --- Linking ---
target_link_libraries(security
  PRIVATE
    ${CRYPTOPP_TARGET}
)

if(NOT APPLE AND NOT WIN32)
  target_link_libraries(security
    PRIVATE
      rt
  )
endif()
