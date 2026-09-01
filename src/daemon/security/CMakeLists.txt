# src/daemon/security/CMakeLists.txt

# --- Define library ---
set(SRC_LIST
  AuthorizationStore.cpp
  HMACVerifier.cpp
  InternalCapability.cpp
  OidcTokenVerifier.cpp
  Principal.cpp
  SecretProtector.cpp
  Security.cpp
  SecurityOidc.cpp
  SharedMemory.cpp
)
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
