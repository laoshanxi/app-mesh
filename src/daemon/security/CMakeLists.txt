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

target_link_libraries(security
  PRIVATE
    rt
)

# spdlog::spdlog carries SPDLOG_COMPILED_LIB: without it these TUs compile
# their own inline copy of the logger registry, which splits from the shared
# library's registry that the logging setup configures - their LOG_* output
# then never reaches server.log.
target_link_libraries(security
  PRIVATE
    spdlog::spdlog
)
