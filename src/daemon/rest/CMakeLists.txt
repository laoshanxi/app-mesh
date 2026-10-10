# src/daemon/rest/CMakeLists.txt

# --- Subdirectories ---
add_subdirectory(prometheus)

# --- Define library ---
aux_source_directory(. SRC_LIST)
if(CMAKE_CXX_STANDARD GREATER_EQUAL 17)
  aux_source_directory(drogon DROGON_SRC_LIST)
  list(APPEND SRC_LIST ${DROGON_SRC_LIST})
endif()
add_library(rest STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::rest ALIAS rest)

# --- Linking ---
target_link_libraries(rest
  PRIVATE
    Boost::regex
)
if(CMAKE_CXX_STANDARD GREATER_EQUAL 17)
  target_link_libraries(rest PUBLIC Drogon::Drogon)
endif()
