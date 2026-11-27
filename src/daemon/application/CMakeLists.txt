# src/daemon/application/CMakeLists.txt

# --- Define application library ---
file(GLOB SRC_LIST CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/*.cpp)
add_library(application STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::application ALIAS application)

# spdlog: keep the inline registry out of these objects (see rest/CMakeLists.txt).
target_link_libraries(application PRIVATE spdlog::spdlog)
# Application.h exposes rest types; declare it so consumers link rest after application.
target_link_libraries(application PUBLIC rest)
