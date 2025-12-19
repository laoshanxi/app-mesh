# src/daemon/process/CMakeLists.txt

file(GLOB SRC_LIST *.cpp)
if (WIN32)
    list(REMOVE_ITEM SRC_LIST
      ${CMAKE_CURRENT_SOURCE_DIR}/DockerProcess.cpp
      ${CMAKE_CURRENT_SOURCE_DIR}/DockerApiProcess.cpp
    )
endif()

add_library(process STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::process ALIAS process)
