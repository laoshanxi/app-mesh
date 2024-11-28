##########################################################################
# client
##########################################################################
aux_source_directory(. SRC_LIST)
add_library(client STATIC ${SRC_LIST})
add_library(${PROJECT_NAME}::client ALIAS client)

if (APPLE)
  # Locate readline
  find_path(READLINE_INCLUDE_DIR readline/readline.h HINTS /opt/homebrew/opt/readline/include)
  find_library(READLINE_LIBRARY NAMES readline HINTS /opt/homebrew/opt/readline/lib)

  # Check if found
  if (NOT READLINE_INCLUDE_DIR OR NOT READLINE_LIBRARY)
    message(FATAL_ERROR "Readline library not found. Please install it with Homebrew.")
  endif()

  # Include the directory
  include_directories(${READLINE_INCLUDE_DIR})
  message(STATUS "readline include dir: ${READLINE_INCLUDE_DIR}")

  # Link the library
  target_link_libraries(client PRIVATE ${READLINE_LIBRARY})
else()
  target_link_libraries(client PRIVATE readline)
endif()