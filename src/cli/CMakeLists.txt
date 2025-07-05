##########################################################################
# appc
##########################################################################

aux_source_directory(. SRC_LIST)
add_executable(appc ${SRC_LIST})
add_executable(${PROJECT_NAME}::appc ALIAS appc)

##########################################################################
# Link
##########################################################################
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
  target_link_libraries(appc
   PRIVATE
    ${READLINE_LIBRARY}
    Threads::Threads
    boost_program_options
    common
  )
else()
  target_link_libraries(appc
   PRIVATE
    readline
    Threads::Threads
    boost_program_options
    common
  )
endif()