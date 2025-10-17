##########################################################################
# appc
##########################################################################

aux_source_directory(. SRC_LIST)
add_executable(appc ${SRC_LIST})
add_executable(${PROJECT_NAME}::appc ALIAS appc)

##########################################################################
# Link
##########################################################################
target_link_libraries(appc
  PRIVATE
  linenoise
  Threads::Threads
  Boost::program_options
  common
  cppsdk
)
