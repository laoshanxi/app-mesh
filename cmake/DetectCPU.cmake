# cmake/Utils/DetectCPU.cmake
# Detect number of CPU cores and set PARALLEL_BUILD variable

include(ProcessorCount)
ProcessorCount(NPROC)

if(NOT NPROC EQUAL 0)
    set(PARALLEL_BUILD ${NPROC} CACHE INTERNAL "Number of CPU cores for parallel build")
else()
    set(PARALLEL_BUILD 1 CACHE INTERNAL "Number of CPU cores for parallel build")
endif()
