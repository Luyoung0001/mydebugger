cmake_minimum_required(VERSION 3.0)

project(DEBUGGER)

set(CMAKE_CXX_STANDARD 14)

include_directories(${ICLD_PATH})

link_directories(${LIBELFIN_PATH}/dwarf)
link_directories(${LIBELFIN_PATH}/elf)
link_directories(${LIB_PATH})

aux_source_directory(./ SRC)

set(LIBRARY_OUTPUT_PATH ${LIB_PATH})

add_library(${DBG_LIB} SHARED ${SRC})

target_link_libraries(${DBG_LIB} ${REGIS_LIB})