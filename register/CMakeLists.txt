cmake_minimum_required(VERSION 3.0)

project(REGISTER)

set(CMAKE_CXX_STANDARD 14)

include_directories(${ICLD_PATH})

link_directories(${LIBELFIN_PATH}/dwarf)
link_directories(${LIBELFIN_PATH}/elf)
link_directories(${LIB_PATH})

aux_source_directory(./ SRC)

set(LIBRARY_OUTPUT_PATH ${LIB_PATH})

add_library(${REGIS_LIB} SHARED ${SRC})

target_link_libraries(${REGIS_LIB} ${LINENOISE_LIB} ${HELP_LIB} ${BP_LIB} dwarf++ elf++)

