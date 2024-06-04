cmake_minimum_required(VERSION 3.0)

project(MINIDBG)

set(CMAKE_CXX_STANDARD 14)

include_directories(${INCL_PATH} ${CMAKE_SOURCE_DIR}/libelfin)

set(LIBRARY_OUTPUT_PATH ${LIB_PATH})


link_libraries(${LIB_PATH})

aux_source_directory(./ SRC)

add_executable(${APP_NAME_2} ${SRC})

target_link_libraries(${APP_NAME_2} ${LINENOISE_LIB} ${HELP_LIB} ${REGIS_LIB} ${BP_LIB} ${DBG_LIB} ${CMAKE_SOURCE_DIR}/libelfin/dwarf/libdwarf++.so ${CMAKE_SOURCE_DIR}/libelfin/elf/libelf++.so)