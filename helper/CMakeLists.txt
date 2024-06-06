cmake_minimum_required(VERSION 3.0)

project(HELPER)

set(CMAKE_CXX_STANDARD 14)

include_directories(${ICLD_PATH})

aux_source_directory(./ SRC)

set(LIBRARY_OUTPUT_PATH ${LIB_PATH})

add_library(${HELP_LIB} SHARED ${SRC})