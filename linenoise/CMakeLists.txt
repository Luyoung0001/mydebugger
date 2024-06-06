cmake_minimum_required(VERSION 3.0)

project(LINENOISE)

aux_source_directory(./ SRC)

include_directories(${ICLD_PATH})

set(LIBRARY_OUTPUT_PATH ${LIB_PATH})

add_library(${LINENOISE_LIB} SHARED ${SRC})
