cmake_minimum_required(VERSION 3.0)

project(breakpoint)

set(CMAKE_CXX_STANDARD 14)

include_directories(${ICLD_PATH})

aux_source_directory(./ SRC)

set(LIBRARY_OUTPUT_PATH ${LIB_PATH})

# 生成静态库
add_library(${BP_LIB} STATIC ${SRC})