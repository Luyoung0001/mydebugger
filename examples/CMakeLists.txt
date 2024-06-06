cmake_minimum_required(VERSION 3.0)

project(HELLO)

aux_source_directory(./ SRC)

set(EXECUTABLE_OUTPUT_PATH ${EXEC_PATH})

# 添加编译器标志
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

add_executable(${APP_NAME_1} ${SRC})