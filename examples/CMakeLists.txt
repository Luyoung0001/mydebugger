cmake_minimum_required(VERSION 3.0)

project(examples)

set(EXECUTABLE_OUTPUT_PATH ${EXEC_PATH})

# 添加编译器标志
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -gdwarf-2")

add_executable(${APP_NAME_1} hello.cpp)
add_executable(${APP_NAME_3} stack.cpp)