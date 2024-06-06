cmake_minimum_required(VERSION 3.0)

project(MINIDBG)

# 定义变量
set(ICLD_PATH ${CMAKE_SOURCE_DIR}/include)
set(SRC_PATH ${CMAKE_SOURCE_DIR}/src)
set(EXAMP_PATH ${CMAKE_SOURCE_DIR}/examples)
set(LIB_PATH ${CMAKE_SOURCE_DIR}/lib)
set(EXEC_PATH ${CMAKE_SOURCE_DIR}/bin)
set(LIBELFIN_PATH ${CMAKE_SOURCE_DIR}/libelfin)


## 定义静态库的名称
set(BP_LIB bplib)
set(DBG_LIB dbglib)
set(HELP_LIB helperlib)
set(REGIS_LIB registerlib)
set(LINENOISE_LIB linenoiselib)

## 定义可执行文件的名称
set(APP_NAME_1 hello)
set(APP_NAME_2 minidbg)
set(APP_NAME_3 stack)

# 添加子目录，确认 CMakeLists.txt 关系树
add_subdirectory(breakpoint)
add_subdirectory(debugger)
add_subdirectory(examples)
add_subdirectory(helper)
add_subdirectory(register)
add_subdirectory(src)
add_subdirectory(linenoise)




