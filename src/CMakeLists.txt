cmake_minimum_required(VERSION 3.0)

project(MINIDBG)

set(CMAKE_CXX_STANDARD 14)

include_directories(${ICLD_PATH})

set(EXECUTABLE_OUTPUT_PATH ${EXEC_PATH})

# 添加库搜索路径
link_directories(${LIBELFIN_PATH}/elf)
link_directories(${LIBELFIN_PATH}/dwarf)
link_directories(${LIB_PATH})

aux_source_directory(./ SRC)

add_executable(${APP_NAME_2} ${SRC})

target_link_libraries(${APP_NAME_2} ${DBG_LIB})