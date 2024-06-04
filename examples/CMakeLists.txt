cmake_minimum_required(VERSION 3.0)

aux_source_directory(./ SRC)

set(EXECUTABLE_OUTPUT_PATH ${EXEC_PATH})

add_executable(${APP_NAME_1} ${SRC})