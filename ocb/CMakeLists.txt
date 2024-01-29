cmake_minimum_required(VERSION 3.27)
project(ocb C)

#set(CMAKE_C_COMPILER "gcc")
set(CMAKE_C_STANDARD 23)
set(EXECUTABLE_OUTPUT_PATH ./target)
add_compile_options(-O3 -march=native -Wall -Wextra -Wpedantic)

add_executable(ocb main.c
        ocb/ocb.c
        ocb/ocb.h
        lea/lea.c)
