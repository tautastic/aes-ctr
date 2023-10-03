cmake_minimum_required(VERSION 3.26)
project(aes-256-ctr-enc)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=gnu++1z -O3 -march=native")

add_executable(aes-256-ctr-enc main.cpp aes_256_ctr_enc.hpp aes_256_ctr_enc.cpp)
