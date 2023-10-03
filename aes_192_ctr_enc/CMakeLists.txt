cmake_minimum_required(VERSION 3.26)
project(aes-192-ctr-enc)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=gnu++1z -O3 -march=native")

add_executable(aes-192-ctr-enc main.cpp aes_192_ctr_enc.hpp aes_192_ctr_enc.cpp)
