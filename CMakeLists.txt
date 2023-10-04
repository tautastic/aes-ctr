cmake_minimum_required(VERSION 3.26)
project(aes-ctr)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -std=gnu++1z -O3 -march=native")

add_executable(aes-128-ctr ./aes_128_ctr/main.cpp aes_128_ctr/aes_128_ctr.hpp aes_128_ctr/aes_128_ctr.cpp common_io.hpp)

add_executable(aes-192-ctr ./aes_192_ctr/main.cpp aes_192_ctr/aes_192_ctr.hpp aes_192_ctr/aes_192_ctr.cpp common_io.hpp)

add_executable(aes-256-ctr ./aes_256_ctr/main.cpp aes_256_ctr/aes_256_ctr.hpp aes_256_ctr/aes_256_ctr.cpp common_io.hpp)

set(INSTALL_DIR "$ENV{HOME}/.local/bin")
install(TARGETS aes-128-ctr aes-192-ctr aes-256-ctr RUNTIME DESTINATION ${INSTALL_DIR})