cmake_minimum_required(VERSION 3.16)
project(bgv_bts)

SET(CMAKE_CXX_STANDARD 17)
add_compile_options(-fPIC -march=native)
# set this to your helib install directory
set(helib_DIR /home/msh/cmakepkg/share/cmake/helib/)
find_package(helib)

add_executable(fatboot fatboot.cpp)
target_link_libraries(fatboot helib ntl gmp)