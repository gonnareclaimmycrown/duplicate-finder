cmake_minimum_required(VERSION 3.20)
project(dupfind LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(Threads REQUIRED)

add_library(dupfind_core STATIC src/dupfind.cpp)
target_include_directories(dupfind_core PUBLIC src)
target_link_libraries(dupfind_core PUBLIC Threads::Threads bcrypt shell32)
target_compile_definitions(dupfind_core PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)

if(MSVC)
    target_compile_options(dupfind_core PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(dupfind_core PRIVATE -Wall -Wextra -Wpedantic)
endif()
