cmake_minimum_required(VERSION 3.20.0)
set(CMAKE_CXX_STANDARD 20)
project(STEAM_THING)

add_library(main SHARED dll.cpp)
target_include_directories(main PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(main "${CMAKE_CURRENT_SOURCE_DIR}/steam_api64.lib")

add_executable(injector exe.cpp)