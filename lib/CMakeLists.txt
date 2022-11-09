cmake_minimum_required(VERSION 3.0.0)

project(wakeup VERSION 0.1.0)

add_executable(wakeup
  main.cpp
  wol.cpp
)

include_directories(${CMAKE_SOURCE_DIR}/include)

target_link_libraries(wakeup net)

set(CMAKE_EXE_LINKER_FLAGS "-Wl,-rpath='$ORIGIN'")
