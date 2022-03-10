cmake_minimum_required(VERSION 3.0.0)
project(Hashing VERSION 1.0.0)

set(TARGET_GROUP "build" CACHE STRING "Group to build")

add_subdirectory(src)

if(TARGET_GROUP STREQUAL "test")
    include(CTest)
    add_subdirectory(external)
    add_subdirectory(test)
endif()