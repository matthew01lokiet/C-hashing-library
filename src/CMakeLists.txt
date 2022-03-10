add_library(hashing_static STATIC hashing.c)

target_include_directories(hashing_static PUBLIC ${CMAKE_CURRENT_LIST_DIR})