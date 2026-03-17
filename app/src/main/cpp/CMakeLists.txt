cmake_minimum_required(VERSION 4.2.3)
project(xts_aes_native LANGUAGES CXX)

add_library(xts_aes_native SHARED
    xts_aes_native.cpp
)

target_link_libraries(xts_aes_native
    android
    log
)

set_target_properties(xts_aes_native PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# Aggressive optimization for crypto hot paths
target_compile_options(xts_aes_native PRIVATE -O3 -DNDEBUG)
