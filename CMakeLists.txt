cmake_minimum_required(VERSION 4.0)
project(flash C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
if (MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Core library
add_library(frf STATIC
        src/frf.c
        src/crc32.c
)
target_include_directories(frf PUBLIC include)

# Generic tools
add_executable(flsh_write tools/flsh_write.c)
target_link_libraries(flsh_write PRIVATE frf)

add_executable(flsh_read tools/flsh_read.c)
target_link_libraries(flsh_read PRIVATE frf)

set_target_properties(flsh_write flsh_read PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
