cmake_minimum_required(VERSION 4.0)
project(flash C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
if (MSVC)
    add_compile_options(/W4 /permissive-)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# BLAKE3
set(BLAKE3_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/third_party/blake3)

set(BLAKE3_CORE
        ${BLAKE3_DIR}/blake3.c
        ${BLAKE3_DIR}/blake3_portable.c
        ${BLAKE3_DIR}/blake3_dispatch.c
        include/flash/index.h
)

set(BLAKE3_SIMD_X86
        ${BLAKE3_DIR}/blake3_sse2.c
        ${BLAKE3_DIR}/blake3_sse41.c
        ${BLAKE3_DIR}/blake3_avx2.c
        ${BLAKE3_DIR}/blake3_avx512.c
)

set(BLAKE3_SIMD_ARM
        ${BLAKE3_DIR}/blake3_neon.c
)

add_library(blake3 STATIC ${BLAKE3_CORE})
target_include_directories(blake3 PUBLIC ${BLAKE3_DIR})

# Detect architecture and add SIMD sources + per-file flags
string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" CPU_LOWER)

if (CPU_LOWER MATCHES "x86_64|amd64|x86|i[3-6]86")
    target_sources(blake3 PRIVATE ${BLAKE3_SIMD_X86})
    if (MSVC)
        set_source_files_properties(${BLAKE3_DIR}/blake3_avx2.c PROPERTIES COMPILE_OPTIONS "/arch:AVX2")
        set_source_files_properties(${BLAKE3_DIR}/blake3_avx512.c PROPERTIES COMPILE_OPTIONS "/arch:AVX512")
    else()
        set_source_files_properties(${BLAKE3_DIR}/blake3_sse2.c PROPERTIES COMPILE_OPTIONS "-msse2")
        set_source_files_properties(${BLAKE3_DIR}/blake3_sse41.c PROPERTIES COMPILE_OPTIONS "-msse4.1")
        set_source_files_properties(${BLAKE3_DIR}/blake3_avx2.c PROPERTIES COMPILE_OPTIONS "-mavx2")
        set_source_files_properties(${BLAKE3_DIR}/blake3_avx512.c PROPERTIES COMPILE_OPTIONS "-mavx512f;-mavx512vl")
    endif()
elseif (CPU_LOWER MATCHES "aarch64|arm64|armv7|armv8|arm")
    target_sources(blake3 PRIVATE ${BLAKE3_SIMD_ARM})
    if (CPU_LOWER MATCHES "armv7")
        set_source_files_properties(${BLAKE3_DIR}/blake3_neon.c PROPERTIES COMPILE_OPTIONS "-mfpu=neon")
    endif()
endif()

# Core library
add_library(frf STATIC src/frf.c src/crc32.c src/flash_reader.c
        src/seal.c src/third_party/monocypher/monocypher.c
        src/index.c)
target_include_directories(frf PUBLIC include)
target_link_libraries(frf PRIVATE blake3)
target_include_directories(frf PRIVATE ${BLAKE3_DIR})

# Tiny tools
add_executable(flsh_write tools/flsh_write.c)
target_link_libraries(flsh_write PRIVATE frf)

add_executable(flsh_read tools/flsh_read.c)
target_link_libraries(flsh_read PRIVATE frf)

# Unified CLI
add_executable(flash
        cli/flash_main.c
        cli/ingest.c
        cli/ingest_formats.c
        cli/ingest_source.c
        cli/verify.c
        cli/repair.c
        cli/replay.c
        cli/index.c
        cli/merge.c
        cli/export.c
)
target_link_libraries(flash PRIVATE frf)
target_include_directories(flash PRIVATE include)

if (WIN32)
    target_link_libraries(flash PRIVATE ws2_32)
    target_link_libraries(frf PRIVATE bcrypt)
endif()

# Put all binaries in bin/
set_target_properties(flsh_write flsh_read flash PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")