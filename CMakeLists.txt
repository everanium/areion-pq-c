# Copyright (c) 2026 Andrey Kuvshinov
# Dual-licensed under Apache-2.0 OR MIT.

cmake_minimum_required(VERSION 3.16)
project(areion_pq VERSION 0.1.1 LANGUAGES C ASM)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

set(AREION_C_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../areion-c" CACHE PATH "Path to areion-c directory")

set(AREION_PQ_C_SRCS
    constants.c
    cpu.c
    cpu_amd64.c
    cpu_arm64.c
    cpu_other.c
    areion_pq_purec.c
    areion_pq_amd64.c
    areion_pq_arm64.c
    areion_pq_other.c
    ${AREION_C_DIR}/constants.c
    ${AREION_C_DIR}/cpu.c
    ${AREION_C_DIR}/cpu_amd64.c
    ${AREION_C_DIR}/cpu_arm64.c
    ${AREION_C_DIR}/cpu_other.c
    ${AREION_C_DIR}/areion_purec.c
    ${AREION_C_DIR}/areion_amd64.c
    ${AREION_C_DIR}/areion_arm64.c
    ${AREION_C_DIR}/areion_other.c
)

if(MSVC)
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        enable_language(ASM_MASM)
        set(AREION_PQ_ASM_SRCS
            msvc/areion_pq_amd64.asm
            ${AREION_C_DIR}/msvc/areion_amd64.asm
            ${AREION_C_DIR}/msvc/areion_soem256_amd64.asm
            ${AREION_C_DIR}/msvc/areion_soem512_amd64.asm
            ${AREION_C_DIR}/msvc/areion_soem_aesni_amd64.asm
        )
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        enable_language(ASM_MARMASM)
        set(AREION_PQ_ASM_SRCS
            msvc/areion_pq_arm64.asm
            ${AREION_C_DIR}/msvc/areion_arm64.asm
        )
    else()
        set(AREION_PQ_ASM_SRCS "")
    endif()
else()
    set(AREION_PQ_ASM_SRCS
        areion_pq_amd64.S
        areion_pq_arm64.S
        ${AREION_C_DIR}/areion_amd64.S
        ${AREION_C_DIR}/areion_soem256_amd64.S
        ${AREION_C_DIR}/areion_soem512_amd64.S
        ${AREION_C_DIR}/areion_soem_aesni_amd64.S
        ${AREION_C_DIR}/areion_arm64.S
    )
    set_source_files_properties(${AREION_PQ_ASM_SRCS} PROPERTIES LANGUAGE C)
endif()

add_library(areion_pq_static STATIC ${AREION_PQ_C_SRCS} ${AREION_PQ_ASM_SRCS})
set_target_properties(areion_pq_static PROPERTIES
    OUTPUT_NAME areion_pq
    POSITION_INDEPENDENT_CODE ON
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
target_compile_definitions(areion_pq_static PRIVATE "AREION_API=")
target_include_directories(areion_pq_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${AREION_C_DIR})

add_library(areion_pq_shared SHARED ${AREION_PQ_C_SRCS} ${AREION_PQ_ASM_SRCS})
set_target_properties(areion_pq_shared PROPERTIES
    OUTPUT_NAME areion_pq
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)
target_compile_definitions(areion_pq_shared PRIVATE AREION_PQ_SHARED_EXPORTS "AREION_API=")
target_include_directories(areion_pq_shared PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${AREION_C_DIR})
if(UNIX AND NOT APPLE)
    target_link_options(areion_pq_shared PRIVATE "-Wl,-z,relro,-z,now,-z,noexecstack")
endif()

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    include(CheckCCompilerFlag)
    set(AREION_PQ_WARN_FLAGS
        -Wpedantic -Wall -Wextra -Wconversion -Wsign-conversion -Wshadow -Wvla
        -Wstrict-prototypes -Wmissing-prototypes -Wold-style-definition
        -Wcast-qual -Wcast-align -Wundef -Wformat=2
        -fstrict-aliasing -Wstrict-aliasing=2 -fvisibility=hidden -Werror
    )
    set(AREION_PQ_CFI_FLAGS "")
    if(CMAKE_SYSTEM_PROCESSOR MATCHES "AMD64|x86_64")
        check_c_compiler_flag("-fcf-protection=full" AREION_PQ_HAS_CF_PROTECTION)
        if(AREION_PQ_HAS_CF_PROTECTION)
            list(APPEND AREION_PQ_WARN_FLAGS "-fcf-protection=full")
            list(APPEND AREION_PQ_CFI_FLAGS "-fcf-protection=full")
        endif()
    elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "ARM64|aarch64")
        check_c_compiler_flag("-mbranch-protection=standard" AREION_PQ_HAS_BRANCH_PROTECTION)
        if(AREION_PQ_HAS_BRANCH_PROTECTION)
            list(APPEND AREION_PQ_WARN_FLAGS "-mbranch-protection=standard")
            list(APPEND AREION_PQ_CFI_FLAGS "-mbranch-protection=standard")
        endif()
    endif()
    target_compile_options(areion_pq_static PRIVATE ${AREION_PQ_WARN_FLAGS})
    target_compile_options(areion_pq_shared PRIVATE ${AREION_PQ_WARN_FLAGS})
    target_link_options(areion_pq_shared PRIVATE -fvisibility=hidden ${AREION_PQ_CFI_FLAGS})
endif()

enable_testing()
find_package(Threads REQUIRED)

add_executable(areion_pq_test areion_pq_test.c)
target_link_libraries(areion_pq_test PRIVATE areion_pq_static Threads::Threads)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(areion_pq_test PRIVATE ${AREION_PQ_WARN_FLAGS})
endif()
add_test(NAME areion_pq_test COMMAND areion_pq_test)

add_executable(areion_pq_zeroize_test areion_pq_zeroize_test.c)
target_link_libraries(areion_pq_zeroize_test PRIVATE areion_pq_static)
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(areion_pq_zeroize_test PRIVATE ${AREION_PQ_WARN_FLAGS})
endif()
add_test(NAME areion_pq_zeroize_test COMMAND areion_pq_zeroize_test)
