cmake_minimum_required(VERSION 3.22)
project(Profile LANGUAGES C CXX)
# --- Capstone (our fork, built from submodule) ---
set(CAPSTONE_BUILD_SHARED_LIBS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_STATIC_LIBS ON  CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL      OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_LEGACY_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTEST      OFF CACHE BOOL "" FORCE)
set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
set(CAPSTONE_X86_SUPPORT       ON  CACHE BOOL "" FORCE)
set(CAPSTONE_ARM_SUPPORT        ON  CACHE BOOL "" FORCE)
set(CAPSTONE_AARCH64_SUPPORT    ON  CACHE BOOL "" FORCE)
set(CAPSTONE_RISCV_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_PPC_SUPPORT ON CACHE BOOL "" FORCE)
set(CAPSTONE_MIPS_SUPPORT       ON  CACHE BOOL "" FORCE)
# Select the output paths measured with the static Linux Clang decoder.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CMAKE_C_COMPILER_ID STREQUAL "Clang"
   AND CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|amd64|AMD64)$")
    set(CAPSTONE_MIPS_PRECHECK_PRINTED_ALIAS ON)
    set(CAPSTONE_MIPS_FINAL_OUTPUT_TRIM ON)
    set(CAPSTONE_X86_NEAR_INDIRECT_OUTPUT ON)
endif()
add_subdirectory(third_party/capstone)

# Capstone's decode DFA is the single hottest dependency in the front end, so
# keep it explicitly optimized in non-Debug configurations.  This preserves
# representative decode throughput in Release and RelWithDebInfo builds while
# allowing Debug to honor its source-level debugging contract: no forced
# optimization and Capstone's internal assertions enabled.  In particular,
# MSVC's Debug runtime checks are incompatible with /O2. Apply the same flags
# to the ordinary decoder and both static x86 iterators.
include(${CMAKE_SOURCE_DIR}/cmake/NeverDCapstoneCompilerOptions.inc)
foreach(capstone_object IN ITEMS capstone capstone_x86_iter32 capstone_x86_iter64)
    if(MSVC)
        target_compile_options(${capstone_object} PRIVATE
            "$<$<NOT:$<CONFIG:Debug>>:/O2>")
    else()
        target_compile_options(${capstone_object} PRIVATE
            "$<$<NOT:$<CONFIG:Debug>>:-O3;-fomit-frame-pointer>"
            # glibc/clang 21 treat strchr(const char*) as returning const char*.
            "$<$<COMPILE_LANG_AND_ID:C,Clang,AppleClang>:${NEVERD_CAPSTONE_CLANG_QUALIFIERS}>")
    endif()
    target_compile_definitions(${capstone_object} PRIVATE
        "$<$<NOT:$<CONFIG:Debug>>:NDEBUG>")
endforeach()

