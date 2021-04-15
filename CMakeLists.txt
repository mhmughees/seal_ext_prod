cmake_minimum_required(VERSION 3.12)
project(external_prod VERSION 0.1 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)

find_package(SEAL 3.5.1 EXACT REQUIRED)
include_directories("/usr/local/include")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY
            STRINGS "Release" "Debug" "MinSizeRel" "RelWithDebInfo")
endif()
message(STATUS "Build type (CMAKE_BUILD_TYPE): ${CMAKE_BUILD_TYPE}")

option(NFL_OPTIMIZED "Build an optimized version of NFL" OFF)
if(NFL_OPTIMIZED)
    message(STATUS "Tring to use optimized version of NFL")
    add_definitions(-DNFL_OPTIMIZED)

    include(CheckCXXSourceCompiles)
    set(CMAKE_CXX_FLAGS_OLD ${CMAKE_CXX_FLAGS})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

    check_cxx_source_compiles("#include <immintrin.h>\nint main() { return 0;}" NFLLIB_USE_AVX)
    check_cxx_source_compiles("#include <pmmintrin.h>\nint main() { return 0;}" NFLLIB_USE_SSE)
    if(NFLLIB_USE_AVX)
        message(STATUS "Using AVX vector engine")
        add_definitions(-DNTT_AVX2)
    elseif(NFLLIB_USE_SSE)
        message(STATUS "Using SSE vector engine")
        add_definitions(-DNTT_SSE)
    else()
        message(ERROR "Asking for optimized mode but neither SSE not AVX support detected")
    endif()
endif()


add_executable(external_prod main.cpp external_prod.h external_prod.cpp util.h)

target_link_libraries(external_prod PRIVATE SEAL::seal)
target_link_libraries(external_prod PRIVATE /usr/local/lib/libnfllib.dylib)
