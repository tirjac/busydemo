cmake_minimum_required(VERSION 3.16)

project(dual_tls_demo LANGUAGES C CXX)

if(APPLE)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "14.0" CACHE STRING "" FORCE)
    if(NOT DEFINED CMAKE_OSX_SYSROOT)
        execute_process(
            COMMAND xcrun --show-sdk-path
            OUTPUT_VARIABLE SDKROOT_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE
        )
        if(SDKROOT_PATH)
            set(CMAKE_OSX_SYSROOT "${SDKROOT_PATH}" CACHE PATH "macOS SDK path" FORCE)
        endif()
    endif()
    if(CMAKE_OSX_SYSROOT)
        add_compile_options(-isysroot ${CMAKE_OSX_SYSROOT})
        add_link_options(-isysroot ${CMAKE_OSX_SYSROOT})
    endif()
endif()

find_program(CCACHE_PROGRAM ccache)
if(CCACHE_PROGRAM)
    set(CMAKE_C_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
    set(CMAKE_CXX_COMPILER_LAUNCHER "${CCACHE_PROGRAM}")
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

if("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source build not allowed. Please use: cmake -S . -B build")
endif()


add_subdirectory(src/oldserver)

# On Linux, prefer system Botan 3 via pkg-config; otherwise build vendored Botan.
if(UNIX AND NOT APPLE)
    find_package(PkgConfig)
    if(PkgConfig_FOUND)
        pkg_check_modules(BOTAN botan-3)
    endif()
    if(NOT BOTAN_FOUND)
        set(BOTAN_VENDOR ON CACHE BOOL "Use vendored Botan build" FORCE)
        set(BOTAN_VENDOR_ROOT "${CMAKE_BINARY_DIR}/botan-install" CACHE PATH "Vendored Botan install prefix" FORCE)
        add_subdirectory(thirdparty/botan-3.10.0 ${CMAKE_BINARY_DIR}/botan-vendor)
    endif()
endif()

add_subdirectory(src/newserver)
add_subdirectory(src/client)
