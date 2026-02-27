cmake_minimum_required(VERSION 3.16)

project(botan_vendor NONE)

include(ExternalProject)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_Interpreter_FOUND)
    set(BOTAN_PYTHON "${Python3_EXECUTABLE}")
else()
    find_package(Python COMPONENTS Interpreter)
    if(Python_Interpreter_FOUND)
        set(BOTAN_PYTHON "${Python_EXECUTABLE}")
    endif()
endif()

if(NOT BOTAN_PYTHON)
    message(FATAL_ERROR "Python interpreter not found. Install Python 3 to build Botan.")
endif()

find_program(CCACHE_PROGRAM ccache)
find_program(NINJA_PROGRAM ninja)

set(BOTAN_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(BOTAN_WORK_DIR "${CMAKE_BINARY_DIR}/botan-src")
set(BOTAN_BUILD_DIR  "${CMAKE_BINARY_DIR}/botan-build")
set(BOTAN_INSTALL_DIR "${CMAKE_BINARY_DIR}/botan-install")

# Allow overriding compilers via cache; default to clang/clang++ on macOS.
set(BOTAN_CC "" CACHE STRING "C compiler for Botan")
set(BOTAN_CXX "" CACHE STRING "C++ compiler for Botan")
if(NOT BOTAN_CC)
    if(APPLE)
        set(BOTAN_CC "clang")
    else()
        set(BOTAN_CC "cc")
    endif()
endif()
if(NOT BOTAN_CXX)
    if(APPLE)
        set(BOTAN_CXX "clang++")
    else()
        set(BOTAN_CXX "c++")
    endif()
endif()

set(BOTAN_CXXFLAGS "-std=c++20")
set(BOTAN_LDFLAGS "")
if(APPLE)
    set(BOTAN_CXXFLAGS "-std=c++20 -stdlib=libc++")
    set(BOTAN_LDFLAGS "-stdlib=libc++")
endif()

if(CCACHE_PROGRAM)
    set(BOTAN_CC_ENV "CC=ccache ${BOTAN_CC}")
    set(BOTAN_CXX_ENV "CXX=ccache ${BOTAN_CXX}")
else()
    set(BOTAN_CC_ENV "CC=${BOTAN_CC}")
    set(BOTAN_CXX_ENV "CXX=${BOTAN_CXX}")
endif()

set(BOTAN_ENV_ARGS
    "${BOTAN_CC_ENV}"
    "${BOTAN_CXX_ENV}"
)
if(CMAKE_AR)
    list(APPEND BOTAN_ENV_ARGS "AR=${CMAKE_AR}")
endif()
if(CMAKE_RANLIB)
    list(APPEND BOTAN_ENV_ARGS "RANLIB=${CMAKE_RANLIB}")
endif()

set(BOTAN_CONFIGURE_ARGS
    "--prefix=${BOTAN_INSTALL_DIR}"
    "--with-build-dir=${BOTAN_BUILD_DIR}"
    "--cxxflags=${BOTAN_CXXFLAGS}"
)
if(BOTAN_LDFLAGS)
    list(APPEND BOTAN_CONFIGURE_ARGS "--ldflags=${BOTAN_LDFLAGS}")
endif()
list(APPEND BOTAN_CONFIGURE_ARGS "--without-documentation")
list(APPEND BOTAN_CONFIGURE_ARGS "--build-targets=shared,static")
list(APPEND BOTAN_CONFIGURE_ARGS "--no-install-python-module")

set(BOTAN_BUILD_TOOL "make")
set(BOTAN_BUILD_COMMAND ${CMAKE_MAKE_PROGRAM})
if(NINJA_PROGRAM)
    set(BOTAN_BUILD_TOOL "ninja")
    set(BOTAN_BUILD_COMMAND ${NINJA_PROGRAM})
endif()
list(APPEND BOTAN_CONFIGURE_ARGS "--build-tool=${BOTAN_BUILD_TOOL}")

ExternalProject_Add(botan_build
    SOURCE_DIR "${BOTAN_WORK_DIR}"
    BINARY_DIR "${BOTAN_BUILD_DIR}"
    DOWNLOAD_COMMAND "${CMAKE_COMMAND}" -E copy_directory "${BOTAN_SOURCE_DIR}" "${BOTAN_WORK_DIR}"
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    CONFIGURE_COMMAND
        "${CMAKE_COMMAND}" -E env
        ${BOTAN_ENV_ARGS}
        "${BOTAN_PYTHON}" "${BOTAN_WORK_DIR}/configure.py"
        ${BOTAN_CONFIGURE_ARGS}
    BUILD_COMMAND ${BOTAN_BUILD_COMMAND} -C "${BOTAN_BUILD_DIR}"
    INSTALL_COMMAND ${BOTAN_BUILD_COMMAND} -C "${BOTAN_BUILD_DIR}" install
    LOG_CONFIGURE ON
    LOG_BUILD ON
    LOG_INSTALL ON
    LOG_OUTPUT_ON_FAILURE ON
    BUILD_BYPRODUCTS
        "${BOTAN_INSTALL_DIR}/lib/libbotan-3.a"
        "${BOTAN_INSTALL_DIR}/lib/libbotan-3.dylib"
)

ExternalProject_Add_Step(botan_build coffee_message
    COMMAND ${CMAKE_COMMAND} -E echo "Botan build may take several minutes; go grab a coffee."
    DEPENDEES configure
    DEPENDERS build
)

add_custom_target(botan ALL DEPENDS botan_build)
