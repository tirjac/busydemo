if(BOTAN_VENDOR)
    set(BOTAN_ROOT "${BOTAN_VENDOR_ROOT}")
    set(BOTAN_INCLUDE_DIR "${BOTAN_ROOT}/include/botan-3")
    set(BOTAN_LIBRARY "${BOTAN_ROOT}/lib/libbotan-3${CMAKE_SHARED_LIBRARY_SUFFIX}")
    if(NOT EXISTS "${BOTAN_LIBRARY}")
        set(BOTAN_LIBRARY "${BOTAN_ROOT}/lib/libbotan-3.a")
    endif()
    # Ensure include dir exists to satisfy CMake, even before install step.
    file(MAKE_DIRECTORY "${BOTAN_INCLUDE_DIR}")
    add_library(botan_lib UNKNOWN IMPORTED)
    set_target_properties(botan_lib PROPERTIES
        IMPORTED_LOCATION "${BOTAN_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${BOTAN_INCLUDE_DIR}"
    )
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(BOTAN REQUIRED botan-3)
endif()

find_package(Threads REQUIRED)

add_executable(newserver
    newserver.cpp
    newserver_db.cpp
    newserver_sync.cpp
    newserver_tls.cpp
)

if(BOTAN_VENDOR AND TARGET botan)
    add_dependencies(newserver botan)
endif()

find_package(SQLite3 REQUIRED)

if(BOTAN_VENDOR)
    target_include_directories(newserver PRIVATE ${BOTAN_INCLUDE_DIR})
else()
    target_include_directories(newserver PRIVATE ${BOTAN_INCLUDE_DIRS})
endif()
target_include_directories(newserver PRIVATE ../../thirdparty/nlohmann_json/single_include)
if(BOTAN_VENDOR)
    target_link_libraries(newserver PRIVATE botan_lib)
else()
    target_link_directories(newserver PRIVATE ${BOTAN_LIBRARY_DIRS})
    target_link_libraries(newserver PRIVATE ${BOTAN_LIBRARIES})
    target_compile_options(newserver PRIVATE ${BOTAN_CFLAGS})
endif()
target_link_libraries(newserver PRIVATE SQLite::SQLite3 Threads::Threads ${CMAKE_DL_LIBS})

if(APPLE)
    # Keep Apple clang defaults; no extra stdlib flags required.
endif()

set_target_properties(newserver PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
