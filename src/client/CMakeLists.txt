if(BOTAN_VENDOR)
    set(BOTAN_ROOT "${BOTAN_VENDOR_ROOT}")
    set(BOTAN_INCLUDE_DIR "${BOTAN_ROOT}/include/botan-3")
    set(BOTAN_LIBRARY "${BOTAN_ROOT}/lib/libbotan-3${CMAKE_SHARED_LIBRARY_SUFFIX}")
    if(NOT EXISTS "${BOTAN_LIBRARY}")
        set(BOTAN_LIBRARY "${BOTAN_ROOT}/lib/libbotan-3.a")
    endif()
    file(MAKE_DIRECTORY "${BOTAN_INCLUDE_DIR}")
    add_library(botan_client_lib UNKNOWN IMPORTED)
    set_target_properties(botan_client_lib PROPERTIES
        IMPORTED_LOCATION "${BOTAN_LIBRARY}"
        INTERFACE_INCLUDE_DIRECTORIES "${BOTAN_INCLUDE_DIR}"
    )
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(BOTAN REQUIRED botan-3)
endif()

add_executable(client
    client.cpp
    ../newserver/newserver_tls.cpp
)

if(BOTAN_VENDOR)
    target_include_directories(client PRIVATE ${BOTAN_INCLUDE_DIR})
    target_link_libraries(client PRIVATE botan_client_lib)
else()
    target_include_directories(client PRIVATE ${BOTAN_INCLUDE_DIRS})
    target_link_directories(client PRIVATE ${BOTAN_LIBRARY_DIRS})
    target_link_libraries(client PRIVATE ${BOTAN_LIBRARIES})
    target_compile_options(client PRIVATE ${BOTAN_CFLAGS})
endif()

target_include_directories(client PRIVATE ../newserver)

find_package(Threads REQUIRED)
target_link_libraries(client PRIVATE Threads::Threads ${CMAKE_DL_LIBS})

set_target_properties(client PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
)
