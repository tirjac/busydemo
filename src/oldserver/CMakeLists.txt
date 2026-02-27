add_executable(oldserver
    oldserver.cpp
    oldserver_db.cpp
    oldserver_sync.cpp
    ../../thirdparty/simpleson/json.cpp
)

target_include_directories(oldserver PRIVATE ../../thirdparty/simpleson)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
target_link_libraries(oldserver PRIVATE SQLite::SQLite3 OpenSSL::SSL OpenSSL::Crypto)

set_target_properties(oldserver PROPERTIES
    CXX_STANDARD 98
    CXX_STANDARD_REQUIRED ON
)
