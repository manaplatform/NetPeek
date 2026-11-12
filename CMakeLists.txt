cmake_minimum_required(VERSION 3.16)
project(netpeek VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

configure_file(include/version.h.in include/version.h)

include(CTest)

find_package(PkgConfig REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Lua 5.4 REQUIRED)
find_package(SQLite3 REQUIRED)

pkg_check_modules(PCAP QUIET libpcap)
if(NOT PCAP_FOUND)
    find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
    find_library(PCAP_LIBRARY pcap)
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR "libpcap not found. Install with: brew install libpcap OR apt install libpcap-dev")
    endif()
    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
endif()

pkg_check_modules(PCRE2 QUIET libpcre2-8)
if(NOT PCRE2_FOUND)
    find_path(PCRE2_INCLUDE_DIR pcre2.h)
    find_library(PCRE2_LIBRARY pcre2-8)
    if(NOT PCRE2_INCLUDE_DIR OR NOT PCRE2_LIBRARY)
        message(FATAL_ERROR "PCRE2 not found. Install with: brew install pcre2 OR apt install libpcre2-dev")
    endif()
    set(PCRE2_INCLUDE_DIRS ${PCRE2_INCLUDE_DIR})
    set(PCRE2_LIBRARIES ${PCRE2_LIBRARY})
endif()

pkg_check_modules(LIBSSH2 QUIET libssh2)
if(NOT LIBSSH2_FOUND)
    find_path(LIBSSH2_INCLUDE_DIR libssh2.h)
    find_library(LIBSSH2_LIBRARY ssh2)
    if(NOT LIBSSH2_INCLUDE_DIR OR NOT LIBSSH2_LIBRARY)
        message(FATAL_ERROR "libssh2 not found. Install with: brew install libssh2 OR apt install libssh2-1-dev")
    endif()
    set(LIBSSH2_INCLUDE_DIRS ${LIBSSH2_INCLUDE_DIR})
    set(LIBSSH2_LIBRARIES ${LIBSSH2_LIBRARY})
endif()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    pkg_check_modules(LIBURING QUIET liburing)
endif()

file(GLOB_RECURSE NETPEEK_SRCS CONFIGURE_DEPENDS
    src/*.c
    utils/*.c)

set(NP_INCLUDE_DIRS ${CMAKE_SOURCE_DIR}/include ${CMAKE_BINARY_DIR}/include)
file(GLOB_RECURSE NP_INCLUDE_DIR_CANDIDATES LIST_DIRECTORIES true ${CMAKE_SOURCE_DIR}/include/*)
foreach(candidate ${NP_INCLUDE_DIR_CANDIDATES})
    if(IS_DIRECTORY ${candidate})
        list(APPEND NP_INCLUDE_DIRS ${candidate})
    endif()
endforeach()
list(REMOVE_DUPLICATES NP_INCLUDE_DIRS)

add_executable(netpeek ${NETPEEK_SRCS})

target_include_directories(netpeek PRIVATE
    ${NP_INCLUDE_DIRS}
    ${PCAP_INCLUDE_DIRS}
    ${PCRE2_INCLUDE_DIRS}
    ${LIBSSH2_INCLUDE_DIRS}
    ${LIBURING_INCLUDE_DIRS}
    ${LUA_INCLUDE_DIR})

target_link_directories(netpeek PRIVATE
    ${PCAP_LIBRARY_DIRS}
    ${PCRE2_LIBRARY_DIRS}
    ${LIBSSH2_LIBRARY_DIRS}
    ${LIBURING_LIBRARY_DIRS})

target_link_libraries(netpeek PRIVATE
    ${PCAP_LIBRARIES}
    ${PCRE2_LIBRARIES}
    ${LIBSSH2_LIBRARIES}
    ${LIBURING_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    ${LUA_LIBRARIES}
    pthread
    m)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(netpeek PRIVATE dl)
endif()

target_compile_options(netpeek PRIVATE
    ${PCAP_CFLAGS_OTHER}
    ${PCRE2_CFLAGS_OTHER}
    ${LIBSSH2_CFLAGS_OTHER}
    ${LIBURING_CFLAGS_OTHER})

if(LIBURING_FOUND)
    target_compile_definitions(netpeek PRIVATE NP_HAVE_LIBURING)
endif()

target_compile_definitions(netpeek PRIVATE _DEFAULT_SOURCE _DARWIN_C_SOURCE)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_compile_options(netpeek PRIVATE -O0 -g -fsanitize=address,undefined)
    target_link_options(netpeek PRIVATE -fsanitize=address,undefined)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(netpeek PRIVATE -O2 -march=native -flto)
    target_link_options(netpeek PRIVATE -flto)
elseif(CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
    target_compile_options(netpeek PRIVATE -O2 -g)
endif()

if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

install(TARGETS netpeek RUNTIME DESTINATION bin)

