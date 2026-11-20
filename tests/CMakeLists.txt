file(GLOB TEST_SRCS CONFIGURE_DEPENDS *.c)

# Use the exact same sources as the main binary, excluding main.c
file(GLOB_RECURSE NETPEEK_SRCS CONFIGURE_DEPENDS
    ${CMAKE_SOURCE_DIR}/src/*.c
    ${CMAKE_SOURCE_DIR}/utils/*.c)

list(FILTER NETPEEK_SRCS EXCLUDE REGEX ".*/main\\.c$")

add_executable(netpeek_tests
    ${TEST_SRCS}
    ${NETPEEK_SRCS}
)

target_include_directories(netpeek_tests PRIVATE
    ${NP_INCLUDE_DIRS}
    ${PCAP_INCLUDE_DIRS}
    ${PCRE2_INCLUDE_DIRS}
    ${LIBSSH2_INCLUDE_DIRS}
    ${LIBURING_INCLUDE_DIRS}
    ${LUA_INCLUDE_DIR}
)

target_link_directories(netpeek_tests PRIVATE
    ${PCAP_LIBRARY_DIRS}
    ${PCRE2_LIBRARY_DIRS}
    ${LIBSSH2_LIBRARY_DIRS}
    ${LIBURING_LIBRARY_DIRS}
)

target_link_libraries(netpeek_tests PRIVATE
    ${PCAP_LIBRARIES}
    ${PCRE2_LIBRARIES}
    ${LIBSSH2_LIBRARIES}
    ${LIBURING_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    SQLite::SQLite3
    ${LUA_LIBRARIES}
    pthread
    m
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(netpeek_tests PRIVATE dl)
endif()

target_compile_options(netpeek_tests PRIVATE
    ${PCAP_CFLAGS_OTHER}
    ${PCRE2_CFLAGS_OTHER}
    ${LIBSSH2_CFLAGS_OTHER}
    ${LIBURING_CFLAGS_OTHER}
)

target_compile_definitions(netpeek_tests PRIVATE _DEFAULT_SOURCE _DARWIN_C_SOURCE)

add_test(NAME unit COMMAND netpeek_tests)
add_test(
    NAME cmake_version
    COMMAND /bin/sh ${CMAKE_SOURCE_DIR}/tests/test_cmake_version.sh)
add_test(
    NAME release_constcorrect
    COMMAND /bin/sh ${CMAKE_SOURCE_DIR}/tests/test_release_constcorrect.sh)
add_test(
    NAME release_strptime
    COMMAND /bin/sh ${CMAKE_SOURCE_DIR}/tests/test_release_strptime.sh ${LUA_INCLUDE_DIR})