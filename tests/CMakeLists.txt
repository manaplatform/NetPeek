file(GLOB TEST_SRCS CONFIGURE_DEPENDS *.c)

add_executable(netpeek_tests ${TEST_SRCS}
    ${CMAKE_SOURCE_DIR}/src/args.c
    ${CMAKE_SOURCE_DIR}/src/netpeek.c
    ${CMAKE_SOURCE_DIR}/src/target.c
    ${CMAKE_SOURCE_DIR}/src/ports.c
    ${CMAKE_SOURCE_DIR}/src/core/arena.c
    ${CMAKE_SOURCE_DIR}/src/core/checksum.c
    ${CMAKE_SOURCE_DIR}/src/core/error.c
    ${CMAKE_SOURCE_DIR}/src/logger.c
    ${CMAKE_SOURCE_DIR}/src/proxy.c
    ${CMAKE_SOURCE_DIR}/src/evasion/evasion.c
    ${CMAKE_SOURCE_DIR}/src/evasion/decoy.c
    ${CMAKE_SOURCE_DIR}/src/evasion/spoof.c
    ${CMAKE_SOURCE_DIR}/src/evasion/fragment.c
    ${CMAKE_SOURCE_DIR}/src/cli/cli_privilege.c
    ${CMAKE_SOURCE_DIR}/src/cli/help.c
    ${CMAKE_SOURCE_DIR}/src/subenum/dns_packet.c
    ${CMAKE_SOURCE_DIR}/src/subenum/result_store.c
    ${CMAKE_SOURCE_DIR}/src/subenum/wordlist.c
    ${CMAKE_SOURCE_DIR}/src/recon/context.c
    ${CMAKE_SOURCE_DIR}/src/recon/graph.c
    ${CMAKE_SOURCE_DIR}/src/recon/evidence.c
    ${CMAKE_SOURCE_DIR}/src/recon/query.c
    ${CMAKE_SOURCE_DIR}/src/recon/module.c
    ${CMAKE_SOURCE_DIR}/src/recon/output/sections.c
    ${CMAKE_SOURCE_DIR}/src/recon/port_table.c
    ${CMAKE_SOURCE_DIR}/src/npe/npe_registry.c
    ${CMAKE_SOURCE_DIR}/src/recon/output_registry.c
    ${CMAKE_SOURCE_DIR}/utils/utils.c)

target_include_directories(netpeek_tests PRIVATE ${NP_INCLUDE_DIRS})
target_link_libraries(netpeek_tests PRIVATE pthread OpenSSL::Crypto)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(netpeek_tests PRIVATE dl)
endif()
target_compile_definitions(netpeek_tests PRIVATE _DEFAULT_SOURCE _DARWIN_C_SOURCE)

add_test(NAME unit COMMAND netpeek_tests)
add_test(
    NAME cmake_version
    COMMAND /bin/sh ${CMAKE_SOURCE_DIR}/tests/test_cmake_version.sh)
add_test(
    NAME release_constcorrect
    COMMAND /bin/sh ${CMAKE_SOURCE_DIR}/tests/test_release_constcorrect.sh)
