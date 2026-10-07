# GoogleTest — try system-installed first, fall back to FetchContent
find_package(GTest QUIET)
if(NOT GTest_FOUND)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    set(GTEST_LIBRARIES gtest gtest_main)
    set(GTEST_INCLUDE_DIRS ${googletest_SOURCE_DIR}/include)
else()
    set(GTEST_LIBRARIES GTest::gtest GTest::gtest_main)
endif()

set(PNTP_TEST_SOURCES
    ${CMAKE_SOURCE_DIR}/src/pntp_core.asm
    ${CMAKE_SOURCE_DIR}/src/raw_socket_handler.cpp
    ${CMAKE_SOURCE_DIR}/src/packet_builder.cpp
    ${CMAKE_SOURCE_DIR}/src/tcp_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/stealth_ensemble.cpp
    ${CMAKE_SOURCE_DIR}/src/byte_stream.cpp
    ${CMAKE_SOURCE_DIR}/src/dns_resolver.cpp
    ${CMAKE_SOURCE_DIR}/src/tls_interceptor.cpp
    ${CMAKE_SOURCE_DIR}/src/http1_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/http2_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/url_manipulator.cpp
    ${CMAKE_SOURCE_DIR}/src/data_extractor.cpp
    ${CMAKE_SOURCE_DIR}/src/cookie_jar.cpp
    ${CMAKE_SOURCE_DIR}/src/transcendence_engine.cpp
    test_http1_parser.cpp
    test_dns_resolver.cpp
    test_tls_interceptor.cpp
    test_http2_parser.cpp
    test_url_manipulator.cpp
    test_data_extractor.cpp
    test_transcendence_engine.cpp
    test_packet_builder.cpp
    test_tcp_engine.cpp
)

add_executable(pntp_tests ${PNTP_TEST_SOURCES})
target_link_libraries(pntp_tests PRIVATE
    ${GTEST_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_include_directories(pntp_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${GTEST_INCLUDE_DIRS}
)

include(GoogleTest)
gtest_discover_tests(pntp_tests)

# ── Fuzzing harness (standalone, no libFuzzer required) ──────────
option(PNTP_BUILD_FUZZ "Build fuzzing harness" OFF)
if(PNTP_BUILD_FUZZ)
    add_executable(pntp_fuzz_http2
        ${CMAKE_SOURCE_DIR}/src/http2_parser.cpp
        fuzz_http2_parser.cpp
    )
    target_include_directories(pntp_fuzz_http2 PRIVATE ${CMAKE_SOURCE_DIR}/include)
    target_link_libraries(pntp_fuzz_http2 PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_options(pntp_fuzz_http2 PRIVATE -fsanitize=address,undefined -g -O1)
    target_link_options(pntp_fuzz_http2 PRIVATE -fsanitize=address,undefined)
endif()
