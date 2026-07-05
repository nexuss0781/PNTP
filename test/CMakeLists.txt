# GoogleTest
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

# Test executable
set(PNTP_TEST_SOURCES
    ${CMAKE_SOURCE_DIR}/src/pntp_core.asm
    ${CMAKE_SOURCE_DIR}/src/raw_socket_handler.cpp
    ${CMAKE_SOURCE_DIR}/src/tcp_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/stealth_ensemble.cpp
    ${CMAKE_SOURCE_DIR}/src/tls_interceptor.cpp
    ${CMAKE_SOURCE_DIR}/src/http2_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/url_manipulator.cpp
    ${CMAKE_SOURCE_DIR}/src/data_extractor.cpp
    ${CMAKE_SOURCE_DIR}/src/transcendence_engine.cpp
    ${CMAKE_SOURCE_DIR}/src/performance_monitor.cpp
    test_pntp_core.cpp
    test_raw_socket_handler.cpp
    test_tcp_engine.cpp
    test_http2_parser.cpp
    test_url_manipulator.cpp
    test_data_extractor.cpp
    test_performance_monitor.cpp
)

add_executable(pntp_tests ${PNTP_TEST_SOURCES})
target_link_libraries(pntp_tests PRIVATE
    gtest
    gtest_main
    OpenSSL::SSL
    OpenSSL::Crypto
)
target_include_directories(pntp_tests PRIVATE ${CMAKE_SOURCE_DIR}/include)

include(GoogleTest)
gtest_discover_tests(pntp_tests)
