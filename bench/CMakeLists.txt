include(FetchContent)
FetchContent_Declare(
    googlebenchmark
    URL https://github.com/google/benchmark/archive/refs/tags/v1.9.0.zip
)
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googlebenchmark)

add_executable(pntp_bench
    ${CMAKE_SOURCE_DIR}/src/pntp_core.asm
    ${CMAKE_SOURCE_DIR}/src/http2_parser.cpp
    ${CMAKE_SOURCE_DIR}/src/url_manipulator.cpp
    bench_pntp_core.cpp
    bench_http2_parser.cpp
)

target_link_libraries(pntp_bench PRIVATE benchmark::benchmark OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(pntp_bench PRIVATE ${CMAKE_SOURCE_DIR}/include)
