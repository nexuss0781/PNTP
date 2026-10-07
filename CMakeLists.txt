cmake_minimum_required(VERSION 3.25)
project(pntp VERSION 4.0.0 LANGUAGES CXX ASM_NASM)

# ── C++ Standard ────────────────────────────────────────────────────
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── NASM Assembler ──────────────────────────────────────────────────
find_program(NASM nasm)
if(NOT NASM)
    message(FATAL_ERROR "NASM not found. Install nasm: sudo apt install nasm")
endif()
set(CMAKE_ASM_NASM_COMPILER ${NASM})
set(CMAKE_ASM_NASM_OBJECT_FORMAT elf64)
set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -wno-unknown-warning")

# ── Options ─────────────────────────────────────────────────────────
option(PNTP_BUILD_TESTS   "Build unit tests"   ON)
option(PNTP_BUILD_BENCH   "Build benchmarks"   OFF)
option(PNTP_ENABLE_ASAN   "Enable AddressSanitizer" OFF)
option(PNTP_ENABLE_UBSAN  "Enable UndefinedBehaviorSanitizer" OFF)
option(PNTP_WERROR        "Treat warnings as errors" ON)

# ── Sanitizers ──────────────────────────────────────────────────────
if(PNTP_ENABLE_ASAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=address")
endif()
if(PNTP_ENABLE_UBSAN)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fsanitize=undefined")
endif()

# ── Warnings ────────────────────────────────────────────────────────
set(PNTP_WARNING_FLAGS -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion)
if(PNTP_WERROR)
    list(APPEND PNTP_WARNING_FLAGS -Werror)
endif()

# ── Dependencies ────────────────────────────────────────────────────
find_package(OpenSSL REQUIRED)

# ── Include directories ─────────────────────────────────────────────
include_directories(${CMAKE_SOURCE_DIR}/include)

# ── Source files ────────────────────────────────────────────────────
set(PNTP_SOURCES
    src/pntp_core.asm
    src/raw_socket_handler.cpp
    src/packet_builder.cpp
    src/tcp_engine.cpp
    src/stealth_ensemble.cpp
    src/byte_stream.cpp
    src/tls_interceptor.cpp
    src/http1_parser.cpp
    src/http2_parser.cpp
    src/url_manipulator.cpp
    src/data_extractor.cpp
    src/transcendence_engine.cpp
    src/cookie_jar.cpp
    src/dns_resolver.cpp
    src/performance_monitor.cpp
    src/main.cpp
)

# ── Main executable ─────────────────────────────────────────────────
add_executable(pntp_v4 ${PNTP_SOURCES})

target_compile_options(pntp_v4 PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${PNTP_WARNING_FLAGS}>)

target_link_libraries(pntp_v4 PRIVATE
    OpenSSL::SSL
    OpenSSL::Crypto
)

# ── Raw socket test tool ───────────────────────────────────────────
add_executable(pntp_test_raw_socket
    src/pntp_core.asm
    src/raw_socket_handler.cpp
    src/test_raw_socket.cpp
)
target_compile_options(pntp_test_raw_socket PRIVATE $<$<COMPILE_LANGUAGE:CXX>:${PNTP_WARNING_FLAGS}>)
target_link_libraries(pntp_test_raw_socket PRIVATE)

# ── Tests ───────────────────────────────────────────────────────────
if(PNTP_BUILD_TESTS)
    add_subdirectory(test)
endif()

# ── Benchmarks ──────────────────────────────────────────────────────
if(PNTP_BUILD_BENCH)
    add_subdirectory(bench)
endif()

# ── Install ─────────────────────────────────────────────────────────
install(TARGETS pntp_v4 RUNTIME DESTINATION bin)
