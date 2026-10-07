# PNTP V4 — Agents Guide

## Build & Test
- **CMake configure**: `cmake -B build -DCMAKE_BUILD_TYPE=Debug -DPNTP_BUILD_TESTS=ON`
- **Build all**: `cmake --build build -j$(nproc)`
- **Build single target**: `cd build && make -j$(nproc) pntp_tests`
- **Run tests**: `./build/pntp_tests`
- **Fast compile + run** (single file changes):
  ```
  g++ -std=c++20 -O0 -I include -I build/_deps/googletest-src/googletest/include -c src/<file>.cpp -o /tmp/<file>.o
  g++ /tmp/<file>.o /tmp/test_<file>.o /tmp/pntp_core.o build/lib/libgtest.a build/lib/libgtest_main.a -lpthread -o /tmp/test_bin && /tmp/test_bin
  ```
- **NASM**: `/usr/bin/nasm -f elf64 -o /tmp/pntp_core.o src/pntp_core.asm`
- **GoogleTest headers**: `build/_deps/googletest-src/googletest/include`

## Project Conventions
- C++20, no exceptions, return-code style
- No iostream in implementation files
- `std::string_view` for function parameters
- No regex, no external URL parsers, no high-level libraries — hand-written C++ only
- Assembly primitives from `src/pntp_core.asm` (e.g., `stealth_rand`)
- All public APIs in `include/pntp/` headers
- Tests in `test/` using GoogleTest

## Implementation Progress
- Phase 1-7: Completed (core, networking, HTTP, TLS, SOCKS5, proxy chaining, protocol detection)
- **Phase 8: URL Manipulator** — Completed (`include/pntp/url_manipulator.h`, `src/url_manipulator.cpp`, `test/test_url_manipulator.cpp`, 86 tests all passing)
- **Phase 9: Data Extractor** — Completed (`include/pntp/data_extractor.h`, `src/data_extractor.cpp`, `test/test_data_extractor.cpp`, 162 tests all passing)
- **Phase 10: Transcendence Engine** — Completed (`include/pntp/transcendence_engine.h`, `src/transcendence_engine.cpp`, `test/test_transcendence_engine.cpp`, 30 tests; 675 total passing, `ldd` curl-free). Native fetch stack: TCP → TLS 1.3 → HTTP/1.1/HTTP/2, cookie jar, auth injection, redirect follow, `parallelFetch()` multiplexing, plan-driven extraction.
- Phase 11-16: Not yet implemented (Stealth Ensemble, Performance Monitor, Connection Pool, Config/Logging, Integration Tests, V5 Foundation)

## Key Files
- `PNTP_V4_Design.md` — Full architecture specification
- `Phase.md` — 16-phase implementation plan
- `Todo.md` — Atomic task tracking
- `plan/phase_9_data_extractor.md` — Phase 9 Data Extractor full plan
