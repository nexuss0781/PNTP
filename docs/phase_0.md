# Phase 0: Foundation & Scaffolding

**Status:** In Progress  
**Description:** Build system, directory structure, convention enforcement, CI configuration, and all modules not yet implemented (placeholder/stub files for phases 4+).

---

## File Reference

| File | Target Phase | Purpose |
|------|-------------|---------|
| `CMakeLists.txt` | 0 | Top-level CMake build definition with ASM + CXX support |
| `CMakePresets.json` | 0 | CMake preset configurations (debug/release/perf/asan/size) |
| `.clang-format` | 0 | Clang formatting conventions |
| `.clang-tidy` | 0 | Clang-tidy linting configuration |
| `.gitignore` | 0 | Git ignore rules |
| `Dockerfile.test` | 0 | Docker test environment with all dependencies |
| `run.txt` | 0 | Build and run commands |
| `Phase.md` | 0 | Phase tracking document with all 16 phases |
| `PNTP_V4_Design.md` | 0 | PNTP V4 architecture design document (922 lines) |
| `NNTP_Architecture_Design.md` | 0 | NNTP architecture design (legacy) |
| `NNTP_Final_Report.md` | 0 | NNTP final report (legacy) |
| `Todo.md` | 0 | Project todo list |
| `include/pntp/pntp_version.h` | 0 | Version macros (MAJOR/MINOR/PATCH) |
| `include/pntp/log.h` | 14 | Structured logging stub (not yet implemented) |
| `include/pntp/tls_interceptor.h` | 5 | TLS 1.3 MITM interceptor (stub, not yet implemented) |
| `src/tls_interceptor.cpp` | 5 | TLS interceptor implementation (stub) |
| `include/pntp/http2_parser.h` | 6 | HTTP/2 full stack parser (stub) |
| `src/http2_parser.cpp` | 6 | HTTP/2 parser implementation (stub) |
| `bench/bench_http2_parser.cpp` | 6 | HTTP/2 parser benchmarks (stub) |
| `test/test_http2_parser.cpp` | 6 | HTTP/2 parser tests (stub) |
| `include/pntp/url_manipulator.h` | 8 | RFC 3986 URL parser with query mutation (stub) |
| `src/url_manipulator.cpp` | 8 | URL manipulator implementation (stub) |
| `test/test_url_manipulator.cpp` | 8 | URL manipulator tests (stub) |
| `include/pntp/data_extractor.h` | 9 | SAX HTML parser + CSS selector engine (stub) |
| `src/data_extractor.cpp` | 9 | Data extractor implementation (stub) |
| `test/test_data_extractor.cpp` | 9 | Data extractor tests (stub) |
| `include/pntp/transcendence_engine.h` | 10 | Native raw-socket fetch engine (stub) |
| `src/transcendence_engine.cpp` | 10 | Transcendence engine implementation (stub) |
| `include/pntp/stealth_ensemble.h` | 11 | Traffic obfuscation ensemble (stub) |
| `src/stealth_ensemble.cpp` | 11 | Stealth ensemble implementation (stub) |
| `include/pntp/performance_monitor.h` | 12 | RDTSC-based packet-granularity monitor (stub) |
| `src/performance_monitor.cpp` | 12 | Performance monitor implementation (stub) |
| `test/test_performance_monitor.cpp` | 12 | Performance monitor tests (stub) |

---

## Stub Module Details

The following modules exist as skeleton files (header declarations + .cpp stubs with placeholder implementations) and have NOT been implemented yet. They are tracked here under Phase 0 until their respective phase begins active development.

| Module | Target Phase | Key Dependencies | Current State |
|--------|-------------|------------------|---------------|
| TLS Interceptor | 5 | Phase 3 (TCP) | Stub — OpenSSL wrapper, no MITM logic |
| HTTP/2 Parser | 6 | Phase 5 (TLS) | Stub — frame types defined, no HPACK/stream machine |
| URL Manipulator | 8 | Phase 2 (Raw Socket) | Stub — URL rewrite, header mod, auth token |
| Data Extractor | 9 | Phase 8 (URL) | Stub — HTML/JSON extraction, video URL find |
| Transcendence Engine | 10 | Phase 3/5/6/8/9 | Stub — libcurl wrapper, no native fetch |
| Stealth Ensemble | 11 | Phase 10 | Stub — print-only placeholders |
| Performance Monitor | 12 | Phase 1 (TSC) | Stub — start/end timing, packet loss |
| Logging | 14 | Phase 0 | Stub — basic macros |

---

## Phase 0 Completed Tasks

- [x] CMakeLists.txt with ASM + CXX support
- [x] CMakePresets.json (debug/release/perf/asan/size)
- [x] Directory structure: `src/`, `include/`, `test/`, `bench/`, `docs/`
- [x] `.clang-format` and `.clang-tidy`
- [x] `Dockerfile.test` with all dependencies
- [x] `pntp_version.h` with `PNTP_VERSION_MAJOR/MINOR/PATCH`
- [x] `include/pntp/log.h` stub
- [x] All NNTP → PNTP renames complete
- [x] Phase tracking documentation (Phase.md, docs/phase_*.md)
