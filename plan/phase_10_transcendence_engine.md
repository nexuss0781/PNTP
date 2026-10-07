# Phase 10: Transcendence Engine — Full Plan

**Time estimate:** 24 hours | **Files:** `include/pntp/transcendence_engine.h`, `src/transcendence_engine.cpp`, `include/pntp/byte_stream.h`, `src/tls_interceptor.cpp`, `src/tcp_engine.cpp`, `include/pntp/cookie_jar.h`, `src/cookie_jar.cpp`, `test/test_transcendence_engine.cpp`, `bench/bench_transcendence_engine.cpp`, `CMakeLists.txt`, `test/CMakeLists.txt`, `bench/CMakeLists.txt`

---

## Current State

- `src/transcendence_engine.cpp` — 107 lines: libcurl wrapper (`curl_easy_*`, guarded by `PNTP_HAVE_CURL`) + `std::regex` extraction, returning a hardcoded `UdacityCourseData`.
- `CMakeLists.txt:43,76-79` — `find_package(CURL QUIET)` + `CURL::libcurl` link + `PNTP_HAVE_CURL` define (to remove).
- Blocking blocks already exist natively and are proven:
  - `TCPEngine` (`src/tcp_engine.cpp`) — raw-socket TCP (PACKET_MMAP/raw), `resolveHost` via native `DNSResolver` (`:153`), `open()` (`:164`), `send`/`recv`/`close`, and an existing plain-HTTP `transcendentFetch` (`:804`).
  - `TLSInterceptor` (`src/tls_interceptor.cpp`) — full TLS 1.3 client handshake in `connect()` (`:2307`), record layer `readRecord`/`writeRecord` (`:125`,`:151`), `readData`/`writeData` over a POSIX `fd`. Already used by DNS DoH (`dns_resolver.cpp:361`).
  - `Http1Parser` — `serializeRequest`/`feed`/`getResponse`; `Http2Parser` — `serializeHeaders`/`serializeSettings`/`serializeData` + callback dispatch.
  - `UrlManipulator` — `ParsedURL::parse`, `modifyRequestHeaders`, `injectAuth`, `resolveRedirect`.
  - `DataExtractor` — `ExtractionPlan` → `extract()`.
- **Design target** (`PNTP_V4_Design.md §3.9`): native fetch (no libcurl) with `FetchResult` (timing, packet/retransmit counts), `FetchConfig`, `parallelFetch` (HTTP/2 multiplexed), `Session` persistence, `TranscendencePlan`, `setEnsembleProfile`. Success criteria §10.2: fetch without libcurl; §10.8 single build.

---

## Architecture

```
                              ┌───────────────────────────────┐
                              │  BackendTranscendence         │
                              │  transcendFetch / parallelFetch│
                              └──────┬────────────────────────┘
                                     │ (per-host Session)
                    ┌────────────────┼──────────────────┐
                    ▼                ▼                  ▼
              ┌───────────┐   ┌──────────────┐  ┌──────────────┐
              │ TCPEngine │   │ TLSInterceptor│  │ Http1Parser /│
              │ (raw TCP) │──▶│  (raw stream) │  │ Http2Parser  │
              └─────┬─────┘   └──────┬───────┘  └──────────────┘
                    │                │
                    ▼                ▼
              ┌─────────────┐ ┌────────────┐
              │ DNSResolver │ │ByteStream  │  FdByteStream / RawTCPByteStream
              │ (native)    │ │ (transport)│
              └─────────────┘ └────────────┘
```

### Key Design Decisions

1. **TLS over raw TCP, not POSIX `fd`.** We honor the core pillar: *native stack from raw socket up*. TLS record I/O is transport-agnostic via a new `ByteStream` abstraction. MITM/DoH keep the `FdByteStream` (POSIX) path; the TranscendenceEngine uses `RawTCPByteStream` over `TCPEngine::TCPConnection*`. The TLS handshake code is shared by both transports — no duplication.
2. **`connect()` refactored into a shared handshake core.** `TLSInterceptor::connect()` gains a parameterized byte-stream path. `connectOverTCP()` reuses the identical handshake over `RawTCPByteStream`.
3. **Gateway MAC resolution.** `TCPEngine::open()` resolves the next-hop MAC via a hand-built ARP exchange (`/proc/net/route` default route + ARP request/reply over the existing `RawSocketHandler`), falling back to the existing direct-MAC / loopback behavior when no route exists.
4. **`CookieJar`** separate file (Set-Cookie parser, domain/path scoping, `Cookie` header injection) — testable offline.
5. **No exceptions, no regex, no iostream in Impl** — return codes/`bool` + shared `std::vector<uint8_t>` buffers (project conventions).
6. **Timing via `get_rdtsc_serialized`** for `tsc_cycles` and `std::chrono::steady_clock` for us fields; `packet_count`/`retransmit_count` read from `TCPConnection` send/retransmit queues.

---

## Tasks

### P10-001: `FetchConfig` struct (0.5h)
`include/pntp/transcendence_engine.h`: `FetchConfig` with `Headers headers`, `uint32_t timeout_ms`, `bool follow_redirects`, `uint32_t max_redirects`, `CachePolicy cache_policy`, `StealthProfile stealth_profile`. Also `CachePolicy` enum (`NONE`, `REUSE_IF_FRESH`), `StealthProfile` (`name`, `layers`), `URLRewriteRule` (`match`, `replace`), `Buffer = std::vector<uint8_t>`, `Headers` (ordered `std::vector<std::pair<std::string,std::string>>` with helpers).

### P10-002: `FetchResult` struct (0.5h)
`FetchResult`: `Buffer response_body; Headers response_headers; uint16_t status_code; std::string protocol;` nested `Timing{dns_us,connect_us,tls_us,ttfb_us,total_us,tsc_cycles}`; `uint32_t packet_count, retransmit_count; bool ok; std::string error;`.

### P10-003: `transcendFetch()` native pipeline (8h)
**New `include/pntp/byte_stream.h`** — abstract `ByteStream` (`read(void*,size,timeout_ms)`, `write`, `close`, `isOpen`), `FdByteStream` (POSIX, used by MITM/DoH), `RawTCPByteStream` (buffers `TCPEngine::recv` chunks into a stream to satisfy TLS record reads).

**TLS refactor (`src/tls_interceptor.cpp`)** — add byte-stream record overloads `readRecord(ByteStream&)`, `writeRecord(ByteStream&,...)`, `writeRecordVec(...)`; `TLSConnection` gains optional owned `ByteStream`; `readData`/`writeData` dispatch stream vs fd; new `connectOverTCP(TCPEngine&, host, port, timeout)` reusing the same handshake.

**TCP gateway MAC (`src/tcp_engine.cpp`)** — `resolveNextHopMAC(uint32_t dst_ip, MAC&)`: read default gateway from `/proc/net/route`; if same-subnet/direct or loopback use existing behavior; else hand-built ARP request/reply via `RawSocketHandler::injectPacket`/`acquirePacket`. Wire into `open()`.

**Pipeline in `src/transcendence_engine.cpp`** — `ParsedURL::parse` → `DNSResolver` → `TCPEngine::open` → `TLSInterceptor::connectOverTCP` (ALPN h2/http1.1) → `Http1Parser::serializeRequest` + `UrlManipulator` headers + CookieJar inject → `RawTCPByteStream` write → read loop over TLS records feeding `Http1Parser` → status/headers/body; measure `dns_us/connect_us/tls_us/ttfb_us/total_us/tsc_cycles`.

### P10-004: auth injection (1h)
`UrlManipulator::modifyRequestHeaders` + optional `injectAuth` wired into request building.

### P10-005: CookieJar (2h)
`include/pntp/cookie_jar.h`, `src/cookie_jar.cpp`: `CookieJar::setFromHeaders(url, headers)` parses `Set-Cookie`, domain/path/secure/HttpOnly; `injectCookieHeader(url, Headers&)`; per-host storage; unit tests offline.

### P10-006: redirect follow (1h)
In `transcendFetch`: on 3xx with `Location`, `UrlManipulator::resolveRedirect(original, location)`, carry cookies, loop up to `max_redirects`.

### P10-007: `parallelFetch()` HTTP/2 (3h)
Over one raw TLS session: send connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`) + `serializeSettings` + `serializeHeaders` per stream; read frames, dispatch via `Http2Parser` callbacks into per-`FetchResult`; collect all results.

### P10-008: `TranscendencePlan` (2h)
Struct with `extraction_plans`, `stealth_profiles`, `rewrite_rules`; `transcendWithPlan` runs `DataExtractor::extract`.

### P10-009/010/011: Session, plan, ensemble hook (2.5h)
`Session` = {`TCPConnection* tcp; TLSInterceptor::TLSConnection* tls; Http2Parser* h2; map cookies;`} + `createSession`/`destroySession`/`transcendWithPlan`/`setEnsembleProfile`.

### P10-012: remove libcurl (0.5h)
Delete CURL block + regex; remove `find_package(CURL)`, `CURL::libcurl`, `PNTP_HAVE_CURL` from `CMakeLists.txt`.

### P10-013: integration test (2h)
`test/test_transcendence_engine.cpp`: offline unit tests (cookie jar, redirect resolution, request serialization, plan/result structs, byte-stream buffer logic). Live fetch test gated like DNS tests (`GTEST_SKIP` unless root + `eth0` + network).

### P10-014: benchmark (1h)
`bench/bench_transcendence_engine.cpp`: `parallelFetch` of 10 URLs vs sequential baseline.

### P10-015: `ldd` verify (0.25h)
`ldd build/src/pntp_v4 | grep -i curl` empty.

---

## Test/CMake changes
- `test/CMakeLists.txt`: add `transcendence_engine.cpp`, `cookie_jar.cpp`, `tcp_engine.cpp`, `raw_socket_handler.cpp`, `packet_builder.cpp`, `stealth_ensemble.cpp`, `byte_stream.cpp` to `PNTP_TEST_SOURCES`; add `test_transcendence_engine.cpp`.
- `bench/CMakeLists.txt`: add `transcendence_engine.cpp`, `cookie_jar.cpp`, `byte_stream.cpp`, `bench_transcendence_engine.cpp`.

## Risks
- Raw external fetch needs gateway ARP (new, hand-built) — loopback fallback keeps tests deterministic.
- TLS-over-raw read semantics (block until N bytes, timeout) — handled by `RawTCPByteStream` buffering.
- Keep all 521 existing tests green; the TLS refactor is transport-only (no handshake/key changes).

## Acceptance
- `transcendFetch("http://<host>")` and `https://<host>` work via raw TCP + native TLS + native HTTP.
- No libcurl in build or `ldd`.
- All tests pass; live-fetch tests skip cleanly without root.