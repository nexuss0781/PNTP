# PNTP V4 — Implementation Phases

## Phase Ordering Strategy

Phases are ordered by dependency: lower layers first, then protocol processing, then intelligence/stealth, then integration. Within each phase, **hardest-first** — implement the most critical/risky item first so failures surface early.

```
Phase 0:  Foundation & Scaffolding       (wk 1)
Phase 1:  Assembly Core Hardening         (wk 1-2)
Phase 2:  Raw Socket Maturity             (wk 2-3)
Phase 3:  TCP Engine                      (wk 3-5)
Phase 4:  DNS Resolver                    (wk 4-5, parallel with 3)
Phase 5:  TLS Interceptor Maturity        (wk 5-7)
Phase 6:  HTTP/2 Full Stack               (wk 6-8)
Phase 7:  HTTP/1.1 Parser                 (wk 7-8, parallel with 6)
Phase 8:  URL Manipulator                 (wk 8-9)
Phase 9:  Data Extractor                  (wk 9-10, parallel with 8)
Phase 10: Transcendence Engine            (wk 10-12)
Phase 11: Stealth Ensemble Realization    (wk 11-13, parallel with 10)
Phase 12: Performance Monitor Maturity    (wk 12-13, parallel with 11)
Phase 13: Connection Pool                 (wk 13-14)
Phase 14: Configuration & Logging         (wk 14, parallel with 13)
Phase 15: Integration & System Tests      (wk 15-16)
Phase 16: V5 Foundation                   (wk 16-17)
```

---

## Phase 0: Foundation & Scaffolding

**Goal:** Build system, directory structure, convention enforcement, and CI.

### Tasks
- [ ] Create CMakeLists.txt with ASM + CXX support
- [ ] Create CMakePresets.json (debug/release/perf/asan/size)
- [ ] Rename all files NNTP → PNTP (`nntp_core` → `pntp_core`, etc.)
- [ ] Create `src/` and `include/` directory layout
- [ ] Create `test/` directory with GoogleTest submodule
- [ ] Create `bench/` directory for benchmarks
- [ ] Create `.clang-format` and `.clang-tidy`
- [ ] Create `Dockerfile.test` with all dependencies
- [ ] Create helper namespaces: `pntp::net`, `pntp::asm`, `pntp::crypto`, etc.
- [ ] Migrate all `cout`/`cerr` to structured logging stub
- [ ] Create `pntp_version.h` with `PNTP_VERSION_MAJOR/MINOR/PATCH`
- [ ] Verify `cmake -B build -G Ninja && ninja -C build` produces a binary

**Files changed:** 20+ (every file needs namespace migration and path rename)

---

## Phase 1: Assembly Core Hardening

**Goal:** Production-quality assembly primitives with proper serialization, memory fencing, and entropy.

### Tasks
- [ ] Add `get_rdtsc_serialized` with `mfence; lfence; rdtsc` sequence
- [ ] Add `get_rdtscp` variant (RDTSCP for immediate processor ID)
- [ ] Add `mfence_acquire` / `mfence_release` memory barriers
- [ ] Add `cache_flush_line(VirtualAddress)` using `clflush`
- [ ] Add `avx2_copy_nt` — non-temporal aligned copy with `vmovntdqa`/`vmovntdq`
- [ ] Add `stealth_rand` — PRNG from RDTSC + CPUID entropy pool with RDRAND fallback
- [ ] Add entropy pool (256-byte, seeded at init from CPUID + RDRAND)
- [ ] Add `cpuid_string` — full CPUID leaf dumping (for hardware fingerprint)
- [ ] Add `pause_loop` — optimized spin-loop hint with PAUSE instruction
- [ ] Add `prefetch_range` — software prefetch for cache warming
- [ ] Verify with `objdump -d` and performance counters

**Files:** `pntp_core.asm`, `pntp_core.h`

---

## Phase 2: Raw Socket Maturity

**Goal:** Move from heap-allocated per-packet capture to zero-copy PACKET_MMAP ring buffer with BPF.

### Tasks
- [ ] Add `PACKET_MMAP` ring buffer allocation (huge pages preferred)
- [ ] Implement `acquirePacket()` — zero-copy from ring (kernel → user)
- [ ] Implement `releasePacket()` — return slot to kernel
- [ ] Add BPF program compilation and attachment (`setsockopt SO_ATTACH_FILTER`)
- [ ] Add `setPromiscuous()` via `PACKET_ADD_MEMBERSHIP`
- [ ] Add `setFanoutGroup()` for RSS across queues
- [ ] Add per-queue statistics (captured, dropped kernel, dropped ring, bytes)
- [ ] Add non-blocking mode with `O_NONBLOCK` or `PACKET_TIMEOUT`
- [ ] Add IP/TCP/UDP header parsing helpers on captured packets
- [ ] Verify 10 Gbps capture capability on test hardware

**Files:** `raw_socket_handler.h/.cpp`

---

## Phase 3: TCP Engine

**Goal:** Replace the hardcoded SYN-packet builder with a complete RFC 793 TCP state machine.

### Tasks
- [x] Implement `TCPState` enum and state transition table (RFC 793)
- [x] Implement `TCPConnection` struct with send/recv sequence space
- [x] Implement `open()` — full SYN → SYN-ACK → ACK handshake via raw socket
- [x] Implement `send()` — data segmentation, PSH flag, sequence tracking
- [x] Implement `recv()` — ACK processing, data reassembly, out-of-order queue
- [x] Implement `close()` — FIN exchange with TIME_WAIT handling
- [x] Implement TCP options: MSS, Window Scale, SACK Permitted, Timestamps (RFC 1323)
- [x] Implement RTT estimation: SRTT, RTTVAR, RTO calculation (RFC 6298)
- [x] Implement retransmission timer and fast retransmit (RFC 5681)
- [x] Implement CUBIC congestion control
- [x] Implement RST handling and connection abort
- [x] Add `TCPEngine::buildSegment()` packet builder (wraps PacketBuilder)
- [ ] Test against local nginx with `pntp-test-http1` container
- [ ] Test RTT estimation accuracy against ping

**Files:** `tcp_engine.h/.cpp` (renamed from `stealth_network_engine.h/.cpp`)

---

## Phase 4: DNS Resolver

**Goal:** Bypass system resolver with raw DNS + DoH capability.

**Status:** Complete (2026-07-07) — 47/47 tests passing, 0 failures

### Tasks
- [x] Implement raw UDP DNS query (single socket per query)
- [x] Parse DNS response: header, questions, answers, authority, additional
- [x] Support A and AAAA record types
- [x] Implement `DNSCache` with LRU eviction and TTL expiry
- [x] Implement DoH (DNS-over-HTTPS) via raw TLS + HTTP/1.1 CONNECT
- [x] Implement stub resolution order: cache → DoH → raw UDP → system fallback
- [ ] DNSSEC validation (optional, off by default — tracked in P0-003)
- [x] Test: `resolve("example.com")` returns correct IPs

**Files:** `dns_resolver.h/.cpp`

---

## Phase 5: TLS Interceptor Maturity

**Goal:** Full TLS 1.3 MITM with dynamic certificate generation, session resumption, and memory-safe key handling.

### Tasks
- [ ] Implement dynamic X.509 certificate generation per-domain (on-the-fly, cached)
- [ ] Implement full MITM proxy listener (listen_fd → accept → TLS handshake with client)
- [ ] Implement outbound TLS connection to real server
- [ ] Implement `pumpData()` — bidirectional decrypt/encrypt forwarding
- [ ] Implement TLS 1.3 handshake intercept (supported_versions, key_share, sig_algs)
- [ ] Implement session resumption (session ticket storage + PSK)
- [ ] Implement ALPN routing (h2, http/1.1 negotiation)
- [ ] Implement 0-RTT early data handling (with replay protection)
- [ ] Implement NSS key log for debugging (`SSLKEYLOGFILE`)
- [ ] Add memory-safe key clearing (`clearSensitiveData()`)
- [ ] Add constant-time comparison for sensitive operations
- [ ] Add OCSP response handling (optional, for complete MITM fidelity)
- [ ] Test: HTTPS fetch through MITM proxy, verify decrypted content matches direct

**Files:** `tls_interceptor.h/.cpp`

---

## Phase 6: HTTP/2 Full Stack

**Goal:** Complete HTTP/2 protocol implementation: HPACK, stream machine, flow control, priority.

### Tasks
- [ ] Implement HPACK decoder (RFC 7541): static table, dynamic table, Huffman coding
- [ ] Implement HPACK encoder (RFC 7541): index references, literal encoding, table updates
- [ ] Implement full stream state machine (IDLE → OPEN → CLOSED transitions)
- [ ] Implement HEADERS frame handler with END_STREAM, END_HEADERS, PADDED, PRIORITY flags
- [ ] Implement DATA frame handler with flow control
- [ ] Implement SETTINGS frame handler (local → remote sync)
- [ ] Implement WINDOW_UPDATE for connection + stream-level flow control
- [ ] Implement GOAWAY with graceful shutdown (last_stream_id, error code, debug data)
- [ ] Implement PING handler (ACK response)
- [ ] Implement PRIORITY frame handler (dependency tree, weight)
- [ ] Implement RST_STREAM handler
- [ ] Implement CONTINUATION frame reassembly
- [ ] Implement connection preface validation (PRI * HTTP/2.0)
- [ ] Implement request/response multiplexing (concurrent streams)
- [ ] Implement flow control autotuning (window size adaptation)
- [ ] Test: `h2load` with self-signed nginx, verify all frame types

**Files:** `http2_parser.h/.cpp`

---

## Phase 7: HTTP/1.1 Parser

**Goal:** RFC 7230-compliant HTTP/1.1 parser for fallback connections.

### Tasks
- [ ] Implement request line parser: `METHOD path HTTP/1.1\r\n`
- [ ] Implement response line parser: `HTTP/1.1 STATUS reason\r\n`
- [ ] Implement header parser (key: value, continuation, folding)
- [ ] Implement chunked transfer encoding decoder
- [ ] Implement Content-Length body reader
- [ ] Implement Connection: keep-alive vs close handling
- [ ] Implement Upgrade: h2c (HTTP/2 cleartext upgrade)
- [ ] Implement 100 Continue handling
- [ ] Implement request/response serialization
- [ ] Test: fetch via nginx, compare headers and body with curl

**Files:** `http1_parser.h/.cpp` (NEW)

---

## Phase 8: URL Manipulator

**Goal:** Full RFC 3986 URL parser with normalization, query mutation, and redirect tracing.

### Tasks
- [ ] Implement `ParsedURL::parse()` — RFC 3986 grammar (scheme, authority, path, query, fragment)
- [ ] Implement percent-encoding/decoding (encode reserved chars, decode %XX)
- [ ] Implement `normalize()` — lower case scheme/host, remove default port, dot-segments, empty query/fragment
- [ ] Implement `mutateQuery()` — SET, DELETE, RENAME, SIGN operations
- [ ] Implement `authInject()` — BEARER, BASIC, COOKIE, DIGEST header generation
- [ ] Implement redirect chain tracer (follow 3xx, max hops configurable)
- [ ] Implement `setAuthProvider()` for pluggable auth strategies
- [ ] Test: parse 1000 random URLs from HTTP Archive, verify correctness against curl

**Files:** `url_manipulator.h/.cpp`

---

## Phase 9: Data Extractor

**Goal:** Streaming SAX HTML parser + CSS selector engine + JSON streaming extractor.

### Tasks
- [ ] Implement SAX HTML tokenizer (tags, attributes, text, comments, CDATA, scripts)
- [ ] Implement token callback API for streaming processing
- [ ] Implement CSS selector parser (tag, id, class, attribute, descendant, child, nth-child)
- [ ] Implement selector match engine against SAX token stream
- [ ] Implement JSON streaming parser (STaR: Structural Token and Ranges)
- [ ] Implement JSON path matching (`$.data.course.title`)
- [ ] Implement `ExtractionPlan` — declarative extraction rules
- [ ] Implement regex-based heuristics engine (for pattern discovery)
- [ ] Implement content-type negotiation: HTML vs JSON vs XML vs raw text
- [ ] Test: extract known fields from Udacity HTML, verify 100% accuracy

**Files:** `data_extractor.h/.cpp`

---

## Phase 10: Transcendence Engine

**Goal:** Complete stack: URL → DNS → TCP → TLS → HTTP → Extract. No libcurl.

### Tasks
- [ ] Create `FetchConfig` struct with all fetch parameters
- [ ] Create `FetchResult` struct with timing/status/body/headers
- [ ] Implement native `transcendFetch()` — harness DNS + TCP + TLS + HTTP
- [ ] Implement authentication injection via URLManipulator
- [ ] Implement cookie jar (Set-Cookie parser + storage + injection)
- [ ] Implement redirect following (via URLManipulator chain trace)
- [ ] Implement HTTP/2 multiplexed `parallelFetch()`
- [ ] Create `TranscendencePlan` — combined extraction + stealth + rewrite rules
- [ ] Create `Session` struct for persistent connections (TCP + TLS + HTTP2 state)
- [ ] Implement `transcendWithPlan()` — full guided extraction
- [ ] Test: fetch udacity.com, extract course title, compare with reference

**Files:** `transcendence_engine.h/.cpp` (renamed from `backend_transcendence.h/.cpp`)

---

## Phase 11: Stealth Ensemble Realization

**Goal:** All stealth methods operate on real packets, verifiable on the wire.

### Tasks
- [ ] Implement `injectNoisePackets()` — craft random-size UDP/TCP packets to decoy IPs at configurable rate
- [ ] Implement `randomizeHopLimits()` — per-packet TTL jitter in [min_ttl, max_ttl]
- [ ] Implement `spoofTcpFingerprint()` — adjust TCP options to match target browser profile
- [ ] Create pre-built fingerprint profiles: Chrome 120, Firefox 121, Safari 17, Edge 120
- [ ] Implement `morphTrafficPattern()` — pad data segment to MTU or random boundary
- [ ] Implement `scheduleJitter()` — add timing jitter between packet sends (us resolution)
- [ ] Implement `enableTrafficPadding()` — pad HTTP/2 DATA frames to block sizes
- [ ] Create `NoiseProfile` struct for configurable noise generation
- [ ] Implement ensemble integration hook in `TranscendenceEngine`
- [ ] Test: capture traffic through ensemble, verify against browser baseline with p0f

**Files:** `stealth_ensemble.h/.cpp`

---

## Phase 12: Performance Monitor Maturity

**Goal:** RDTSC-based, lockless, packet-granularity monitoring with heatmaps.

### Tasks
- [ ] Implement `CPUTimer::calibrate()` — measure TSC frequency at startup
- [ ] Replace all `high_resolution_clock` calls with `CPUTimer::now()`
- [ ] Implement lockless `EventRing` (SPSC, wait-free push/pop)
- [ ] Implement `recordPacketEvent()` direction + size + timing
- [ ] Implement packet loss detection at single-packet granularity
- [ ] Implement `PacketStats` with rolling window for throughput/latency/jitter
- [ ] Implement latency `Heatmap` (configurable bucket ranges, atomic counters)
- [ ] Implement `LatencyHeatmap::dump()` — output as JSON for visualization
- [ ] Implement min/max/avg/p50/p95/p99 latency tracking
- [ ] Add instrumentation hooks to TCP engine for event recording
- [ ] Add instrumentation hooks to TLS interceptor for handshake timing
- [ ] Remove all `std::chrono` from hot paths
- [ ] Test: verify TSC calibration accuracy against clock_gettime(CLOCK_MONOTONIC)

**Files:** `performance_monitor.h/.cpp`

---

## Phase 13: Connection Pool

**Goal:** Reuse TCP/TLS sessions to eliminate connection setup overhead on repeated fetches.

### Tasks
- [ ] Implement `PooledConnection` — wraps TCPEngine::TCPConnection + TLS + HTTP state
- [ ] Implement `acquire()` — return idle connection or create new
- [ ] Implement `release()` — reset to idle state
- [ ] Implement `setMaxConnections()` and `setIdleTimeout()` with eviction
- [ ] Implement health checking (TCP keepalive probe)
- [ ] Implement `PoolStats` — active/idle/created/reused/wait_time
- [ ] Integrate with `TranscendenceEngine`
- [ ] Test: 100 requests to same host, verify all but first are pooled

**Files:** `connection_pool.h/.cpp` (NEW)

---

## Phase 14: Configuration & Logging

**Goal:** Zero-copy config parsing, asynchronous lockless logging.

### Tasks
- [ ] Implement `PNTPConfig` POD struct with all config fields
- [ ] Implement `PNTPConfig::fromFile()` — parse JSON5 config file
- [ ] Implement `PNTPConfig::fromEnv()` — override via environment variables
- [ ] Implement `log::setLevel()` and `log::addSink()`
- [ ] Implement console sink (stdout, colored)
- [ ] Implement file sink (rotating files)
- [ ] Implement ring buffer sink (lockless, for hot path)
- [ ] Implement log format: timestamp [level] module: message
- [ ] Add config initialization to `main()`
- [ ] Test: start with config file, verify all modules read their settings

**Files:** `config_engine.h/.cpp`, `log.h/.cpp`

---

## Phase 15: Integration & System Tests

**Goal:** Full pipeline tests from URL input to extracted output, measured against targets.

### Tasks
- [ ] Create integration test: `ParseURL → ResolveDNS → TCPConnect → TLSHandshake → HTTPRequest → ExtractContent → ValidateOutput`
- [ ] Create Docker Compose test environment: nginx (HTTP/1.1 + HTTP/2) + TLS server + DoH server
- [ ] Implement end-to-end test against known Udacity page (or snapshot)
- [ ] Implement stealth test: capture traffic, analyze with p0f/tshark
- [ ] Implement performance test: 10k requests, measure p50/p95/p99
- [ ] Implement regression tests for each module
- [ ] Implement ASan/UBSan test run
- [ ] Implement valgrind/drmemory for memory correctness
- [ ] Verify all "conceptual" / "placeholder" print statements are eliminated
- [ ] Verify zero libcurl dependency in final binary (`ldd` check)

**Files:** `test/`, `.github/workflows/ci.yml`

---

## Phase 16: V5 Foundation

**Goal:** Laying groundwork for Hardware-Bound Proof-of-Transcendence authentication.

### Tasks
- [ ] Design HBPoT challenge-response message format (binary, embeddable in TCP options)
- [ ] Implement fast hash primitive in assembly (BLAKE3 or SHA-256 with AVX2)
- [ ] Implement constant-time memory compare in assembly
- [ ] Design `AuthChallenge` and `AuthProof` structs
- [ ] Create `hardware_fingerprint.h/.cpp` — extract stable hardware ID
- [ ] Create `zkp_stubs.h/.cpp` — abstract ZKP interface (will implement in V5)
- [ ] Add CP_Challenge option to TCP SYN handler (experimental)
- [ ] Document V5 protocol spec in `PNTP_V5_AUTH_SPEC.md`
- [ ] Design distributed ensemble key exchange protocol

**Files:** `hardware_fingerprint.h/.cpp`, `zkp_engine.h/.cpp`, `pntp_v5_spec.md`

---

## Dependency Graph

```
Phase 0 ──► Phase 1 ──► Phase 2 ──► Phase 3 ──► Phase 5 ──► Phase 6 ──► Phase 10
               │            │            │                      │            │
               │            │            ▼                      ▼            │
               │            │         Phase 4 ◄────────── Phase 7           │
               │            │                                               │
               │            └───────────────────────────────────────────────┤
               │                                                            │
               ▼                                                            │
          Phase 8 ──► Phase 9 ──────────────────────────────────────────────┤
                                                                            │
Phase 11 ◄──────────────────────────────────────────────────────────────────┤
Phase 12 ◄──────────────────────────────────────────────────────────────────┤
Phase 13 ◄──────────────────────────────────────────────────────────────────┤
Phase 14 ◄──────────────────────────────────────────────────────────────────┤
                                                                            ▼
                                                                      Phase 15
                                                                          │
                                                                          ▼
                                                                      Phase 16
```

**Parallelizable groups:**
- Phase 4 (DNS) can start after Phase 3 TCP basics are stable
- Phase 7 (HTTP/1.1) can start after Phase 3 TCP is stable
- Phase 8 (URL) + Phase 9 (Data Extractor) can run in parallel after Phase 2
- Phase 11 (Stealth) + Phase 12 (Perf Monitor) can run in parallel after Phase 3
- Phase 13 (Conn Pool) depends on Phase 5 + Phase 6 but can share Phase 10 parallel window
- Phase 14 (Config/Log) can be done incrementally through all earlier phases

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| PACKET_MMAP kernel version differences | High | Feature detection at init, fallback to heap mode |
| TLS 1.3 MITM breaks with new cipher suites | Medium | Always negotiate to lowest common, CI tests with latest OpenSSL |
| HPACK implementation bugs under fuzzing | High | Fuzz from day 1 of Phase 6, strict validation |
| TCP engine doesn't handle all edge cases | Critical | Exhaustive state machine tests, packet-level validation |
| Stealth ensemble detectable by advanced IDS | Low | Continue evolving; V4 is baseline, V5 adds ML resistance |
| Build system complexity delays development | Medium | Use CMake presets, CI validates builds on 3 distributions |
