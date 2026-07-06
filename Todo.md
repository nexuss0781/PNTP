# PNTP V4 — Atomic Todo List

> Each entry is a single, verifiable, completable unit of work.
> Format: `[ ] PHASE-NNN: Description (est. hours)`

---

## Phase 0 — Foundation & Scaffolding

```
[ ] P0-001: Create CMakeLists.txt with C++20, ASM, and OpenSSL/CURL find_package (2h)
[ ] P0-002: Create CMakePresets.json: debug, release, perf, asan, size (1h)
[ ] P0-003: Rename nntp_core.h → pntp_core.h, update include guards and all includes (0.5h)
[ ] P0-004: Rename nntp_core.asm → pntp_core.asm, update global symbols (0.5h)
[ ] P0-005: Rename stealth_network_engine.h/.cpp → tcp_engine.h/.cpp (0.5h)
[ ] P0-006: Rename backend_transcendence.h/.cpp → transcendence_engine.h/.cpp (0.5h)
[ ] P0-007: Move all .h to include/pntp/ and .cpp to src/ (1h)
[ ] P0-008: Create test/ directory with GoogleTest submodule registration (1h)
[ ] P0-009: Create bench/ directory with Google Benchmark registration (1h)
[ ] P0-010: Create .clang-format (Google style, 100 cols, sorted includes) (0.5h)
[ ] P0-011: Create .clang-tidy with modernize and performance checks (0.5h)
[ ] P0-012: Create Dockerfile.test with g++, cmake, ninja, openssl, libpcap, ninja (1h)
[ ] P0-013: Create pntp_version.h with PNTP_VERSION_MAJOR=4 MINOR=0 PATCH=0 (0.25h)
[ ] P0-014: Replace all std::cout/cerr with PNTP_LOG macro (stub to cout for now) (2h)
[ ] P0-015: Verify cmake -B build -G Ninja && ninja -C build/pntp_v4 compiles (0.5h)
```

**Total:** 11.75h

---

## Phase 1 — Assembly Core Hardening

```
[x] P1-001: Add get_rdtsc_serialized: mfence; lfence; rdtsc; shl; or; ret (0.5h)
[x] P1-002: Add get_rdtscp: rdtscp; mov [rdi], eax; mov [rdi+4], edx; ret (0.5h)
[x] P1-003: Add mfence_acquire and mfence_release wrapper functions (0.25h)
[x] P1-004: Add cache_flush_line(addr): clflush [rdi]; sfence; ret (0.25h)
[x] P1-005: Add avx2_copy_nt(dst, src, len): vmovntdqa + vmovntdq + sfence (1h)
[x] P1-006: Add stealth_rand(): mix RDTSC + CPUID entropy + RDRAND fallback (1h)
[x] P1-007: Add 256-byte entropy pool in .data section, seeded at init (1h)
[x] P1-008: Add cpuid_string(leaf, buffer): dump full CPUID leaf to buffer (0.5h)
[x] P1-009: Add pause_loop(count): spin-loop with PAUSE instruction (0.25h)
[x] P1-010: Add prefetch_range(addr, len): software prefetch with PREFETCHT0 (0.5h)
[x] P1-011: Update pntp_core.h extern "C" declarations for all new functions (0.5h)
[x] P1-012: Verify with objdump -d | grep -E 'rdtsc|cpuid|clflush|vmov' (0.25h)
[x] P1-013: Write unit test: verify get_rdtsc_serialized returns increasing values (0.5h)
[x] P1-014: Write unit test: verify cache_flush_line doesn't crash (0.25h)
[x] P1-015: Calibrate TSC frequency via sleep(1) delta and print at startup (1h)
```

**Total:** 8.25h

---

## Phase 2 — Raw Socket Maturity

```
[x] P2-001: Add PACKET_MMAP ring allocation: setsockopt PACKET_RX_RING + mmap (3h)
[x] P2-002: Implement acquirePacket(): check consumer_idx != producer_idx, return frame (1h)
[x] P2-003: Implement releasePacket(): advance consumer_idx, set tp_status = 0 (0.5h)
[x] P2-004: Add fallback to heap mode if PACKET_MMAP unsupported (1h)
[x] P2-005: Add BPF program compilation + SO_ATTACH_FILTER (1h)
[x] P2-006: Add setPromiscuous() via PACKET_ADD_MEMBERSHIP + PACKET_MR_PROMISC (0.5h)
[x] P2-007: Add setFanoutGroup() for RSS across multiple sockets (1h)
[x] P2-008: Add per-queue QueueStats struct with atomic counters (1h)
[x] P2-009: Add non-blocking mode via setsockopt SO_RCVTIMEO or O_NONBLOCK (0.5h)
[x] P2-010: Add PacketView struct with ptr+len (no copy) for captured packets (0.5h)
[x] P2-011: Add IP header parsing helper function (0.5h)
[x] P2-012: Add TCP/UDP header parsing helper function (0.5h)
[x] P2-013: Update injectPacket() to work with PacketView (0.5h)
[x] P2-014: Write unit test: capture 100 packets, verify non-zero length (with root SKIP) (1h)
[x] P2-015: Write unit test: verify BPF filters out non-TCP traffic (structural test) (1h)
[x] P2-016: Write benchmark: measure acquirePacket + releasePacket latency (0.5h)
[x] P2-017: Verify zero-copy: code review confirms no heap alloc in hot path (0.25h)
```

**Total:** 14h

---

## Phase 3 — TCP Engine

```
[x] P3-001: Implement TCPState enum: CLOSED, LISTEN, SYN_SENT... TIME_WAIT (0.25h)
[x] P3-002: Implement TCPConnection struct with all state fields (2h)
[x] P3-003: Implement open(): build SYN with MSS/WS/SACK/TS options, send via raw socket (3h)
[x] P3-004: Implement SYN-ACK receive: wait for SYN-ACK, validate seq/ack (1h)
[x] P3-005: Implement ACK send: finalize handshake, enter ESTABLISHED (0.5h)
[x] P3-006: Implement send(): segment data, set PSH, track snd_nxt (2h)
[x] P3-007: Implement recv(): process ACK, deliver data, track rcv_nxt (2h)
[x] P3-008: Implement out-of-order data queue using rb_tree or skiplist (2h)
[x] P3-009: Implement close(): FIN send + receive + TIME_WAIT timer (1.5h)
[x] P3-010: Implement RTT estimation: SRTT, RTTVAR, RTO (RFC 6298) (2h)
[x] P3-011: Implement retransmit timer: periodic check + resend oldest unacked (2h)
[x] P3-012: Implement fast retransmit: 3 duplicate ACKs trigger retransmit (1.5h)
[x] P3-013: Implement CUBIC congestion control: W_cubic calculation (3h)
[x] P3-014: Implement RST handling: abort connection on RST (0.5h)
[x] P3-015: Add TCP option builder helpers (MSS, WS, SACK, TS) (1h)
[x] P3-016: Add TCP checksum verification on receive (0.5h)
[x] P3-017: Integrate PacketBuilder for TCP segment construction (1h)
[x] P3-018: Write integration test: TCP connect to local nginx, verify handshake (2h)
[x] P3-019: Write integration test: send HTTP request, receive response (2h)
[x] P3-020: Write unit test: RTO doubles on timeout, resets on ACK (1h)
[x] P3-021: Write benchmark: TCP connection setup latency (100 iterations) (0.5h)
```

**Total:** 31.25h

---

## Phase 4 — DNS Resolver

```
[ ] P4-001: Implement raw UDP DNS query: build question section, sendto port 53 (2h)
[ ] P4-002: Implement DNS response parser: header/flags, questions, answers (2h)
[ ] P4-003: Support A (type 1) and AAAA (type 28) record extraction (0.5h)
[ ] P4-004: Implement DNSCache: LRU map with TTL expiry via background sweep (2h)
[ ] P4-005: Implement DoH resolver: raw TLS GET to application/dns-message (2h)
[ ] P4-006: Implement resolver order: cache → DoH → raw UDP → system fallback (1h)
[ ] P4-007: Add configurable DNS servers (default: Cloudflare 1.1.1.1 / 8.8.8.8) (0.5h)
[ ] P4-008: Write unit test: resolve("example.com") returns 93.184.216.34 (0.5h)
[ ] P4-009: Write unit test: cache hit returns cached entry, cache miss queries (0.5h)
[ ] P4-010: Write benchmark: DNS resolution time with cache hot vs cold (0.5h)
```

**Total:** 11.5h

---

## Phase 5 — TLS Interceptor Maturity

```
[ ] P5-001: Implement dynamic X.509 cert generation: generate RSA/ECDSA key + self-signed CA (3h)
[ ] P5-002: Implement per-domain cert cache: hash(domain) → X509* map (1h)
[ ] P5-003: Implement MITM listener: socket(), bind(), listen(), accept() loop (2h)
[ ] P5-004: Implement client TLS handshake: accept_client → SSL_new → SSL_accept (2h)
[ ] P5-005: Implement outbound TLS connect: TCP connect → SSL_new → SSL_connect (2h)
[ ] P5-006: Implement pumpData(): poll client+server, SSL_read → SSL_write bidir (3h)
[ ] P5-007: Implement TLS 1.3 handshake intercept: supported_versions, key_share, sig_algs (3h)
[ ] P5-008: Implement session resumption: store session tickets, attempt PSK on reconnect (2h)
[ ] P5-009: Implement ALPN routing: negotiate h2 or http/1.1, expose result (1h)
[ ] P5-010: Implement 0-RTT early data: queue early data, replay detection (2h)
[ ] P5-011: Implement NSS key log: write CLIENT_RANDOM + MASTER_SECRET to file (1h)
[ ] P5-012: Implement clearSensitiveData(): OPENSSL_cleanse on keys, stack variables (0.5h)
[ ] P5-013: Add constant-time comparison for sensitive data: CRYPTO_memcmp wrapper (0.5h)
[ ] P5-014: Write integration test: fetch through MITM, compare body with direct fetch (3h)
[ ] P5-015: Write integration test: TLS 1.3 only server, verify MITM works (2h)
[ ] P5-016: Write benchmark: TLS handshake MITM latency overhead (1h)
```

**Total:** 29h

---

## Phase 6 — HTTP/2 Full Stack

```
[ ] P6-001: Implement HPACK static table (61 entries per RFC 7541 Appendix A) (1h)
[ ] P6-002: Implement HPACK dynamic table: add/evict/lookup entries (2h)
[ ] P6-003: Implement HPACK Huffman decoder: lookup table → output bytes (3h)
[ ] P6-004: Implement HPACK Huffman encoder: byte → lookup code + bits (2h)
[ ] P6-005: Implement HPACK decode(): indexed, literal+indexing, table size update (3h)
[ ] P6-006: Implement HPACK encode(): index ref, literal, table management (2h)
[ ] P6-007: Implement stream state machine: IDLE/OPEN/HALF_CLOSED/CLOSED transitions (2h)
[ ] P6-008: Implement HEADERS frame handler: END_STREAM, END_HEADERS, PADDED, PRIORITY (2h)
[ ] P6-009: Implement DATA frame handler: flow control consumption, END_STREAM (1h)
[ ] P6-010: Implement SETTINGS handler: ACK, apply remote settings, send local (1.5h)
[ ] P6-011: Implement WINDOW_UPDATE: connection + stream window management (1.5h)
[ ] P6-012: Implement GOAWAY handler: last_stream_id, graceful drain (1h)
[ ] P6-013: Implement PING handler: respond with flags=ACK (0.5h)
[ ] P6-014: Implement PRIORITY handler: dependency tree with weight (2h)
[ ] P6-015: Implement RST_STREAM handler: close stream, notify error (0.5h)
[ ] P6-016: Implement CONTINUATION reassembly: accumulate header block fragments (1h)
[ ] P6-017: Implement connection preface validation: verify PRI * HTTP/2.0 (0.5h)
[ ] P6-018: Implement stream multiplexing: concurrent open stream limit (1.5h)
[ ] P6-019: Implement flow control autotuning: window update based on BDP estimate (2h)
[ ] P6-020: Implement request/response header validation (RFC 7540 Section 8) (1.5h)
[ ] P6-021: Write unit test: parse 1000 random frame sequences, verify round-trip (2h)
[ ] P6-022: Write unit test: HPACK encode/decode 100 random header sets (2h)
[ ] P6-023: Write integration test: full h2c request/response via nginx HTTP/2 (3h)
[ ] P6-024: Write fuzz test: libFuzzer harness for parseData with random bytes (2h)
[ ] P6-025: Write benchmark: frame parsing throughput in frames/second (1h)
```

**Total:** 40h

---

## Phase 7 — HTTP/1.1 Parser

```
[ ] P7-001: Implement request line parser: METHOD SP path SP HTTP/1.1 CRLF (1h)
[ ] P7-002: Implement response line parser: HTTP/1.1 SP status SP reason CRLF (1h)
[ ] P7-003: Implement header parser: key: value CRLF with folding/obs-fold (2h)
[ ] P7-004: Implement chunked transfer decoding: size CRLF data CRLF trailer (1.5h)
[ ] P7-005: Implement Content-Length reader: exactly N bytes (0.5h)
[ ] P7-006: Implement Connection: keep-alive vs close state tracking (0.5h)
[ ] P7-007: Implement Upgrade: h2c detection for HTTP/2 cleartext upgrade (0.5h)
[ ] P7-008: Implement 100 Continue: expect-continue → auto-send 100 (1h)
[ ] P7-009: Implement request serialization: Headers → wire format (0.5h)
[ ] P7-010: Implement response serialization (0.5h)
[ ] P7-011: Write unit test: parse 1000 random HTTP messages from corpus (1h)
[ ] P7-012: Write integration test: fetch via nginx, compare with curl (1h)
```

**Total:** 10.5h

---

## Phase 8 — URL Manipulator

```
[ ] P8-001: Implement ParsedURL::parse(): RFC 3986 grammar (3h)
[ ] P8-002: Implement percent-encoding: encode reserved, decode %XX (1h)
[ ] P8-003: Implement normalize(): lower scheme/host, remove default port, dot-segments (2h)
[ ] P8-004: Implement mutateQuery(): SET, DELETE, RENAME, SIGN operations (2h)
[ ] P8-005: Implement authInject(): BEARER, BASIC, COOKIE, DIGEST header generation (2h)
[ ] P8-006: Implement redirect chain tracer: follow 3xx via TCP engine (2h)
[ ] P8-007: Implement setAuthProvider(): pluggable auth strategy interface (1h)
[ ] P8-008: Write unit test: parse 1000 URLs from HTTP Archive, compare with curl --url-parse (1h)
[ ] P8-009: Write unit test: normalize equivalence (www.a.com/ == A:80/a) (0.5h)
[ ] P8-010: Write unit test: redirect chain with 5 hops (1h)
```

**Total:** 15.5h

---

## Phase 9 — Data Extractor

```
[ ] P9-001: Implement SAX HTML tokenizer: tag open/close, attrs, text, comment, script, CDATA (4h)
[ ] P9-002: Implement token callback API: std::function per token type (1h)
[ ] P9-003: Implement CSS selector tokenizer: tag, #id, .class, [attr], space, >, :nth (2h)
[ ] P9-004: Implement CSS selector match engine against SAX token stream (3h)
[ ] P9-005: Implement JSON streaming tokenizer: {, }, [, ], :, ,, strings, numbers (2h)
[ ] P9-006: Implement JSON path matcher: $.data.course.title pattern matching (2h)
[ ] P9-007: Implement ExtractionPlan: declarative rules → ExtractResult (2h)
[ ] P9-008: Implement regex heuristic engine: pattern discovery + confidence score (1h)
[ ] P9-009: Implement content-type dispatch: HTML vs JSON vs XML vs text (0.5h)
[ ] P9-010: Implement charset detection and conversion (iconv) (1h)
[ ] P9-011: Write unit test: extract 100 known fields from test HTML corpus (2h)
[ ] P9-012: Write unit test: CSS selector matching accuracy vs. Selenium reference (2h)
[ ] P9-013: Write benchmark: SAX parse throughput in MB/s (0.5h)
```

**Total:** 23h

---

## Phase 10 — Transcendence Engine

```
[ ] P10-001: Create FetchConfig struct: all fetch parameters (0.5h)
[ ] P10-002: Create FetchResult struct: body, headers, status, protocol, timing (0.5h)
[ ] P10-003: Implement transcendFetch(): URL → DNS → TCP → TLS → HTTP → body (3h)
[ ] P10-004: Implement auth injection hook: UrlManipulator headers → HTTP request (1h)
[ ] P10-005: Implement cookie jar: Set-Cookie parser, storage, Cookie header injection (2h)
[ ] P10-006: Implement redirect follow: URLManipulator tracer → new fetch (1h)
[ ] P10-007: Implement HTTP/2 parallelFetch(): multiplexed streams (2h)
[ ] P10-008: Create TranscendencePlan: extraction + stealth + rewrite combined (2h)
[ ] P10-009: Create Session struct: TCP + TLS + HTTP state per host (1h)
[ ] P10-010: Implement transcendWithPlan(): guided full pipeline (1h)
[ ] P10-011: Implement setEnsembleProfile(): integrate StealthEnsemble (0.5h)
[ ] P10-012: Remove libcurl dependency: replace last curl_easy calls (1h)
[ ] P10-013: Write integration test: fetch udacity.com, compare extracted title (2h)
[ ] P10-014: Write benchmark: parallelFetch() 10 URLs vs sequential baseline (1h)
[ ] P10-015: Verify ldd shows no libcurl dependency (0.25h)
```

**Total:** 18.75h

---

## Phase 11 — Stealth Ensemble Realization

```
[ ] P11-001: Implement injectNoisePackets(): craft random packets to decoy IPs at rate (3h)
[ ] P11-002: Implement randomizeHopLimits(): per-packet TTL in [min, max] range (1h)
[ ] P11-003: Implement spoofTcpFingerprint(): set TCP opts per browser profile (2h)
[ ] P11-004: Create Chrome 120 fingerprint profile (WS, MSS, TS, SACK, WS scale values) (1h)
[ ] P11-005: Create Firefox 121 fingerprint profile (1h)
[ ] P11-006: Create Safari 17 fingerprint profile (1h)
[ ] P11-007: Create Edge 120 fingerprint profile (0.5h)
[ ] P11-008: Implement morphTrafficPattern(): pad segments to MTU or random boundary (1.5h)
[ ] P11-009: Implement scheduleJitter(): delay between sends with us precision (1h)
[ ] P11-010: Implement enableTrafficPadding(): pad HTTP/2 DATA to block multiple (1h)
[ ] P11-011: Create NoiseProfile struct with configurable parameters (0.5h)
[ ] P11-012: Implement ensemble integration hook in TranscendenceEngine (0.5h)
[ ] P11-013: Write test: capture ensemble traffic, analyze with p0f (2h)
[ ] P11-014: Write benchmark: throughput overhead of ensemble vs direct (1h)
```

**Total:** 17h

---

## Phase 12 — Performance Monitor Maturity

```
[ ] P12-001: Implement CPUTimer::calibrate(): sleep(1) delta in TSC cycles (1h)
[ ] P12-002: Replace all std::chrono calls in hot path with CPUTimer::now() (1h)
[ ] P12-003: Implement lockless EventRing: SPSC, atomic head/tail, fixed size (2h)
[ ] P12-004: Implement recordPacketEvent(): push PacketEvent to ring (0.5h)
[ ] P12-005: Implement loss detection: track seq gaps in TCP recv path (1h)
[ ] P12-006: Implement PacketStats: rolling window for throughput/latency/jitter (2h)
[ ] P12-007: Implement latency Heatmap: 256 atomic buckets, configurable range (2h)
[ ] P12-008: Implement Heatmap::dump(): output JSON (0.5h)
[ ] P12-009: Implement percentile tracking: min, max, avg, p50, p95, p99 (1h)
[ ] P12-010: Add TCP event hooks: connect, send, recv, retransmit, close (1h)
[ ] P12-011: Add TLS event hooks: handshake_start, handshake_done, decrypt, encrypt (0.5h)
[ ] P12-012: Add HTTP event hooks: request_sent, response_start, body_done (0.5h)
[ ] P12-013: Write benchmark: EventRing push/pop throughput (100M ops) (0.5h)
[ ] P12-014: Write test: TSC calibration within 1% of clock_gettime (0.5h)
```

**Total:** 14h

---

## Phase 13 — Connection Pool

```
[ ] P13-001: Implement PooledConnection: wraps TCP + TLS + HTTP state (1h)
[ ] P13-002: Implement acquire(): find idle matching host:port or create (2h)
[ ] P13-003: Implement release(): reset state, return to idle pool (1h)
[ ] P13-004: Implement setMaxConnections() with LRU eviction (1h)
[ ] P13-005: Implement setIdleTimeout() with background eviction timer (1h)
[ ] P13-006: Implement TCP keepalive health check on idle connections (1h)
[ ] P13-007: Implement PoolStats: active/idle/created/reused/wait_time (0.5h)
[ ] P13-008: Integrate with TranscendenceEngine (0.5h)
[ ] P13-009: Write unit test: 100 requests to same host, verify all but first reuse (1h)
[ ] P13-010: Write benchmark: pooled vs non-pooled request latency (0.5h)
```

**Total:** 9.5h

---

## Phase 14 — Configuration & Logging

```
[ ] P14-001: Implement PNTPConfig POD struct with all network/stealth/tls/perf fields (1h)
[ ] P14-002: Implement PNTPConfig::fromFile(): JSON5 parser using nlohmann_json or similar (2h)
[ ] P14-003: Implement PNTPConfig::fromEnv(): PNTP_NETWORK_INTERFACE, etc. overrides (1h)
[ ] P14-004: Implement log::setLevel(): TRACE/DEBUG/INFO/WARN/ERROR/FATAL filtering (0.5h)
[ ] P14-005: Implement log::addSink(): abstract Sink interface (0.5h)
[ ] P14-006: Implement ConsoleSink: stdout, colored output per level (0.5h)
[ ] P14-007: Implement FileSink: rotating files, configurable max size (1h)
[ ] P14-008: Implement RingBufferSink: lockless, pre-allocated, for hot path (1h)
[ ] P14-009: Implement log format: "HH:MM:SS.sss [LEVEL] module: message\n" (0.5h)
[ ] P14-010: Replace PNTP_LOG macro with real logging calls throughout codebase (2h)
[ ] P14-011: Add config initialization to main() before engine startup (0.5h)
[ ] P14-012: Write unit test: config file round-trip (serialize → parse → compare) (0.5h)
[ ] P14-013: Write benchmark: RingBufferSink write throughput (10M messages) (0.5h)
```

**Total:** 11h

---

## Phase 15 — Integration & System Tests

```
[ ] P15-001: Create Docker Compose test environment: nginx (HTTP/1.1 + HTTP/2) + TLS (2h)
[ ] P15-002: Write E2E test: full pipeline parseURL → resolveDNS → connect → TLS → HTTP → extract (3h)
[ ] P15-003: Write E2E test: fetch snapshot of Udacity course page, extract title (2h)
[ ] P15-004: Write stealth detection test: tcpdump ensemble output, verify p0f misclassifies (2h)
[ ] P15-005: Write performance test: 10k requests, measure p50/p95/p99 latency (1h)
[ ] P15-006: Write ASan test run: detect leaks, buffer overflows (1h)
[ ] P15-007: Write UBSan test run: detect undefined behavior (1h)
[ ] P15-008: Write valgrind test run: memcheck on E2E pipeline (1h)
[ ] P15-009: Create GitHub CI workflow: build + lint + test + bench (2h)
[ ] P15-010: Scan for remaining "conceptual" or "placeholder" strings, eliminate all (1h)
[ ] P15-011: Run ldd on final binary, verify no unexpected dependencies (0.25h)
[ ] P15-012: Create test coverage report (gcov/lcov), target > 80% line coverage (2h)
```

**Total:** 18.25h

---

## Phase 16 — V5 Foundation

```
[ ] P16-001: Design HBPoT challenge-response binary message format (1h)
[ ] P16-002: Implement fast BLAKE3 hash in assembly with AVX2 (4h)
[ ] P16-003: Implement constant-time memcmp in assembly (0.5h)
[ ] P16-004: Design AuthChallenge struct: server_nonce, timestamp, target (0.5h)
[ ] P16-005: Design AuthProof struct: hardware_id, challenge_hash, signature (0.5h)
[ ] P16-006: Create hardware_fingerprint.h: extract CPUID, MAC, TSC jitter (1h)
[ ] P16-007: Create zkp_stubs.h: IZKPEngine virtual interface for V5 impl (0.5h)
[ ] P16-008: Add experimental CP_Challenge TCP option handler (SYN → embed challenge) (1h)
[ ] P16-009: Create PNTP_V5_AUTH_SPEC.md with full protocol specification (3h)
[ ] P16-010: Design distributed ensemble key exchange protocol outline (2h)
[ ] P16-011: Document V5 roadmap: what V4 enables that V5 will build on (1h)
```

**Total:** 15h

---

## Summary

| Phase | Hours | Files |
|-------|-------|-------|
| P0: Foundation | 11.75 | 20+ |
| P1: Assembly | 8.25 | 2 |
| P2: Raw Socket | 14.00 | 2 |
| P3: TCP Engine | 31.25 | 2 |
| P4: DNS Resolver | 11.50 | 2 |
| P5: TLS Interceptor | 29.00 | 2 |
| P6: HTTP/2 | 40.00 | 2 |
| P7: HTTP/1.1 | 10.50 | 2 |
| P8: URL Manipulator | 15.50 | 2 |
| P9: Data Extractor | 23.00 | 2 |
| P10: Transcendence Engine | 18.75 | 2 |
| P11: Stealth Ensemble | 17.00 | 2 |
| P12: Perf Monitor | 14.00 | 2 |
| P13: Connection Pool | 9.50 | 2 |
| P14: Config & Logging | 11.00 | 3 |
| P15: Integration Tests | 18.25 | 20+ |
| P16: V5 Foundation | 15.00 | 5 |
| **Total V4** | **298.25** | — |
| **Total V4 + V5Found** | **313.25** | — |

---

## Quick Reference: by Priority

### Must-Have (V4 Ship Criteria)
```
P0-001  CMakeLists.txt                 P3-003  TCP open() handshake
P0-015  Builds clean                   P3-006  TCP send()
P1-001  Serialized RDTSC               P3-007  TCP recv()
P2-001  PACKET_MMAP ring               P3-010  RTT estimation
P2-005  BPF filter                     P5-004  Client TLS handshake
P2-013  zero-copy path verified        P5-005  Outbound TLS connect
P3-002  TCPConnection struct           P5-006  pumpData() forwarding
```

### Should-Have
```
P2-006  Promiscuous mode               P8-001  URL parse RFC 3986
P3-011  Retransmit timer               P9-001  SAX HTML tokenizer
P4-001  Raw DNS                        P10-003 transcendFetch() native
P4-005  DoH resolver                   P11-001 injectNoisePackets()
P6-001  HPACK static table             P11-003 spoofTcpFingerprint()
P6-007  Stream state machine           P12-001 CPUTimer calibration
P6-011  WINDOW_UPDATE                  P12-003 Lockless EventRing
P7-001  HTTP/1.1 request parser        P14-001 PNTPConfig struct
```

### Nice-to-Have
```
P6-004  Huffman encoder                P11-008 Traffic morphing
P6-019  Flow control autotuning        P13-001 Connection pool
P9-004  CSS selector engine            P15-001 Docker Compose env
P9-006  JSON path matcher              P16-002 BLAKE3 AVX2 hash
P10-007 HTTP/2 parallelFetch()         P16-009 V5 auth spec
```
