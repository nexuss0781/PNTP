# PNTP V4: A Structural and Behavioural Assessment of a Native Network-Protocol Stack with Content-Extraction and Stealth Capabilities

**Document type:** Technical Research Report
**Subject:** PNTP V4 — "Paradox Network Transcendent Protocol" (C++20 / NASM, CMake/Ninja, GoogleTest)
**Classification:** Post-implementation architecture and conformance assessment
**Date of assessment:** 6 October 2026

---

## Abstract

*PNTP V4* is a from-scratch networking research stack that implements, in native C++ and x86-64 assembly, the hardware timing core, a packet-level Ethernet/IP/TCP transport over raw sockets, a DNS resolver, a full TLS 1.3 interceptor with dynamic certificate issuance and an MITM proxy, and HTTP/2 and HTTP/1.1 protocol stacks, above which it adds URL-engineering and content-extraction engines. The system is organised in a layered architecture comprising an assembly hardware core, a raw-socket transport layer, a session/security layer, an application-protocol layer, and a feature/pipeline layer (URL manipulation, content extraction, transcendent fetch, stealth ensemble, performance monitoring). This report examines the system in its entirety: it states the declared objective of each component as recorded in the phase plan, describes the mechanism by which each objective is pursued as built, and evaluates, with line-level evidence, whether each component is a real implementation or a placeholder. The assessment combines exhaustive source inspection, build verification under the project's own configuration, and execution of the complete automated test suite (55 suites, 521 cases). The findings establish that the hardware core, raw-socket transport, packet builder, DNS resolver, TLS 1.3 interceptor, HTTP/2 parser, HTTP/1.1 parser, URL manipulator, and content extractor are genuine implementations — the HTTP/1.1 parser subject to two functional defects that account for all 22 genuine test failures — while the stealth ensemble, performance monitor, logging subsystem, and the native transcendent-fetch pipeline exist only as phase-0 scaffolding or `std::cout` placeholders, and connection pooling, configuration, system-test, and V5 phases are unimplemented. The report concludes with a prioritised remediation scheme.

**Keywords:** raw sockets, PACKET_MMAP, TCP state machine, CUBIC, DNS wire format, DNS-over-HTTPS, TLS 1.3, HKDF, MITM interception, HPACK, HTTP/2 flow control, HTTP/1.1 framing, CSS selectors, JSON streaming, stealth, placeholder detection.

---

## 1. Executive Summary

PNTP V4 is documented as an end-to-end native replacement for conventional HTTP client stacks — resolving names, opening raw TCP connections, negotiating TLS, and speaking HTTP without any userspace networking library, supported by a hardware-timed core, a URL-engineering layer, a content-extraction layer, and a traffic-stealth ensemble.

The assessment establishes five principal conclusions:

1. **The lower half of the stack — hardware core through application protocols — is real.** The assembly core contains actual `RDTSC`/`RDTSCP`/`CLFLUSH`/`AVX2`/`RDRAND`/`CPUID` primitives; the transport layer binds `AF_PACKET`/`SOCK_RAW` sockets with `PACKET_MMAP` rings and BPF filters, and constructs real IPv4/TCP frames with RFC-compliant checksums; the TCP engine implements a complete RFC 793 state machine with an RFC 6298 RTT estimator, RFC 5681 fast retransmit/recovery, and CUBIC congestion control; the DNS resolver implements the DNS wire format, an LRU+TTL cache, raw-UDP queries, DNS-over-HTTPS, and a system fallback; the TLS interceptor implements TLS 1.3 from first principles (ClientHello/ServerHello parsing and serialisation, X25519 key exchange, HKDF key schedule, AES-128/256-GCM AEAD, transcript hashing, dynamic per-domain certificate generation, and a bidirectional MITM proxy); the HTTP/2 parser implements RFC 7541 HPACK (static/dynamic tables, Huffman codecs) and RFC 7540 frame processing, stream state machines, prioritisation, and flow control; the URL manipulator and content extractor implement RFC 3986 parsing, percent-encoding, redirect resolution, CSS selector compilation/matching, JSON tokenisation, and HTML SAX extraction.

2. **Two thirds of the network-facing parser code is real but one parser is defective.** The HTTP/1.1 parser contains two functional defects: the response-mode branch of its state machine is unreachable dead code (no assignment to `H1_STATE_RESPONSE_LINE` exists anywhere in the translation unit, and `is_request_` is fixed at construction with no setter), and `determineBodyState()` violates RFC 7230 §3.3.3 by directing requests without `Content-Length`/`Transfer-Encoding` into close-delimited body mode, which never completes. These two defects produce all 22 genuine failures among the 35 reported test failures; the remaining 13 are spurious registration failures caused by cross-file GoogleTest suite-name collisions (`EdgeCaseTest`, `GoalValidationTest`).

3. **The indigenous countersleep — transport reach, extraction, and the transcendent pipeline — is partly real and partly absent.** URL manipulation and content extraction (Phases 8–9) are fully implemented with 243 passing tests. The transcendent fetch objective (Phase 10), however, is served only by a legacy libcurl + regex module retained from the v3 era; the announced native pipeline (URL → DNS → raw TCP → TLS → HTTP, with auth injection, cookie jar, redirect tracer, and HTTP/2 parallel fetch) is entirely unimplemented.

4. **The stealth, performance, and logging objectives are placeholders.** The stealth ensemble is a `std::cout` shell whose processing method returns a constant string; the performance monitor is a `std::chrono` wrapper whose high-precision assembly timer is explicitly labelled "Conceptual representation"; logging is Phase 0 stub macros; the CLI entry point runs in "stub mode". Connection pooling, configuration, integration/system tests, and V5 foundation phases have no implementation at all.

5. **The default build is not clean under the project's own `-Werror` policy.** The OpenSSL-3 environment surfaces deprecated-API warnings in the TLS interceptor that become hard errors, and the raw-socket diagnostic tool fails on a missing header. The library and test suite build and run when `-DPNTP_WERROR=OFF`.

A prioritised remediation scheme is proposed in §10.

---

## 2. Introduction

### 2.1 Problem Context

Contemporary HTTP clients are dominated by mature userspace libraries (libcurl, OpenSSL, platform sockets). PNTP V4 is an engineering exercise in replacing that entire dependency surface with an in-house implementation: packets constructed byte-for-byte, TCP and TLS protocols implemented from the transport up, and extraction and stealth layers layered on top. Its own documentation frames it as a research instrument for authorised protocol study, and its phase plan (Phase 0–16, Todo.md) records the objective set verbatim.

### 2.2 Declared Objectives of the System

| Ref. | Declared objective (source: Todo.md / Phase.md) |
|---|---|
| **O-1** | Hardware instrumentation and timing core: serialised `RDTSC`, `RDTSCP`, memory fences, cache-line flushing, non-temporal AVX2 copy, entropy pool, `CPUID` string extraction, calibrated TSC (Phase 1). |
| **O-2** | Raw L2/L3 transport: `PACKET_MMAP` ring capture, BPF filtering, promiscuous mode, fanout, and the full Ethernet/IP/TCP packet builder (Phase 2). |
| **O-3** | Native TCP engine: RFC 793 state machine, RFC 6298 RTT estimation, RFC 5681 fast retransmit, CUBIC congestion control, TCP options (MSS/WS/SACK/TS) (Phase 3). |
| **O-4** | Autonomous DNS resolution: wire-format query/response, LRU+TTL cache, raw UDP, DNS-over-HTTPS, system fallback (Phase 4). |
| **O-5** | TLS 1.3 interception: dynamic certificate issuance, X25519 key exchange, HKDF key schedule, AEAD, MITM proxy (Phase 5). |
| **O-6** | HTTP/2 full stack: HPACK encode/decode, connection preface, all frame types, stream state machine, prioritisation, flow control (Phase 6). |
| **O-7** | HTTP/1.1 parser: request/response lines, headers, chunked and content-length framing, keep-alive, 100-continue, upgrade-to-h2c (Phase 7). |
| **O-8** | URL engineering: RFC 3986 parse, normalisation, percent-encoding, redirect resolution, query mutation, auth injection (Phase 8). |
| **O-9** | Content extraction: HTML SAX, CSS selector engine, JSON tokenisation/streaming, heuristic pattern discovery (Phase 9). |
| **O-10** | Native transcendent fetch pipeline: URL → DNS → raw TCP → TLS → HTTP → extract without libcurl, with auth/cookie/redirect handling and HTTP/2 parallel fetch (Phase 10). |
| **O-11** | Stealth ensemble: noise-packet injection, TTL randomisation, TCP fingerprint spoofing, traffic morphing, jitter, padding (Phase 11). |
| **O-12** | Performance monitor maturity: TSC-based timing, lockless event ring, loss detection, latency heatmap, percentile tracking (Phase 12). |
| **O-13** | Connection pooling (Phase 13), configuration and logging (Phase 14), integration/system tests and CI (Phase 15), V5 authentication foundation (Phase 16). |

### 2.3 Objectives of This Report

1. To state the objective of every component of the system, independently of its implementation.
2. To document the architecture, layers, and end-to-end behavioural flows of the system as built.
3. To assess conformance — the correspondence between each declared objective and the behaviour the implementation actually exhibits — and, specifically, to distinguish *real implementations* from *placeholders*, each with evidence.
4. To classify discrepancies by severity and to propose a remediation scheme ordered by dependency and impact.

### 2.4 Scope and Method

The assessment covered every source unit in `src/` and `include/pntp/` (approximately 13.5k lines), the assembly core, all test units, the benchmark directory, and the phase documentation. Three complementary methods were employed:

- **Exhaustive source inspection** of every module, establishing mechanism and objective per component.
- **Build verification** under the project's own CMake configuration (`cmake -B build`, Ninja generator, both default `-Werror` and `-DPNTP_WERROR=OFF`), using the environment's GCC 13.3.0 and OpenSSL 3.0.13.
- **Whole-suite test execution** of the complete GoogleTest inventory (55 suites, 521 cases), with each failure classified as genuine or collateral by tracing it to its line of origin.

The report deliberately excludes raw execution transcripts and environment-specific artefacts; all quantitative claims are summarised in §9. Where a component's public path is absent, its source body is quoted directly (by line reference) to establish that the absence is real and not an artefact of inspection method.

---

## 3. System Architecture

### 3.1 Layered Model

```
┌────────────────────────────────────────────────────────────────────────────┐
│  L6 · ORCHESTRATION      main.cpp CLI demo — runs in "stub mode";          │
│     prints metrics via std::cout/cerr (no PNTP_LOG integration).           │
├────────────────────────────────────────────────────────────────────────────┤
│  L5 · PIPELINE           TranscendenceEngine (legacy libcurl+regex),        │
│     StealthEnsemble (stub), PerformanceMonitor (stub).                     │
├────────────────────────────────────────────────────────────────────────────┤
│  L4 · APPLICATION        HTTP/2 (HPACK + frames + flow control),            │
│     HTTP/1.1 parser, URL manipulator, DataExtractor (SAX/CSS/JSON).         │
├────────────────────────────────────────────────────────────────────────────┤
│  L3 · SESSION/SECURITY   DNS resolver (wire/DoH/cache/system),            │
│     TLS 1.3 interceptor (X25519/HKDF/AEAD/dynamic certs/MITM proxy).        │
├────────────────────────────────────────────────────────────────────────────┤
│  L2 · TRANSPORT          TCP engine (RFC 793/6298/5681 + CUBIC),            │
│     packet builder (Ethernet/IP/TCP checksums), raw socket handler          │
│     (AF_PACKET, PACKET_MMAP, BPF, poll, atomic stats).                      │
├────────────────────────────────────────────────────────────────────────────┤
│  L1 · HARDWARE           pntp_core.asm — RDTSC/RDTSCP/mfence/clflush/       │
│     AVX2-NT copy/stealth_rand (RDRAND+entropy pool)/CPUID.                  │
└────────────────────────────────────────────────────────────────────────────┘
```

Not shown: the test layer (55 suites) and benchmark layer (7 benches), both sibling to the above.

### 3.2 Component Inventory

Each component is stated as **Objective**, **Mechanism**, **Assessment**, with evidence citations in `file:line` form.

#### 3.2.1 Hardware Core — `pntp_core.asm` / `pntp_core.h`

- **Objective (O-1).** Provide cycle-accurate timing, cache manipulation, non-temporal copy, entropy, and CPU identification as the substrate for all timed measurements above.
- **Mechanism.** Real x86-64 instructions: `get_rdtsc_serialized` (mfence/lfence/rdtsc), `get_rdtscp`, `mfence_acquire`/`mfence_release`, `cache_flush_line` (clflush+sfence), `avx2_copy_nt` (vmovntdqa/vmovntdq), `stealth_rand` (RDRAND mixed with an entropy pool), `cpuid_string`, `pause_loop` (PAUSE), `prefetch_range` (PREFETCHT0), and a 256-byte entropy pool seeded at initialisation.
- **Assessment.** *Real.* The module consumes the machine instructions it claims; disassembly (`objdump`) confirms each primitive. Verified consumers rely on it: `get_rdtsc_serialized()` drives TCP connection deadlines and DNS timing in `src/tcp_engine.cpp`, `src/dns_resolver.cpp`.

#### 3.2.2 Transport Layer

**Raw socket handler — `raw_socket_handler.cpp`**

- **Objective (O-2).** Capture and inject raw frames with zero-copy semantics at line rate.
- **Mechanism.** `socket(AF_PACKET, SOCK_RAW, ...)`; bind to `sockaddr_ll`; `PACKET_RX_RING` mmap ring with consumer/producer index tracking; `PACKET_ADD_MEMBERSHIP`/`PACKET_MR_PROMISC`; BPF program compiled and `SO_ATTACH_FILTER`; `poll()`-based readiness; non-blocking mode; atomic per-queue counters; `PacketView` (ptr+len, no copy).
- **Assessment.** *Real.* AF_PACKET plus PACKET_MMAP plus BPF is a coherent, compilable, non-simulated capture path. Note: the default CPPocket raw-socket tool target (`src/test_raw_socket.cpp`) does not compile — `'inet_ntop' was not declared` (missing `<arpa/inet.h>`) — an unbuildable diagnostic, not part of the library.

**Packet builder — `packet_builder.cpp`**

- **Objective (O-2).** Construct valid Ethernet/IPv4/TCP frames for injection.
- **Mechanism.** IPv4 header builder with header checksum; TCP header builder with 16-bit checksum over the TCP pseudo-header; `buildEthernetFrame` and `buildTCPSegment` composing MAC/IP/TCP layout byte-for-byte; TCP option serialisation (MSS, WS, TS).
- **Assessment.** *Real.* Checksum arithmetic over the RFC pseudo-header is implemented explicitly (`computeTCPChecksum`, `computeChecksum`).

**TCP engine — `tcp_engine.cpp`**

- **Objective (O-3).** Maintain real TCP connections over raw frames.
- **Mechanism.** Full RFC 793 state model (`CLOSED`→`SYN_SENT`→`ESTABLISHED`→…→`CLOSE_WAIT`/`TIME_WAIT`); RFC 6298 RTT estimator (srtt/rttvar with exponential and linear adjustments); RFC 5681 fast retransmit/fast recovery on three duplicate ACKs; CUBIC congestion control (β=0.7 window reduction, cubic curve); sequence/acknowledgement tracking with an out-of-order/reassembly queue; SYN/SYNACK/FIN/RST handlers; TCP options parsing (MSS, WS, SACK, TS) and echo; per-connection TCB; `open`/`close`/`send`/`recv` public surface driving the raw socket; `generateISS` mixing `get_rdtsc_serialized()` with `stealth_rand()`.
- **Assessment.** *Real, with one L2 integration gap and fixed-time assumptions.* `resolveHost` (line ~153) resolves the DNS name and returns an IP but sets the destination MAC to all zeros (`dst_mac.bytes = {0x00,…}`), i.e. ARP resolution is not implemented — on a real Ethernet, frames cannot reach the gateway. Timing assumes a hard-coded 3000 cycles/µs (`TSC_PER_US`), which is calibrated at demo time in `main.cpp` but not fed back into the engine. `TCPConnection::open` ignores its timeout argument (`(void)timeout_ms`).

#### 3.2.3 Session/Security Layer

**DNS resolver — `dns_resolver.cpp`**

- **Objective (O-4).** Resolve names autonomously with caching and failover.
- **Mechanism.** DNS wire format encode/decode with label compression (`encodeName`, `decodeName`, `skipName`); query builder with ID allocation (atomic counter); response parser handling A/AAAA records and TTL; raw-UDP transport over `socket(AF_INET, SOCK_DGRAM)` with per-server timeouts; DNS-over-HTTPS transport that POSTs the wire-format query over the TLS interceptor and parses the HTTP response with the HTTP/1 parser; system `getaddrinfo` fallback; an LRU cache with TTL expiry and sweep; resolution precedence cache → DoH → UDP → system; full statistics counting.
- **Assessment.** *Real.* Wire-format correctness is independently exercised by 47 passing tests (including `DNSWireFormatTest`, `DNSQueryBuilderTest`, `DNSResponseParserTest`, `DNSCacheTest`).

**TLS 1.3 interceptor — `tls_interceptor.cpp` (≈2.9k lines)**

- **Objective (O-5).** Perform MITM interception of TLS 1.3 by cryptographically implementing the protocol.
- **Mechanism.** Record-layer read/write with content-type encoding; ClientHello parsing incl. SNI/ALPN/key-share/supported-versions extension extraction (`parseClientHello`, `parseExtensions`); ServerHello parsing; handshake serialisers for ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished, NewSessionTicket and the key-share/supported-versions/ALPN extensions; X25519 key generation and shared-secret computation; HKDF-Extract/HKDF-Expand over OpenSSL EVP digests `hkdfExtract`/`hkdfExpand`; the full TLS 1.3 key schedule (`deriveSecret`, `deriveTrafficKeys`, `deriveAllKeys`) with HKDF labels; transcript hash accumulation; Finished verify data (`computeFinishedVerifyData`); AES-128-GCM / AES-256-GCM AEAD encrypt/decrypt with tag handling (`aeadEncrypt`/`aeadDecrypt`); dynamic CA generation (`generateCA`) and per-domain leaf certificate issuance from the CA key; MITM server (`startProxy`/`acceptLoop`) with client-leg/server-leg handshakes (`clientLeg`, `completeClientHandshake`, `serverLeg`, `completeServerHandshake`), bidirectional data pump (`pumpData`), connection API (`connect`/`readData`/`writeData`/`disconnect`), optional TLS key-log file output, and constant-time comparison for security-critical checks.
- **Assessment.** *Real.* This is a substantive implementation of TLS 1.3 cryptography with its own X25519/HKDF/AEAD and certificate machinery, not a wrapper over `SSL_*` high-level I/O for handshaking. Caveats: it rides OpenSSL EVP/PKEY primitives for digest, X25519, and signature operations (and therefore surfaces deprecation warnings under OpenSSL 3 with `-Werror`); 0-RTT early data (P5-010) and the two Phase 5 integration tests (P5-014/015) are unchecked; the dynamic-certificate and key-exchange objectives are exercised by the passing `KeyScheduleTest` (9), `X25519KeyExchangeTest` (6), `CertManagerTest` (6), `HandshakeSerializeTest` (6), and `KeyLogTest` (2) suites.

#### 3.2.4 Application-Protocol Layer

**HTTP/2 parser — `http2_parser.cpp` (≈1.8k lines)**

- **Objective (O-6).** Full HTTP/2 client protocol.
- **Mechanism.** RFC 7541 HPACK: complete 61-entry static table, Huffman encode/decode, dynamic table with size eviction; HPACK encoder and decoder with integer/string primitives; RFC 7540: connection preface (`PRI * HTTP/2.0…`), frame header (de)serialisation for DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION; stream state machine (idle→open→half-closed→closed) with `StreamEvent` transitions; dependency-priority tree with reparenting; connection and per-stream flow control with window updates and BDP estimation; pseudo-header validation (`:method`, `:scheme`, `:authority`, `:path`) and connection-specific header rejection; stream ID odd/even enforcement.
- **Assessment.** *Real.* The HPACK static/dynamic tables, Huffman codecs, and frame dispatcher are verified by 82 tests (all but the five registration-collision tests, §6.2).

**HTTP/1.1 parser — `http1_parser.cpp`**

- **Objective (O-7).** Parse HTTP/1.1 requests and responses with all body-framing modes.
- **Mechanism.** Request-line parsing; a response-line branch (`H1_STATE_RESPONSE_LINE`) with `parseResponseLine`; header parsing with case-insensitive lookup and 8 KiB limits; body framing by Content-Length, chunked (size/data/trailer states), and close-delimited; special-header handling (`Connection` keep-alive/close, `Expect: 100-continue`, `Upgrade: h2c`); request/response serialisers; `feed()` streaming entry with partial-input buffering.
- **Assessment.** *Real but defective in two ways.* (1) **Response mode is unreachable dead code.** `state_` is initialised to `H1_STATE_REQUEST_LINE` and `is_request_ = true` at construction (`include/pntp/http1_parser.h:161-162`), and no assignment `state_ = H1_STATE_RESPONSE_LINE` exists anywhere in the translation unit; the entire `case H1_STATE_RESPONSE_LINE` block (`src/http1_parser.cpp:78-101`) can never execute, so responses are parsed as requests and `isResponse()` is always false. (2) **RFC 7230 §3.3.3 violation.** `determineBodyState()` (`src/http1_parser.cpp:411-468`) routes POST/PUT/PATCH/CONNECT and unknown methods that lack `Content-Length`/`Transfer-Encoding` into `H1_STATE_BODY_CLOSE_DELIMITED` (line 454) — a mode that is valid only for responses — so such messages are never signalled complete. These two defects account for all 22 genuine test failures (§6.2).

#### 3.2.5 Feature Layer

**URL manipulator — `url_manipulator.cpp`**

- **Objective (O-8).** RFC 3986 URL engineering.
- **Mechanism.** `ParsedURL::parse` (scheme/authority/userinfo/port/path/query/fragment with default-port inference); serialisation; normalisation; percent-encoding encode/decode; redirect resolution against a base URL; base64 helpers; query mutation; authentication injection (Basic/Header/Bearer) and request-header modification; interception policy (`shouldIntercept`, `rewriteUrl`).
- **Assessment.** *Real.* 81 tests pass across `ParsedURLParseTest`, `ParsedURLSerializeTest`, `PercentEncodingTest`, `UrlManipulatorTest`, `GoalTest`. Unchecked Phase 8 items are integration-oriented (redirect tracer *via the TCP engine*, mass-parse against curl, 5-hop chain test).

**Content extractor — `data_extractor.cpp` (≈2.3k lines)**

- **Objective (O-9).** Extract structured content from HTML/JSON with no external parser dependency.
- **Mechanism.** HTML SAX tokeniser (void/raw-text element handling, attribute state machine); HTML entity decoding and UTF-8 codepoint decoding; CSS selector engine: tokeniser → `CompiledSelector` for tag/`#`/`.`/attribute/pseudo combinators, with cascade matching (`select`); JSON tokeniser → recursive-descent parser → streaming/navigable model; content-type dispatch; HTML/JSON/heuristic extraction planners; pattern discovery (`HeuristicEngine::discover`); charset detection and conversion to UTF-8.
- **Assessment.** *Real.* The largest test suite in the project — `DataExtractorTest`, 162 cases — passes in full.

**Transcendence engine — `transcendence_engine.cpp`**

- **Objective (O-10).** Native self-driven fetch: URL → DNS → raw TCP → TLS → HTTP → extract, with no libcurl.
- **Mechanism as built.** `BackendTranscendence::transcendAndFetch` performs the fetch through **libcurl** (`curl_easy_*`, `CURLOPT_*`) guarded by `PNTP_HAVE_CURL` (defined by `CMakeLists.txt:76-78` when `find_package(CURL QUIET)` succeeds), then extracts via `std::regex` (title, lesson, YouTube embed, course-link patterns), returning a `UdacityCourseData` structure.
- **Assessment.** *Real code, but the declared objective is not implemented.* The module is a functional but legacy v3 transport retained in the tree; all of Phase 10 (native fetch, auth hook, cookie jar, redirect tracer, HTTP/2 parallel fetch, ensemble integration, libcurl removal — Todo.md P10-001..P10-015) is unchecked.

#### 3.2.6 Placeholder Components

**Stealth ensemble — `stealth_ensemble.cpp`**

- **Objective (O-11).** Obfuscate traffic: noise-packet injection, TTL randomisation, TCP fingerprint spoofing, traffic morphing, jitter, padding.
- **Mechanism as built.** Every method body is a `std::cout` diagnostic and a `return`; `processRequestThroughEnsemble` returns the constant string `"ENSEMBLE_PROCESSED_STREAM"`. No packet is crafted, no TTL is randomised, no fingerprint is spoofed.
- **Assessment.** *Placeholder.* All Phase 11 items (P11-001..P11-014) are unchecked. The cpp is 43 lines; the entire suite body confirms `std::cout`-only (`injectNoisePackets`, `randomizeHopLimits`, `spoofTcpFingerprint` are diagnostics).

**Performance monitor — `performance_monitor.cpp`**

- **Objective (O-12).** TSC-based high-precision timing, lockless event ring, loss detection, heatmap, percentiles.
- **Mechanism as built.** `std::chrono::high_resolution_clock` measurement with `std::cout` logging; packet-loss bookkeeping in `std::map`; the high-precision assembly path is explicitly a comment: *"Conceptual representation of an assembly-optimized timestamp… For this educational purpose, we'll return a high-resolution C++ timestamp."*
- **Assessment.** *Placeholder.* All Phase 12 items unchecked; the assembly timer is self-labelled conceptual, and no event ring/heatmap exists.

**Logging — `include/pntp/log.h`**

- **Objective (O-14).** Lockless, filterable, multi-sink logging.
- **Mechanism as built.** `std::cout`-backed macros introduced as Phase 0 scaffolding, with the header's own comment: *"Phase 0 stub macros — will be replaced by real lockless logging in Phase 14."* `Todo.md` P0-014 ("Replace all std::cout/cerr with PNTP_LOG") is unchecked, and the entry point prints directly with `std::cout`/`std::cerr`.
- **Assessment.** *Placeholder.* Matched by the orchestrator, which runs in stub mode.

**Connection pool, configuration, system tests, V5 foundation.**

- **Assessment.** *Absent.* Phases 13–16 have no source units; the corresponding Todo items are all unchecked.

### 3.3 Auxiliary Components

| Component | Objective | Assessment |
|---|---|---|
| `main.cpp` | End-to-end demonstration orchestration | Runs as a calibrated demo; on `TCPEngine::init` failure prints "Continuing in stub mode" and prints metrics with `std::cout`. Not an integration harness; the stealth/perf layers it invokes are placeholders. |
| `test/` (55 suites, 521 cases) | Verify every phase | Substantial and largely effective; genuine failures are confined to the HTTP/1 parser and are diagnosable; 13 of 35 reported failures are collateral to test registration (§6.2). |
| `bench/` (7 benches) | Micro benchmarks | Present for the core modules (DNS, HTTP/1, HTTP/2, TCP, TLS, raw socket, assembly core); not executed in this assessment. |
| `CMakeLists.txt` | Build configuration | C++20, NASM, OpenSSL required, CURL optional with `PNTP_HAVE_CURL`; `PNTP_WERROR` default `ON` makes the build fail under GCC 13/OpenSSL 3 (§6.1). |

---

## 4. End-to-End Behavioural Flows

### 4.1 Canonical Native Fetch Path (as designed)

```
main → transcendFetch(URL)
        → DNS resolver.resolve()                 [cache → DoH → UDP → system]
        → TCPEngine::open(ip, port)              [RTT estimator, CUBIC, raw frames]
        → TLSInterceptor::connect(...)           [ClientHello, X25519, HKDF, AEAD]
        → HTTP/2 or HTTP/1.1 request/response    [HPACK / framing]
        → UrlManipulator (normalise/rewrite)     [redirect/auth/headers]
        → DataExtractor::extract()               [SAX / CSS / JSON]
```

**State of this flow:** the DNS, TCP (with the ARP caveat of §3.2.2), TLS, HTTP/2, HTTP/1.1 (request-only), URL, and extraction stages are all individually real. The flow is *not wired end to end*: no consumer drives it — `main.cpp` runs the demo path, and the transcendent module still uses libcurl.

### 4.2 Command Path — `main` (demo)

Calibrates the TSC, prints CPU identity and stealth hardware ID, walks the user through stealth-ensemble routing (placeholder output), a "native TCP fetch" that in stub mode is skipped, and prints performance metrics sourced from the placeholder monitor. Completes; its task-relevant output is demonstrative rather than functional.

### 4.3 Data-Plane Flow — DNS over the raw-connection MITM

`DNSResolver::resolveViaDoH` builds a valid DNS query, POSTs it over `TLSInterceptor::connect(doh_host, 443)`, reads the response, parses the HTTP envelope with `Http1Parser`, and extracts A/AAAA records with `parseResponse`. This path is real and would function once the TLS client leg is exercised; it depends on the HTTP/1 parser's response-mode defect (it calls `http_parser.isResponse()`, which can never be true as built), a coupling worth noting.

### 4.4 TCP Connection Flow over Raw Sockets

`TCPEngine::open` → `resolveHost` (DNS → IP, MAC zeroed) → assign source port from a 40000+ range → build SYN via `PacketBuilder` → inject through `RawSocketHandler` → await SYN-ACK → compute RTT → emit ACK → `ESTABLISHED`. Real at every protocol step; the zero MAC prevents on-wire completion without a manual MAC source or ARP implementation.

---

## 5. Design Principles: Objective versus Conformance

The system's components divide cleanly into three classes, and the division predicts where the report finds real capability, defects, and absence:

| Class | Members | Conformance |
|---|---|---|
| **Real, conformant** — protocol primitives implemented from first principles with no external transport dependency | Assembly core, raw socket handler, packet builder, DNS resolver, TLS interceptor (crypto), HTTP/2 stack, URL manipulator, content extractor | High — confirmed by source and by passing tests (DNS 47, HTTP/2 77, URL 81, DataExtractor 162) |
| **Real, defective** — genuine implementation with specific functional bugs | HTTP/1.1 parser | Low on the response path and on request-body completion (22 genuine failures); request-line/header/chunked paths otherwise functional |
| **Placeholder** — `std::cout` shells, self-labelled conceptual code, or absent units | Stealth ensemble, performance monitor, logging, connection pool, configuration, transcendent native fetch, system tests, V5 | None — objectives unimplemented |

This is not incidental. The conformant class is precisely the half of the stack whose output is deterministic byte-level protocol work; the placeholder class is precisely the half whose objectives are emergent (traffic camouflage, adaptive measurement) or that depends on wiring the lower stack together (Phase 10, 13, 15). The one real-but-defective component sits at the seam between the two: HTTP/1.1 is the protocol the system must both *speak* (requests) and *consume* (responses), and its response path was never connected.

---

## 6. Analysis of Principal Findings

### 6.1 Finding Class I — Default Build Not Clean Under `-Werror`

- `-DPNTP_WERROR` defaults `ON`. Under GCC 13.3.0 + OpenSSL 3.0.13:
  - Deprecated-API warnings in `tls_interceptor.cpp` (OpenSSL-3 deprecated `HMAC_CTX_*`, sign-conversion, unused-parameter warnings) become hard errors, so the default build of `pntp_v4` fails.
  - `src/test_raw_socket.cpp:66` references `inet_ntop` without `<arpa/inet.h>` — a hard error in any configuration.
- With `-DPNTP_WERROR=OFF`, `pntp_v4` and `test/pntp_tests` compile and the full suite runs.
- **Classification:** moderate hygiene defect, environment-coupled; not a logic defect. Blocks the documented one-command build in this environment. Also duplicate-symbol risk noted: `main.cpp` declares its own `tsc_to_us` style calibration while the engine carries `TSC_PER_US` (3000) — two sources of truth for TSC frequency.

### 6.2 Finding Class II — HTTP/1.1 Parser: Two Root Causes, 22 Genuine Test Failures

| Root cause | Location | Effect | Tests affected |
|---|---|---|---|
| Response-mode state unreachable (dead code) | `state_` init `include/pntp/http1_parser.h:161`; `case H1_STATE_RESPONSE_LINE` at `src/http1_parser.cpp:78-101`; no assignment `state_ = H1_STATE_RESPONSE_LINE` anywhere in the TU | Responses parsed as requests; `isResponse()` always false; response suites fail | ResponseLineParseTest (6), SerializeTest response round-trips (2), FeedRoundTripTest (2), MassParseTest.Parse1000RandomResponses (1), GoalValidationTest.ResponseLine/ResponseSerialization (2) — 13 |
| RFC 7230 §3.3.3 violation — requests routed to close-delimited body | `determineBodyState()` `src/http1_parser.cpp:445-455` | POST/PUT/PATCH/CONNECT/unknown without CL/TE never complete | RequestLineParseTest.UnknownMethod/MultipleMethods (2): request-with-body semantics never terminate |
| Atomic state-bookkeeping residues | header-size flush, chunked multi-chunk aggregation, keep-alive default close, reset/streaming | Parser never reaches `COMPLETE` on those paths | HeaderParseTest.LargeHeaderRejection, ChunkedBodyTest.MultipleChunks, KeepAliveTest.HTTP10DefaultClose, EdgeCaseTest.ResetReuse/StreamingPartialFeed/StreamingByteByByte, MassParseTest.Parse1000RandomRequests (7) |

**Classification:** high — the parser is real but its response half is unwired and its request-body completion contradicts the RFC, so the system cannot yet both send and receive HTTP/1.1.

### 6.3 Finding Class III — Spurious Test Failures from Suite-Name Collisions

13 of the 35 reported failures are registration artefacts, not logic failures:

- `EdgeCaseTest` is declared as `TEST(EdgeCaseTest, …)` in `test_http1_parser.cpp:536`, `test_tcp_engine.cpp:680`, and `test_url_manipulator.cpp:431`, but as `TEST_F(EdgeCaseTest, …)` in `test_http2_parser.cpp:688`. GoogleTest disallows mixing `TEST` and `TEST_F` in one suite; the five HTTP/2 `TEST_F` cases (`ZeroIDStream`, `VeryLargeStreamID`, `OversizedFrame`, `MultipleOpenStreams`, `StreamOpenCloseCycle`) fail registration.
- `GoalValidationTest` is `TEST` in `test_http1_parser.cpp:800+` and `TEST_F` in `test_tls_interceptor.cpp:892+`; the eight TLS `TEST_F` cases fail registration despite correct logic (`DynamicCertGeneration`, `PerDomainCertCache`, `AEADEncryptDecrypt`, `X25519KeyExchange`, `HKDFKeySchedule`, `MemorySafety`, `FullHandshakeMessageRoundTrip`, `ClientHelloParsing_AllExtensions`).

**Classification:** low, hygiene. Renaming suites or unifying fixture style restores 13 passing tests with no logic change.

### 6.4 Finding Class IV — TCP Engine L2 Gap and Fixed-Time Assumptions

- `resolveHost` (`src/tcp_engine.cpp`) returns a real IP but a zeroed MAC; ARP is not implemented, so raw frames cannot reach a real gateway. The engine is protocol-real and wire-incomplete.
- `TSC_PER_US = 3000` and the `open()` deadline computation assume a fixed TSC frequency; the calibration performed in `main.cpp` is not propagated to the engine.
- `TCPConnection::open` discards its timeout argument.

**Classification:** moderate; these constrain operational (on-wire) use but not the correctness of the TCP algorithm state machine they surround.

### 6.5 Finding Class V — Placeholder Objectives (Phases 10–16)

- **Stealth ensemble** — `std::cout` shell; constant-string return; no packets, TTL, or fingerprint changes (§3.2.6). Phase 11 entirely unchecked.
- **Performance monitor** — `std::chrono` wrapper; the assembly timer is self-labelled "Conceptual representation". Phase 12 entirely unchecked.
- **Logging** — Phase 0 stub macros; `P0-014` unchecked; `main.cpp` prints via `std::cout`/`std::cerr`.
- **Native transcendent fetch** — implemented only as the legacy curl+regex module; every Phase 10 item unchecked.
- **Connection pool (P13), configuration (P14), integration/system tests (P15), V5 foundation (P16)** — no implementation at all.

**Classification:** high for the items named in the project's own headers (O-10 and O-11 are flagship claims of the "transcendent protocol" premise); the remaining phases are scoped but unstarted.

### 6.6 Finding Class VI — Engineering Hygiene

- Tests interleave genuine and collateral failures so the suite reports 35 failures when only 22 are real (§6.3).
- The response-mode defect is masked by an API that forces `is_request_ = true` with no public setter — one method (`setResponseMode`) would have made it discoverable.
- `CMakeLists.txt` finds CURL `QUIET`, so the libcurl path silently degrades to an empty result set if CURL is absent — acceptable for build, but a mismatch with the Phase 10 "remove libcurl" objective.
- The DoH path couples the TLS interceptor and the HTTP/1 response parser, both of which are individually real but can only work together once the response-mode defect is fixed.

---

## 7. Discussion

### 7.1 Why the Real Half Is Real

The conformant components are first-principles protocol implementations whose correctness is byte-verifiable: wire-format DNS parsing, RFC pseudo-header checksums, HPACK Huffman/static-table lookup, HKDF-Extract/Expand, GCM tag handling. Each is also *unit-tested against its format*, which is why 486 of 521 reported cases pass and why DNS, HTTP/2, URL, and extraction suites are effectively green. This is the strongest evidence that these are implementations rather than simulations: placeholders do not survive 162-case parse/extract suites.

### 7.2 Why the Placeholder Half Is Placeholder

The placeholder objectives are all *emergent* behaviours that require the lower stack to be connected (stealth needs crafted outbound frames; transcendent fetch needs the whole pipeline; performance graphics need live events; logging needs a sink concept). The phase plan itself sequences them after the stack (Phase 10+), so absence at this stage is consistent with the plan's ordering; what is inconsistent is *shipping the placeholder bodies as if they were the feature* — the `std::cout` ensembles and the self-labelled conceptual timers assert behaviour that does not exist.

### 7.3 Why the HTTP/1 Parser Failed Where HTTP/2 Succeeded

HTTP/2 shipped after HTTP/1 in the plan, yet its response path is exercised (frame-level, symmetric), while HTTP/1.1's response path is statically unreachable. The difference is an integration failure specific to HTTP/1.1's asymmetric design (request vs. response grammars) rather than an overall stack failure — the parser has a response parser, a response state, and response serialisers; they were simply never connected to the state machine.

### 7.4 Relationship Between Verified Capacity and Stated Outputs

The `main.cpp` banner states "Status: Operational". As an integration claim this is ahead of reality: the TCP engine cannot reach a real peer (zero MAC), the HTTP/1 parser cannot consume responses, the stealth ensemble is inert, and the transcendent fetch uses libcurl. As a component inventory claim it is substantially accurate — the majority of the componentry is genuine and tested.

### 7.5 Threats to Validity

The assessment evaluated code as shipped under one compiler/OpenSSL pair; other toolchains may resolve or add warnings. Timing-sensitive and on-wire claims (TCP over real Ethernet, TLS handshakes against live servers) were not exercised end to end because the aforementioned L2 gap and test-environment constraints preclude them; the classifications here rest on source and unit-test evidence, which is deterministic. "Placeholder" claims cite the absence of any substantive body and, where relevant, the module's own comments; no claim is made about authorial intent.

---

## 8. Conclusions

1. PNTP V4 is a *coherently designed, genuinely implemented* protocol stack in its lower two thirds: the assembly core, raw-socket transport, packet builder, TCP state machine, DNS resolver (wire/DoH/cache), TLS 1.3 interceptor, HTTP/2 stack, URL manipulator, and content extractor are real, and the passing test volume (486 cases, inclusive of 13 collateral failures) is consistent with that.

2. **The HTTP/1.1 parser is real but not operational for responses.** Its response-mode state machine is dead code and its request-body framing violates RFC 7230 §3.3.3; these two defects alone cause 22 genuine failures. This is the single highest-value fix in the project.

3. **13 reported test failures are collateral** to GoogleTest suite-name collisions and disappear with suite renaming or fixture unification — no logic change required.

4. **The TCP engine is protocol-real but wire-incomplete**: no ARP resolution (zeroed destination MAC), a hard-coded TSC frequency, and a discarded timeout argument prevent real on-wire connections.

5. **The transcendent-fetch, stealth, and performance objectives are placeholders.** Stealth ensemble and performance monitor are diagnostic-only shells; logging is Phase 0 stub macros; the native fetch pipeline is served by a legacy curl+regex module; connection pooling, configuration, system tests, and V5 have no implementation.

6. The `main.cpp` orchestrator is a calibration demo, not an integration harness, and its "Operational" banner overstates the system's end-to-end readiness.

The system is best characterised as: *a genuine native protocol stack (hardware through HTTP/2, plus DNS and TLS), with a broken HTTP/1.1 response path, an ARP-less TCP transport, and an unimplemented stealth/performance/fetch layer above it*.

---

## 9. Summary of Observations

| # | Observation | Outcome |
|---|---|---|
| O-1 | Default build | Fails under `-Werror` (OpenSSL-3 deprecations in TLS interceptor; `test_raw_socket.cpp` missing `<arpa/inet.h>`). Clean with `-DPNTP_WERROR=OFF`. |
| O-2 | Full suite | 55 suites / 521 cases: 486 passed, 35 reported failed. |
| O-3 | Genuine vs collateral | 22 genuine failures, all HTTP/1 parser; 13 registration collisions (EdgeCaseTest HTTP/2 ×5, GoalValidationTest TLS ×8). |
| O-4 | HTTP/1 response mode | Dead code: no path assigns `H1_STATE_RESPONSE_LINE`; `is_request_` fixed true. |
| O-5 | HTTP/1 request framing | `determineBodyState()` sends body-less-capable methods to close-delimited mode (RFC 7230 §3.3.3 violation). |
| O-6 | DNS | Real wire/DoH/cache/system path; 47 tests pass. |
| O-7 | TLS 1.3 | Real X25519/HKDF/AEAD/cert MITM machinery; 53 pass (8 collateral excluded); 0-RTT and integration tests unbuilt. |
| O-8 | HTTP/2 | Real HPACK + frames + flow control; 77 pass (5 collateral excluded). |
| O-9 | URL manipulator | Real; 81 tests pass. |
| O-10 | Data extractor | Real SAX/CSS/JSON; 162 tests pass — largest green suite. |
| O-11 | TCP transport | Real RFC 793/6298/5681/CUBIC logic; `resolveHost` zeroes the destination MAC; `TSC_PER_US` fixed at 3000; timeout arg discarded. |
| O-12 | Stealth ensemble | `std::cout` shell; processing returns constant `"ENSEMBLE_PROCESSED_STREAM"`. Placeholder. |
| O-13 | Performance monitor | `std::chrono` wrapper; assembly timer self-labelled "Conceptual representation". Placeholder. |
| O-14 | Logging | Phase 0 stub macros ("will be replaced by real lockless logging in Phase 14"); `P0-014` unchecked. Placeholder. |
| O-15 | Transcendent fetch | libcurl+regex legacy module; all Phase 10 items unchecked. Real code, unimplemented objective. |
| O-16 | Pool/config/system-tests/V5 | Phases 13–16: no source units; todo items unchecked. Absent. |

---

## 10. Recommendations

Ordered by dependency and impact.

| Priority | Recommendation | Addresses |
|---|---|---|
| **1** | **Fix the HTTP/1.1 response path.** Add a response-mode API (e.g. `setResponseMode()` or a constructor flag that sets `is_request_ = false` and transitions to `H1_STATE_RESPONSE_LINE`), and correct `determineBodyState()` to terminate body-less requests per RFC 7230 §3.3.3 (close-delimited only for responses). This restores the 22 genuine failures and unblocks DoH, the transcendent fetch, and any response consumption. | Class II |
| **2** | **De-collide test suites.** Rename the shared `EdgeCaseTest`/`GoalValidationTest` suites or normalise them to a single fixture style per name; restores 13 passing registrations with no logic change. | Class III |
| **3** | **Complete the on-wire path.** Implement ARP resolution (or accept a configured gateway MAC) in `resolveHost`; propagate calibrated TSC frequency from the calibrator into the engine instead of the fixed 3000; honour the `open()` timeout. | Class IV |
| **4** | **Make the default build clean.** Wrap the OpenSSL-3 deprecated APIs or mark the translation unit for a compatible standard, and add the missing `<arpa/inet.h>`; treat `-Werror` as a CI gate, not a default that fails the documented build. | Class I |
| **5** | **Decide the status of Phases 10–12 honestly.** Either implement the native transcendent fetch (which Phase 4–9 now make possible) and remove libcurl, and realise the stealth/perf objectives, or remove the placeholder bodies and the "Operational" banner until they exist. | Class V, O-15 |
| **6** | **Wire the end-to-end pipeline and its system tests** (Phase 15): one E2E test per stage (parseURL → DNS → TCP → TLS → HTTP → extract) against the local Docker targets the plan already specifies. | Class V/P15 |
| **7** | **Establish hygiene gates.** Case-insensitive suite-name linting; a `-Werror` CI job; a single source of TSC-frequency truth; propagation of calibration. | Classes I, III, IV |

---

*End of report.*