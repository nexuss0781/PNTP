# Paradox Network Transcendent Protocol (PNTP) — Version 4 Design

## 0. The Paradox Philosophy

PNTP V4 is the maturation of NNTP. The name **Paradox** reflects the core design tension:

> *Operate at the lowest layer (raw silicon/network) to transcend the highest layer (application/auth).*

A paradox resolved through architecture: by embedding application-level intelligence into network-level primitives, PNTP does not "bypass" layers — it **collapses** them. The protocol stack is not a hierarchy but a unified field where the hardware signature of a CPUID+RDTSC pair is semantically equivalent to an OAuth bearer token.

### Core Tenets

1. **Layer Collapse** — No software abstraction is sacred. Application logic (auth, session, content extraction) is compiled into network-level packet operations. The TCP SYN _is_ the login request. The TLS ClientHello _is_ the bearer token.
2. **Deterministic Performance** — Every operation has a known upper bound in TSC cycles. Allocations are zero after init. The only acceptable latency is the speed of light plus cache-miss penalty.
3. **Adversarial Default** — Every module assumes it is being observed, throttled, fingerprint-blocked, or actively MITM'd. Stealth is not a feature; it is the execution model.
4. **Proof-over-Protocol** — A network protocol's legitimacy is not granted by spec compliance but by proven capability to extract target data with zero loss and zero detection under adversarial conditions.
5. **Atomicity at Packet Level** — Each packet is an atomic unit of work. Either it advances the state machine or it is discarded. No partial operations. No half-open states.

---

## 1. V4 Goals

### Primary: Mature Every Stub Into Implementation

| Module | V3 State | V4 Target |
|--------|----------|-----------|
| `nntp_core.asm` | RDTSC + CPUID only | Full serialized timing suite, cache-control ops, AVX2 intrinsics hook |
| `raw_socket_handler` | Working but naive | Zero-copy ring buffer, BPF filters, NUMA-aware, multi-queue RSS |
| `stealth_network_engine` | Static IP, no real TCP | Full TCP state machine, dynamic source IP/port, TCP options, RTT measurement |
| `stealth_ensemble` | Print-only placeholders | Real noise injection, TTL randomizer, TCP timestamp spoofing, packet pacing |
| `tls_interceptor` | OpenSSL stub, no crypto | Working TLS 1.3 MITM, dynamic CA generation, Session resumption, ALPN routing |
| `http2_parser` | Frame parse only | Complete HPACK, stream state machine, flow control, priority tree, GOAWAY handling |
| `url_manipulator` | No-op rewrite | Full URL parser (RFC 3986), parameter mutation, normalization, redirect chain tracer |
| `data_extractor` | Regex-only | SAX-style streaming parser, CSS selector engine, AST-based extractor |
| `backend_transcendence` | libcurl wrapper | Native raw-socket fetch engine, no libcurl dependency |
| `performance_monitor` | chrono fallback | RDTSC-based, packet-granularity, heatmap generation, statistical engine |

### Secondary: Prepare for V5 Authentication Layer

V5 will introduce:
- **Zero-Knowledge Proof handshake** at TCP open
- **Hardware-bound session tokens** derived from CPUID + TSC + MAC
- **Distributed ensemble routing** across multiple egress nodes
- **Adversarial ML-resistant traffic shaping**

V4 must lay the socket-level, timing, and cryptographic groundwork.

### Quantitative Targets

| Metric | Target |
|--------|--------|
| Packet capture throughput | >10 Gbps on single core (AF_PACKET + PACKET_MMAP) |
| TCP connection setup | <100 µs (RTT-dependent, excluding wire) |
| TLS 1.3 handshake MITM | <1 ms added latency |
| HTTP/2 frame parsing | <50 ns per frame after prefetch |
| Memory allocation | Zero after initialization phase |
| Packet loss detection | Single-packet granularity within 1 µs |
| Stealth overhead | <1% bandwidth for obfuscation |
| Build time | <30 s from clean |

---

## 2. Architecture (V4)

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PNTP Core Runtime                            │
│  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────────┐  │
│  │ Assembly     │  │ Memory Pool  │  │ Configuration Engine     │  │
│  │ Primitives   │  │ (Huge Pages) │  │ (Zero-copy JSON5 → PODO) │  │
│  └──────┬───────┘  └──────┬───────┘  └─────────────┬─────────────┘  │
│         │                 │                         │                │
├─────────┼─────────────────┼─────────────────────────┼────────────────┤
│         ▼                 ▼                         ▼                │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  Network Acquisition Layer                     │  │
│  │  ┌─────────────────┐  ┌────────────────┐  ┌────────────────┐  │  │
│  │  │ PACKET_MMAP Ring │  │ BPF Compiler    │  │ Multi-queue    │  │  │
│  │  │ (lockless SPSC)  │  │ & Verifier     │  │ RSS Steering   │  │  │
│  │  └────────┬────────┘  └───────┬────────┘  └───────┬────────┘  │  │
│  └───────────┼────────────────────┼────────────────────┼────────────┘  │
│              ▼                    ▼                    ▼                │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  Protocol Processing Layer                     │  │
│  │  ┌─────────┐ ┌──────────┐ ┌─────────┐ ┌────────┐ ┌────────┐  │  │
│  │  │ TCP     │ │ TLS 1.3  │ │ HTTP/2  │ │ HTTP/1 │ │ WebSocket│  │  │
│  │  │ State   │ │ MITM     │ │ Full    │ │ Parser │ │ Parser  │  │  │
│  │  │ Machine │ │ Engine   │ │ Stack   │ │        │ │         │  │  │
│  │  └────┬────┘ └────┬─────┘ └────┬────┘ └────┬───┘ └────┬────┘  │  │
│  └───────┼────────────┼────────────┼───────────┼───────────┼───────┘  │
│          ▼            ▼            ▼           ▼           ▼         │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  Stealth & Obfuscation Layer                   │  │
│  │  ┌────────────┐ ┌──────────┐ ┌───────────┐ ┌───────────────┐ │  │
│  │  │ Noise      │ │ TCP      │ │ Traffic   │ │ Traffic       │ │  │
│  │  │ Injection  │ │ Morph     │ │ Padding   │ │ Timing        │ │  │
│  │  └────────────┘ └──────────┘ └───────────┘ └───────────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                    │                                │
├────────────────────────────────────┼────────────────────────────────┤
│                                    ▼                                │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                  Extraction & Intelligence Layer               │  │
│  │  ┌────────────┐ ┌────────────┐ ┌───────────┐ ┌──────────────┐ │  │
│  │  │ URL        │ │ URL Router │ │ Content   │ │ Performance  │ │  │
│  │  │ Manipulator│ │ & Resolver │ │ Extractor │ │ Analyzer     │ │  │
│  │  └────────────┘ └────────────┘ └───────────┘ └──────────────┘ │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                    │                                │
│                                    ▼                                │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                       Output Layer                             │  │
│  │  ┌────────────┐ ┌──────────┐ ┌────────┐ ┌──────────────────┐  │  │
│  │  │ Structured │ │ Metrics  │ │ Log    │ │ Callback/Event   │  │  │
│  │  │ Data Export│ │ Dashboard│ │ Stream │ │ Emitter          │  │  │
│  │  └────────────┘ └──────────┘ └────────┘ └──────────────────┘  │  │
│  └───────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 3. Module-by-Module V4 Specification

### 3.1 Assembly Core (`pntp_core.asm`)

**Current:** 2 functions — `get_rdtsc`, `generate_stealth_id`
**Weaknesses:** No serialization before RDTSC (CPUID after, not before), no LFENCE, no cache-control, no SIMD, no padding.

**V4 Implementation:**

```asm
; --- Serialized RDTSC (proper) ---
get_rdtsc_serialized:
    mfence          ; complete all prior memory ops
    lfence          ; serialize instruction stream
    rdtsc           ; low 32 → EAX, high 32 → EDX
    shl rdx, 32
    or  rax, rdx
    ret

; --- Memory fence variants ---
mfence_acquire:
    mfence
    ret

; --- Cache line flush (for zero-copy DMA sync) ---
cache_flush_line:
    ; rdi = virtual address
    clflush [rdi]
    sfence
    ret

; --- AVX2 memcpy (aligned, non-temporal) ---
avx2_copy_nt:
    ; rdi = dst, rsi = src, rdx = len
    ; requires 32-byte alignment
    vmovntdqa ymm0, [rsi]
    vmovntdq  [rdi], ymm0
    sfence
    ret

; --- Pseudo-RNG from RDTSC + CPUID entropy pool ---
stealth_rand:
    rdtsc
    movzx ecx, al
    ; reseed from entropy pool
    lea rsi, [entropy_pool]
    add rsi, rcx
    rdrand rax         ; hardware RNG fallback
    ret

; --- Entropy pool (256 bytes, seeded from CPUID/RDRAND) ---
section .data
entropy_pool: times 256 db 0
```

### 3.2 Raw Socket Handler (`raw_socket_handler.h/.cpp`)

**Current:** Single socket, heap-alloc buffer, blocking, no filter.
**V4 Target:** `PACKET_MMAP` ring buffer, BPF, RSS, NUMA-aware, lockless.

```cpp
// Key additions:
struct PACKET_MMAP_Ring {
    struct tpacket2_hdr* blocks;     // mapped shared memory
    uint32_t block_num;
    uint32_t frame_size;
    atomic<uint32_t> producer_idx;   // kernel side
    atomic<uint32_t> consumer_idx;   // user side
};

class RawSocketHandler {
    bool init(const std::string& interface, int numa_node);
    bool attachBPF(const std::string& bpf_program);
    bool setPromiscuous(bool enable);
    bool setFanoutGroup(uint16_t group_id, PACKET_FANOUT type);
    bool setRingSize(uint32_t block_num, uint32_t frame_size);
    CapturedPacket* acquirePacket();  // zero-copy from ring
    void releasePacket(CapturedPacket* pkt);
    bool injectPacket(const PacketView& pkt, bool async = false);
    
    // Per-queue statistics
    struct QueueStats {
        uint64_t packets_captured;
        uint64_t packets_dropped_kernel;
        uint64_t packets_dropped_ring;
        uint64_t bytes_captured;
    };
    QueueStats getQueueStats(int queue_id);
};
```

### 3.3 TCP State Machine (`tcp_state_machine.h/.cpp`) — NEW

**Current:** None. `stealth_network_engine` has a hardcoded SYN packet builder only.
**V4:** Full TCP engine.

```cpp
enum class TCPState {
    CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED,
    ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2, CLOSE_WAIT,
    CLOSING, LAST_ACK, TIME_WAIT
};

struct TCPConnection {
    TCPState state;
    uint32_t snd_nxt, snd_una, rcv_nxt;
    uint32_t snd_wnd, rcv_wnd;
    uint16_t src_port, dst_port;
    uint32_t src_ip, dst_ip;
    uint8_t sack_permitted;
    uint32_t ts_recent, ts_recent_ack;
    // RTT estimation
    struct {
        uint64_t srtt;     // smoothed RTT (us)
        uint64_t rttvar;   // RTT variance
        uint64_t rto;      // retransmit timeout
    } rtt;
    struct {
        uint64_t sent_tsc; // TSC when sent
        uint32_t seq;      // sequence number sent
    } pending_ack;
};

class TCPEngine {
    TCPConnection* open(const std::string& host, uint16_t port);
    bool send(TCPConnection* conn, const uint8_t* data, size_t len);
    ReceiveResult recv(TCPConnection* conn, uint8_t* buffer, size_t cap);
    void close(TCPConnection* conn);
    // Congestion control (CUBIC)
    void onAck(TCPConnection* conn, uint32_t ack_seq);
    void onLoss(TCPConnection* conn);
    // Retransmission
    void checkRetransmit(TCPConnection* conn, uint64_t current_tsc);
};
```

### 3.4 Stealth Ensemble (`stealth_ensemble.h/.cpp`)

**Current:** 3 print-only methods.
**V4:** Real implementation.

```cpp
class StealthEnsemble {
    bool injectNoisePackets(const std::string& interface, 
                           NoiseProfile profile);
    // NoiseProfile: rate (pkts/s), size_distribution, 
    //              protocol_mix, timing_pattern
    bool randomizeHopLimits(TCPConnection* conn, 
                           uint8_t min_ttl = 32, uint8_t max_ttl = 128);
    bool spoofTcpFingerprint(TCPConnection* conn,
                            FingerprintProfile profile);
    // FingerprintProfile: WS, MSS, TSval freq, SACK, WS scale
    // Pre-built profiles: Chrome 120, Firefox 121, Safari 17
    bool morphTrafficPattern(const PacketView& packet, 
                            MorphTarget target);
    // MorphTarget: PADDING, TIMING, SIZE, PROTOCOL
    
    // New V4 capabilities:
    bool enableTrafficPadding(TCPConnection* conn, 
                             PaddingStrategy strategy);
    // Strategies: MTU_FILL, RANDOM_BURST, PARITY_BLIND
    bool scheduleJitter(uint64_t base_delay_us, uint64_t jitter_us);
};
```

### 3.5 TLS Interceptor (`tls_interceptor.h/.cpp`)

**Current:** OpenSSL context + cert loading, encrypt/decrypt are no-ops.
**V4:** Full TLS 1.3 MITM.

```cpp
class TLSInterceptor {
    // V4 additions:
    struct MITMConfig {
        std::string ca_cert_path;
        std::string ca_key_path;
        bool dynamic_cert_generation;
        std::vector<std::string> target_domains;
        bool enable_session_resumption;
        bool enable_early_data;   // 0-RTT
        bool enable_keylog;       // NSS key log for debugging
    };
    
    // On-the-fly cert generation for MITM
    bool generateDynamicCert(const std::string& domain,
                            EVP_PKEY* ca_key, X509* ca_cert);
    // Full handshake intercept
    bool interceptHandshake(int client_fd, int server_fd);
    // Data pump (decrypt from client, encrypt to server and vice versa)
    void pumpData(SSL* client_ssl, SSL* server_ssl);
    // TLS 1.3 specific
    bool handleEarlyData(SSL* ssl, const uint8_t* data, size_t len);
    bool handleKeyUpdate(SSL* ssl);
    
    // ALPN routing
    bool setALPNProtocols(const std::vector<std::string>& protocols);
    
    // V4 hardened: memory-safe, constant-time operations
    void clearSensitiveData(); // wipe keys after use
};
```

### 3.6 HTTP/2 Parser (`http2_parser.h/.cpp`)

**Current:** Frame parsing works, HPACK is stub, stream handling is stub.
**V4:** Full stack.

```cpp
class Http2Parser {
    // V4 additions:
    struct ConnectionState {
        Settings local_settings;
        Settings remote_settings;
        std::map<uint32_t, StreamState> streams;
        uint32_t last_stream_id;
        uint32_t goaway_last_stream;
        FlowController flow;
        HPACKDecoder hpack_decoder;
        HPACKEncoder hpack_encoder;
        PriorityTree priority;
    };
    
    // Full frame handlers:
    void onSettings(const SettingsFrame& frame);
    void onWindowUpdate(const WindowUpdateFrame& frame);
    void onGoaway(const GoawayFrame& frame);
    void onPing(const PingFrame& frame);
    void onPriority(const PriorityFrame& frame);
    void onContinuation(const ContinuationFrame& frame);
    void onPushPromise(const PushPromiseFrame& frame);
    
    // HPACK (real implementation):
    struct HPACKDecoder {
        DynamicTable table;
        size_t max_table_size;
        std::vector<HeaderField> decode(const uint8_t* data, size_t len);
    };
    struct HPACKEncoder {
        DynamicTable table;
        std::vector<uint8_t> encode(const HeaderField* headers, size_t count);
    };
    
    // Flow control:
    struct FlowController {
        uint32_t initial_window_size;
        uint32_t connection_window;
        std::map<uint32_t, uint32_t> stream_windows;
        bool updateWindow(uint32_t stream_id, int32_t delta);
        bool consumeWindow(uint32_t stream_id, uint32_t bytes);
    };
    
    // Stream state machine:
    enum class StreamState {
        IDLE, OPEN, RESERVED_LOCAL, RESERVED_REMOTE,
        HALF_CLOSED_LOCAL, HALF_CLOSED_REMOTE, CLOSED
    };
    
    // Request/response header validation
    bool validatePseudoHeaders(const HeaderField* headers, size_t count);
};
```

### 3.7 URL Manipulator (`url_manipulator.h/.cpp`)

**Current:** No-op rewrite, trivial header mod.
**V4:** Full RFC 3986 implementation.

```cpp
class UrlManipulator {
    // V4:
    struct ParsedURL {
        std::string scheme;
        std::string userinfo;
        std::string host;
        uint16_t port;
        std::string path;
        std::vector<std::pair<std::string, std::string>> query;
        std::string fragment;
        
        std::string serialize() const;
        bool is_valid() const;
    };
    
    ParsedURL parse(const std::string& url);
    std::string normalize(const ParsedURL& url);
    // Normalization: lowercase scheme/host, 
    //   remove default port, dot-segments, empty query
    ParsedURL mutateQuery(const ParsedURL& url, 
                         const std::vector<QueryOp>& ops);
    // QueryOp: SET(key, val), DELETE(key), RENAME(old, new), SIGN(params)
    
    // Redirect chain tracer:
    struct RedirectChain {
        std::vector<ParsedURL> hops;
        uint32_t total_redirects;
        uint64_t total_time_us;
    };
    RedirectChain traceRedirects(const ParsedURL& url, 
                                int max_hops = 10);
    
    // Authentication injection:
    void setAuthProvider(AuthProvider provider);
    // AuthProvider: BEARER, BASIC, COOKIE, DIGEST, OAUTH2
    Headers injectAuth(const ParsedURL& url, const Headers& original);
};
```

### 3.8 Data Extractor (`data_extractor.h/.cpp`)

**Current:** Regex-only, fragile, no DOM.
**V4:** Streaming SAX parser + CSS selector engine.

```cpp
class DataExtractor {
    // V4:
    struct ExtractionPlan {
        std::vector<ExtractionRule> rules;
        // Rule: { selector: "h1.course-title", output: "course_title" }
        //       { selector: "video[data-url]", output: "video_urls" }
        //       { json_path: "$.data.lesson.title", output: "lesson" }
    };
    
    // Content-type aware dispatch
    ExtractionResult extract(const ExtractionPlan& plan,
                            const uint8_t* data, size_t len,
                            const std::string& content_type);
    
    // SAX HTML parser (streaming, no DOM tree):
    struct SAXParser {
        using TokenCallback = std::function<void(const Token&)>;
        void parse(const uint8_t* data, size_t len, TokenCallback cb);
        // Token types: TAG_OPEN, TAG_CLOSE, ATTRIBUTE, TEXT, COMMENT, SCRIPT
    };
    
    // CSS selector engine (subset: id, class, tag, attr, descendant):
    struct SelectorEngine {
        std::vector<Match> select(const SAXParser::Token* tokens, 
                                 size_t count,
                                 const std::string& selector);
    };
    
    // JSON streaming parser (no full DOM):
    struct JSONStreamer {
        using ValueCallback = std::function<void(const JSONPath&, const Value&)>;
        void parse(const uint8_t* data, size_t len, 
                  const std::vector<std::string>& paths,
                  ValueCallback cb);
    };
    
    // Heuristic engine for pattern discovery:
    struct HeuristicEngine {
        std::vector<DiscoveredPattern> discover(const uint8_t* data, 
                                                size_t len);
        // DiscoveredPattern: regex + context + confidence score
    };
};
```

### 3.9 Backend Transcendence (`backend_transcendence.h/.cpp`)

**Current:** libcurl wrapper with regex extraction.
**V4:** Native stack from raw socket up. No libcurl.

```cpp
class BackendTranscendence {
    // V4: Complete removal of libcurl dependency
    struct FetchResult {
        Buffer response_body;
        Headers response_headers;
        uint16_t status_code;
        std::string protocol;       // "HTTP/1.1" or "HTTP/2"
        struct {
            uint64_t dns_us;
            uint64_t connect_us;
            uint64_t tls_us;
            uint64_t ttfb_us;       // time to first byte
            uint64_t total_us;
            uint64_t tsc_cycles;
        } timing;
        uint32_t packet_count;
        uint32_t retransmit_count;
    };
    
    // Native fetch using internal TCP/TLS/HTTP stacks:
    FetchResult transcendFetch(const std::string& url,
                              const FetchConfig& config);
    // FetchConfig: headers, timeout, follow_redirects, 
    //              cache_policy, stealth_profile
    
    // Multi-stream (HTTP/2 multiplexed):
    std::vector<FetchResult> parallelFetch(
        const std::vector<std::string>& urls,
        const FetchConfig& config);
    
    // Session persistence:
    struct Session {
        TCPConnection* tcp;
        TLSInterceptor::MITMState* tls;
        Http2Parser::ConnectionState* h2;
        std::map<std::string, std::string> cookies;
    };
    Session* createSession(const std::string& host);
    void destroySession(Session* session);
    
    // Transcendence engine:
    struct TranscendencePlan {
        std::vector<ExtractionPlan> extraction_plans;
        std::vector<StealthProfile> stealth_profiles;
        std::vector<URLRewriteRule> rewrite_rules;
    };
    FetchResult transcendWithPlan(const std::string& url,
                                 const TranscendencePlan& plan);
    
    // V4: Integration with StealthEnsemble
    void setEnsembleProfile(StealthProfile profile);
};
```

### 3.10 Performance Monitor (`performance_monitor.h/.cpp`)

**Current:** chrono-based, no integration with assembly, no packet-level tracking.
**V4:** RDTSC-based, lockless, statistical engine.

```cpp
class PerformanceMonitor {
    // V4:
    struct CPUTimer {
        // RDTSC calibration
        static double tsc_per_us;    // calibrated at startup
        static uint64_t calibrate();  // measure TSC frequency
        static inline uint64_t now() {
            uint32_t lo, hi;
            asm volatile("lfence; rdtsc" : "=a"(lo), "=d"(hi));
            return ((uint64_t)hi << 32) | lo;
        }
        static inline double to_us(uint64_t cycles) {
            return cycles / tsc_per_us;
        }
    };
    
    // Lockless event ring (SPSC):
    struct alignas(64) EventRing {
        static constexpr size_t CAPACITY = 1 << 20;
        Event events[CAPACITY];
        atomic<uint64_t> head;        // producer
        atomic<uint64_t> tail;        // consumer
        bool push(const Event& ev);
        bool pop(Event& ev);
    };
    
    // Packet-level tracking:
    void recordPacketEvent(PacketDirection dir, 
                          uint32_t size, uint64_t tsc);
    void recordLoss(uint32_t seq, uint64_t tsc);
    struct PacketStats {
        uint64_t total_packets;
        uint64_t total_bytes;
        uint64_t lost_packets;
        uint64_t retransmitted;
        double throughput_mbps;        // rolling window
        double avg_latency_us;
        double jitter_us;
        double min_latency_us, max_latency_us;
        uint32_t window_size_avg;
    };
    
    // Latency heatmap (configurable buckets):
    struct Heatmap {
        static constexpr int BUCKETS = 256;
        atomic<uint64_t> buckets[BUCKETS];
        uint64_t bucket_min_us, bucket_max_us;
        void record(uint64_t latency_us);
        void dump(const std::string& path);
    };
    
    // V4: Assembly integration
    long long getHighPrecisionTimestampAssembly() const {
        return CPUTimer::now();
    }
};
```

### 3.11 Configuration Engine (`config_engine.h/.cpp`) — NEW

Zero-copy, compile-time parsed configuration in POD structs.

```cpp
struct PNTPConfig {
    struct Network {
        std::string interface = "eth0";
        bool promiscuous = true;
        uint32_t ring_block_num = 1024;
        uint32_t ring_frame_size = 2048;
        std::string bpf_filter = "";
        int numa_node = -1;
    } network;
    
    struct Stealth {
        bool enable_noise = true;
        uint32_t noise_rate_pkts = 100;
        uint8_t ttl_min = 32;
        uint8_t ttl_max = 128;
        std::string fingerprint_profile = "chrome_120";
        bool enable_traffic_padding = false;
        uint64_t jitter_base_us = 100;
        uint64_t jitter_range_us = 50;
    } stealth;
    
    struct TLS {
        std::string ca_cert_path;
        std::string ca_key_path;
        bool dynamic_certs = true;
        bool enable_session_resumption = true;
        bool enable_0rtt = false;
        uint16_t proxy_port = 8080;
        bool keylog = false;
    } tls;
    
    struct Performance {
        bool enable_heatmap = false;
        uint64_t heatmap_min_us = 1;
        uint64_t heatmap_max_us = 10000;
        bool enable_assembly_timing = true;
    } performance;
    
    static PNTPConfig fromFile(const std::string& path);
    static PNTPConfig fromEnv();
};
```

---

## 4. New V4 Modules

### 4.1 TCP State Machine Engine (`tcp_state_machine.h/.cpp`)

Full RFC 793 + RFC 1323 (Timestamps, SACK) + RFC 5681 (Congestion Control).

### 4.2 DNS Resolver (`dns_resolver.h/.cpp`) — NEW

Bypass system resolver. Raw DNS over UDP + DoH (DNS-over-HTTPS) + DoT (DNS-over-TLS).

```cpp
class DNSResolver {
    struct DNSResult {
        std::vector<uint32_t> ipv4_addresses;
        std::vector<uint128_t> ipv6_addresses;
        uint64_t resolve_time_us;
        uint32_t ttl_seconds;
    };
    DNSResult resolve(const std::string& host, 
                     DNSType type = DNSType::A);
    // Cache with LRU eviction
    void setCacheSize(size_t max_entries);
    // DNSSEC validation (optional)
    bool enableDNSSEC(bool enable);
};
```

### 4.3 Packet Builder (`packet_builder.h/.cpp`) — NEW

Modular packet construction library.

```cpp
class PacketBuilder {
    static Buffer buildEthernet(const MAC& dst, const MAC& src, uint16_t proto);
    static Buffer buildIPv4(const IPv4Header& hdr);
    static Buffer buildTCP(const TCPHeader& hdr, const uint8_t* payload, size_t len);
    static Buffer buildUDP(const UDPHeader& hdr, const uint8_t* payload, size_t len);
    static Buffer buildDNS(const DNSHeader& hdr, const DNSQuestion* q, size_t qcount);
    static void calculateIPChecksum(uint8_t* packet, size_t len);
    static void calculateTCPChecksum(uint8_t* packet, size_t len, 
                                    uint32_t src, uint32_t dst);
    // Packet templates for noise:
    static Buffer buildNoisePacket(NoiseProfile profile);
    static Buffer buildKeepalive(uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint32_t seq, uint32_t ack);
};
```

### 4.4 Connection Pool (`connection_pool.h/.cpp`) — NEW

Reuse TCP/TLS connections across fetch operations.

```cpp
class ConnectionPool {
    PooledConnection* acquire(const std::string& host, uint16_t port);
    void release(PooledConnection* conn);
    void setMaxConnections(size_t max);
    void setIdleTimeout(uint64_t ms);
    void closeAll();
    struct PoolStats {
        size_t active;
        size_t idle;
        size_t total_created;
        size_t total_reused;
        uint64_t avg_acquire_wait_us;
    };
    PoolStats getStats() const;
};
```

### 4.5 logging (`log.h/.cpp`) — NEW

Zero-allocation, asynchronous, multi-level logging.

```cpp
namespace pntp {
namespace log {
    enum Level : uint8_t {
        TRACE, DEBUG, INFO, WARN, ERROR, FATAL
    };
    
    struct Sink {
        virtual void write(Level l, const char* msg, size_t len) = 0;
    };
    
    void setLevel(Level min_level);
    void addSink(Sink* sink);  // console, file, ringbuffer, syslog
    
    template<typename... Args>
    void write(Level l, const char* fmt, Args... args);
    
    // Lock-free ring buffer sink for performance-critical paths:
    class RingBufferSink : public Sink {
        // pre-allocated, lockless, SPSC
        static constexpr size_t SIZE = 1 << 18;
        char buffer[SIZE];
        atomic<uint64_t> write_pos;
    };
}
}
```

---

## 5. V5 Authentication Layer — Design Outline

V5 will introduce a radical authentication paradigm: **Hardware-Bound Proof-of-Transcendence (HBPoT)**.

### Core Concept

Traditional auth (OAuth, JWT, SAML) operates at the application layer and is vulnerable to token theft, replay, and MITM. PNTP V5 collapses auth into the network layer:

### Protocol Flow

```
Client                                          Server
  │                                               │
  │  1. TCP SYN + CP_Challenge (TS)              │
  │  ──────────────────────────────────────────►  │
  │                                               │
  │  2. SYN-ACK + ServerNonce (SN)               │
  │  ◄──────────────────────────────────────────  │
  │                                               │
  │  3. ACK + Proof:                             │
  │     H( CPUID || TSC || MAC || SN || TS )     │
  │  ──────────────────────────────────────────►  │
  │                                               │
  │  4. Session Enabled (ZKP verified)           │
  │  ◄──────────────────────────────────────────  │
  │                                               │
  │  5. Encrypted payload (TLS 1.3 + HW token)   │
  │  ═══════════════════════════════════════════►  │
```

### V5 Components to Design in V4

1. **Challenge-Response protocol** in assembly (fast hash, constant-time compare)
2. **Hardware fingerprint extractor** (CPUID leaves, MAC, TSC jitter entropy)
3. **Zero-Knowledge Proof engine** (place stubs in V4, implement in V5)
4. **Distributed ensemble key exchange** (share session state across egress nodes)
5. **Traffic analysis resistant shaping** (V4 ensemble must be complete first)

### V4 → V5 Dependency Map

```
V4 Module                    Enables V5 Feature
─────────────────────────────────────────────────────
Assembly Core (hardened)     HBPoT fast hash + compare
TCP Engine (complete)        Challenge-SYN embedding
Stealth Ensemble (real)      Distributed routing + traffic shaping
TLS Interceptor (real)       Encrypted ZKP transport
Connection Pool              Multi-path ensemble sessions
Performance Monitor          ZKP timing side-channel detection
```

---

## 6. Build System (V4)

Replace manual compilation with CMake + Presets.

```cmake
cmake_minimum_required(VERSION 3.25)
project(pntp VERSION 4.0.0 LANGUAGES CXX ASM)

# Presets:
# - debug     : -O0 -g, ASAN, UBSAN
# - release   : -O3 -march=native -flto
# - perf      : -O3 -march=native -flto -fno-exceptions -fno-rtti
# - size      : -Os -flto
# - asan      : debug + address sanitizer

find_package(OpenSSL REQUIRED)
find_package(CURL)  # optional in V4, removed in V5

add_executable(pntp_v4
    src/pntp_core.asm
    src/raw_socket_handler.cpp
    src/tcp_state_machine.cpp
    src/tls_interceptor.cpp
    src/http2_parser.cpp
    src/url_manipulator.cpp
    src/data_extractor.cpp
    src/backend_transcendence.cpp
    src/stealth_engine.cpp
    src/stealth_ensemble.cpp
    src/performance_monitor.cpp
    src/dns_resolver.cpp
    src/packet_builder.cpp
    src/connection_pool.cpp
    src/config_engine.cpp
    src/log.cpp
    src/main.cpp
)

target_link_libraries(pntp_v4 PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_compile_options(pntp_v4 PRIVATE -Wall -Wextra -Wpedantic -Werror)
```

---

## 7. Testing Strategy (V4)

| Level | Tool | Scope |
|-------|------|-------|
| Unit | GoogleTest | Each module in isolation |
| Integration | Custom harness | Cross-module data flow |
| Network | Docker + netns | Full stack against local httpbin/tls endpoints |
| Performance | Google Benchmark | Throughput, latency percentiles |
| Fuzz | libFuzzer | HTTP/2 parser, URL parser, HPACK |
| Stealth | pcap comparison | Traffic fingerprint analysis |

### Test Targets (Docker images to build):
- `pntp-test-http1` — nginx serving static content
- `pntp-test-http2` — nginx with HTTP/2
- `pntp-test-tls` — OpenSSL s_server for MITM validation
- `pntp-test-stealth` — Suricata/Zcaler for detection evasion testing

---

## 8. Naming Migration

| V3 (NNTP) | V4 (PNTP) |
|-----------|-----------|
| `nntp_core.h/.asm` | `pntp_core.h/.asm` |
| `stealth_network_engine.h/.cpp` | `tcp_engine.h/.cpp` |
| `backend_transcendence.h/.cpp` | `transcendence_engine.h/.cpp` |
| `make_nntp.sh` | `cmake -B build -G Ninja` |
| `NNTP_Architecture_Design.md` | `PNTP_V4_Design.md` (this file) |
| Project namespace `nntp` | Namespace `pntp` |
| Binary name `nntp_v3` | Binary name `pntp_v4` |

File names are renamed ONCE at the start of implementation to avoid churn. Implementation files keep their renamed path.

---

## 9. Performance Budget

All operations budgeted in TSC cycles (assuming 4 GHz Skylake):

| Operation | Budget (cycles) | Budget (µs) |
|-----------|-----------------|-------------|
| RDTSC read | 50 | 0.0125 |
| Packet acquire (ring) | 100 | 0.025 |
| Packet release (ring) | 50 | 0.0125 |
| BPF filter match | 200 | 0.05 |
| TCP header parse | 150 | 0.0375 |
| HTTP/2 frame parse | 300 | 0.075 |
| HPACK decode (1 header) | 500 | 0.125 |
| TLS 1.3 decrypt (1460B) | 2000 | 0.5 |
| Challenge hash (V5) | 800 | 0.2 |
| Log write (lockless) | 100 | 0.025 |

---

## 10. V4 Success Criteria

1. All stubs replaced with real implementations (no "conceptual" or "placeholder" warnings)
2. `backend_transcendence` fetches a URL without libcurl — using native TCP + TLS + HTTP
3. UDP packet capture and injection is functional
4. Stealth ensemble injects real packets on the wire (verifiable via tcpdump)
5. Performance monitor uses RDTSC exclusively (no chrono in hot path)
6. Full HTTP/2 request/response cycle: connection preface → SETTINGS → HEADERS → DATA → GOAWAY
7. TLS MITM intercepts and re-encrypts a real HTTPS connection
8. Build is a single `cmake --build .` command
9. All tests pass under UBSan + ASan
10. Zero loss in extraction pipeline (verified against known test content)
