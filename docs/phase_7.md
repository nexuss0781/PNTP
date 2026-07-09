# Phase 7: HTTP/1.1 Parser

**Status:** Complete (2026-07-09)  
**Lines of Code:** ~1050 (header + impl), ~700 (tests), ~250 (benchmarks)  
**Test Count:** 70+ tests across 12+ test suites  
**Description:** RFC 7230/7231-compliant HTTP/1.1 streaming parser for fallback connections, h2c upgrade detection, and 100 Continue handling.

---

## Architecture Overview

Phase 7 replaces the two ad-hoc HTTP/1.1 implementations in the codebase (`tcp_engine.cpp:transcendentFetch()` and `dns_resolver.cpp:resolveViaDoH()`) with a proper streaming parser that handles the full HTTP/1.1 protocol:

```
Http1Parser
 ├── Request/Response Line Parser   (RFC 7230 §3.1.1/3.1.2)
 ├── Header Parser                  (RFC 7230 §3.2, obs-fold support)
 ├── Content-Length Body Reader     (RFC 7230 §3.3.2)
 ├── Chunked Transfer Decoder       (RFC 7230 §4.1)
 ├── Connection State Tracking      (keep-alive vs close, RFC 7230 §6.1)
 ├── h2c Upgrade Detection          (RFC 7540 §3.2)
 ├── 100 Continue Handling          (RFC 7231 §5.1.1)
 ├── Request/Response Serialization (wire format construction)
 └── Chunked Encoding Serialization
```

---

## File Inventory

| File | Lines | Purpose |
|------|-------|---------|
| `include/pntp/http1_parser.h` | 200 | Class declarations: `Http1Parser`, `Http1Request`, `Http1Response`, `Http1Header`, enums |
| `src/http1_parser.cpp` | ~850 | Full implementation: all parser states, serializers, chunked codec |
| `test/test_http1_parser.cpp` | ~700 | 70+ GTest tests across 12+ test suites |
| `bench/bench_http1_parser.cpp` | ~250 | 10 Google Benchmark suites |
| `src/tcp_engine.cpp` | +3 lines | Refactored `transcendentFetch()` to use `Http1Parser` for response parsing |
| `src/dns_resolver.cpp` | +3 lines | Refactored `resolveViaDoH()` to use `Http1Parser` for HTTP response parsing |

---

## Implementation Detail

### Parse State Machine

```
H1_STATE_REQUEST_LINE     → H1_STATE_HEADERS
H1_STATE_RESPONSE_LINE    → H1_STATE_HEADERS
H1_STATE_HEADERS           → H1_STATE_BODY_* or H1_STATE_COMPLETE
H1_STATE_BODY_CONTENT_LENGTH → H1_STATE_COMPLETE (when all bytes read)
H1_STATE_BODY_CHUNK_SIZE  → H1_STATE_BODY_CHUNK_DATA or H1_STATE_BODY_CHUNK_TRAILER
H1_STATE_BODY_CHUNK_DATA  → H1_STATE_BODY_CHUNK_SIZE (when chunk complete)
H1_STATE_BODY_CHUNK_TRAILER → H1_STATE_COMPLETE (on empty trailer line)
H1_STATE_BODY_CLOSE_DELIMITED → H1_STATE_COMPLETE (on connection close)
H1_STATE_COMPLETE or H1_STATE_ERROR → terminal
```

### Request Line Parser (RFC 7230 §3.1.1)

```
method = token
request-target = origin-form = path [ "?" query ]
HTTP-version = "HTTP/1.1" | "HTTP/1.0"
```

Parses: `METHOD SP request-target SP HTTP-version CRLF`

Supported methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, CONNECT, TRACE

### Response Line Parser (RFC 7230 §3.1.2)

```
HTTP-version SP status-code SP reason-phrase CRLF
status-code = 3-digit integer (100-599)
```

### Header Parser (RFC 7230 §3.2)

- **field-name**: token characters only, validated per RFC 7230 §3.2.6
- **field-value**: OWS stripped, obs-fold (continuation lines starting with SP/HT) supported
- **Duplicate headers**: Comma-separated concatenation (except Set-Cookie and Cookie kept separate)
- **Case-insensitive**: Header names normalized to lowercase internally

### Body Determination (RFC 7230 §3.3)

Priority order:
1. HEAD requests → no body
2. 1xx, 204, 304 → no body
3. Transfer-Encoding: chunked → chunked decoder
4. Content-Length → exact byte reader
5. Request methods without defined body (GET, DELETE, HEAD, OPTIONS, TRACE) → no body
6. Close-delimited → accumulate until connection closes or keep-alive (HTTP/1.0)

### Chunked Transfer Decoder (RFC 7230 §4.1)

```
chunked-body = *chunk last-chunk trailer-part CRLF
chunk        = chunk-size [chunk-ext] CRLF chunk-data CRLF
last-chunk   = 1*("0") [chunk-ext] CRLF
trailer-part = *(header-field CRLF)
```

- Chunk-extensions are ignored per RFC 7230 §4.1.1
- Maximum chunk size: 16MB (configurable via MAX_CHUNK_SIZE)
- Trailer headers are parsed but not currently stored

### Connection State

| Context | Default | Close Condition |
|---------|---------|-----------------|
| HTTP/1.1 | keep-alive | `Connection: close` |
| HTTP/1.0 | close | `Connection: keep-alive` |

### h2c Upgrade Detection (RFC 7540 §3.2)

Detected from:
- `Upgrade: h2c` header
- `HTTP2-Settings: <base64url>` header (raw bytes stored for caller decode)
- `Connection: Upgrade, HTTP2-Settings` header

### 100 Continue (RFC 7231 §5.1.1)

- `Expect: 100-continue` detected from request headers
- `Http1Parser::serializeContinue()` generates the `HTTP/1.1 100 Continue\r\n\r\n` response

---

## Serialization API

```cpp
// Request: "GET /path HTTP/1.1\r\nHost: a.com\r\nContent-Length: 0\r\n\r\n"
static std::vector<uint8_t> serializeRequest(
    const Http1Request& req, const std::vector<Http1Header>& headers,
    const uint8_t* body, size_t body_len);

// Response: "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
static std::vector<uint8_t> serializeResponse(
    const Http1Response& resp, const std::vector<Http1Header>& headers,
    const uint8_t* body, size_t body_len);

// 100 Continue: "HTTP/1.1 100 Continue\r\n\r\n"
static std::vector<uint8_t> serializeContinue();

// Chunk: "5\r\nhello\r\n"
static std::vector<uint8_t> serializeChunk(const uint8_t* data, size_t len);
static std::vector<uint8_t> serializeChunkEnd();  // "0\r\n\r\n"
```

Auto-adds Content-Length if body is present and no Content-Length header is explicitly provided. Default reason phrases for standard status codes (200→OK, 404→Not Found, etc.).

---

## Integration Surface

```cpp
// Main API
size_t feed(const uint8_t* data, size_t len);  // returns bytes consumed
bool isComplete() const;
bool hasError() const;
void reset();

// Accessors
const Http1Request& getRequest() const;
const Http1Response& getResponse() const;
const std::vector<Http1Header>& getHeaders() const;
const std::vector<uint8_t>& getBody() const;
std::string getHeader(const std::string& name) const;
std::vector<std::string> getHeaderValues(const std::string& name) const;

// Connection State
bool shouldClose() const;
bool upgradeDetected() const;
Http1UpgradeInfo getUpgradeInfo() const;
bool expectContinue() const;
```

---

## Refactored Integration Points

### TCP Engine (`src/tcp_engine.cpp`)

`transcendentFetch()` now uses `Http1Parser`:

```cpp
// Before: raw string search for "\r\n\r\n"
std::string response(response_body.begin(), response_body.end());
size_t body_start = response.find("\r\n\r\n");
if (body_start != std::string::npos)
    return response.substr(body_start + 4);

// After: proper HTTP parser
Http1Parser parser;
parser.feed(response_body.data(), response_body.size());
if (parser.isComplete() && parser.getResponse().status_code / 100 == 2) {
    auto body = parser.getBody();
    return std::string(body.begin(), body.end());
}
```

### DNS Resolver (`src/dns_resolver.cpp`)

`resolveViaDoH()` now uses `Http1Parser`:

```cpp
// Before: raw search + status string match
auto it = std::search(http_response.begin(), http_response.end(), "\r\n\r\n", ...);
if (status_line.find("200") == std::string::npos) return result;

// After: proper HTTP parser
Http1Parser http_parser;
http_parser.feed(http_response.data(), http_response.size());
if (http_parser.getResponse().status_code != 200) return result;
auto body = http_parser.getBody();
```

---

## Test Strategy

| Suite | Tests | What It Validates |
|-------|-------|-------------------|
| `RequestLineParseTest` | 7 | Simple GET, POST+body, path+query, HTTP/1.0, unknown method, malformed, all methods |
| `ResponseLineParseTest` | 6 | 200/404/500/101, HTTP/1.0, invalid status |
| `HeaderParseTest` | 8 | Single/multi/duplicate, obs-fold, empty value, case-insensitivity, invalid name, large header |
| `ChunkedBodyTest` | 6 | Single/multi/zero-length chunk, extension, trailer, large chunk rejection |
| `ContentLengthBodyTest` | 4 | Exact/zero/partial/longer-than-CL |
| `KeepAliveTest` | 4 | HTTP/1.1 keep-alive, Connection: close, HTTP/1.0 close, explicit keep-alive |
| `UpgradeH2CTest` | 3 | h2c detected, no upgrade, websocket upgrade |
| `Continue100Test` | 4 | Expect detected, no expect, serialize, GET+Expect |
| `SerializeTest` | 5 | Request/response/chunk round-trip, request with body, request with query |
| `EdgeCaseTest` | 7 | Empty input, reset/reuse, HEAD no-body, streaming partial, byte-by-byte, multi-cookie, CL+TE conflict |
| `FeedRoundTripTest` | 3 | Full request/response cycle, POST chunked, response with Connection: close |
| `MassParseTest` | 2 | 1000 random requests, 1000 random responses |
| `GoalValidationTest` | 10 | All 10 P7 goals verified |

**Total: 70+ tests across 12+ suites**

### Goal Validation Tests

The `GoalValidationTest` suite validates the intended role and goals of Phase 7:

- P7-001: Request line parser works (method, path, version)
- P7-002: Response line parser works (status code)
- P7-003: Header parser works (name-value extraction)
- P7-004: Chunked decoding works (transfer-encoding)
- P7-005: Content-Length body works (exact byte count)
- P7-006: Connection: close tracking (shouldClose)
- P7-007: Upgrade: h2c detection (upgradeDetected)
- P7-008: Expect: 100-continue detection (expectContinue)
- P7-009: Request serialization round-trip
- P7-010: Response serialization round-trip

---

## Benchmarks

| Benchmark | Parameters | What It Measures |
|-----------|-----------|-----------------|
| `BM_ParseRequestLine` | — | Time to parse "GET /index.html HTTP/1.1\r\n" |
| `BM_ParseResponseLine` | — | Time to parse "HTTP/1.1 200 OK\r\n..." |
| `BM_ParseHeaders_10` | 10 headers | Time to parse 10 header lines |
| `BM_ParseHeaders_50` | 50 headers | Time to parse 50 header lines |
| `BM_ParseChunkedBody_1MB` | 128×8KB chunks | Throughput parsing 1MB chunked body |
| `BM_SerializeRequest` | 4 headers | Time to serialize GET request |
| `BM_SerializeResponse` | 3 headers + body | Time to serialize 200 response |
| `BM_FullRoundTrip` | — | Parse request + serialize response |
| `BM_ContentLengthBodyThroughput` | 100B–100KB | Body throughput scaling |
| `BM_SerializeChunk` | 10B–10KB | Chunk serialization overhead |

---

## How This Enables Downstream Phases

| Phase | What Phase 7 Gives It |
|-------|----------------------|
| **P10: Transcendence Engine** | `Http1Parser` for HTTP/1.1 response parsing in native `transcendFetch()`. h2c upgrade detection enables HTTP/2 cleartext upgrade path. |
| **P13: Connection Pool** | `Http1Parser::shouldClose()` enables keep-alive connection management. Parsed headers enable cookie/session reuse. |
| **P9: Data Extractor** | HTTP/1.1 response body extraction via `getBody()` — works for both content-length and chunked responses. |
| **P14: Config & Logging** | HTTP/1.1 response header extraction (`getHeader()`) for logging response metadata. |

---

## Performance Targets

| Operation | Target | Notes |
|-----------|--------|-------|
| Request line parse | <1µs | Method + path + version extraction |
| Response line parse | <1µs | Version + status + reason extraction |
| Header parse (10 headers) | <5µs | Key-value with name normalization |
| Chunked body (1MB) | <10ms | 128 chunks, ~8KB each |
| Content-Length body (100KB) | <1ms | Simple append with size check |
| Request serialize | <2µs | 4 headers, no body |
| Response serialize | <2µs | 3 headers + small body |

---

## Known Limitations

1. **No HTTP/0.9 support**: The parser requires HTTP/1.0 or HTTP/1.1 version strings.
2. **No Transfer-Encoding: gzip**: Content-encoding decompression is not performed; raw body bytes are returned.
3. **No trailer header storage**: Chunked trailers are parsed (consumed) but not stored for access.
4. **No multi-line header folding beyond obs-fold**: RFC 7230 deprecated line folding; only SP/HT continuation is supported.
5. **No Upgrade: h2c automatic handoff**: The parser detects h2c upgrades but does not automatically switch to Http2Parser; the caller must handle this.
6. **No pipelining support**: Multiple requests on the same connection require separate parser instances or manual reset.

---

## File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `include/pntp/http1_parser.h` | 200 | Full class declarations with all types and enums |
| `src/http1_parser.cpp` | ~850 | Complete RFC 7230 implementation |
| `test/test_http1_parser.cpp` | ~700 | 70+ GTest tests across 12+ suites |
| `bench/bench_http1_parser.cpp` | ~250 | 10 Google Benchmark suites |

## Revision History

| Date | Change |
|------|--------|
| 2026-07-09 | Phase 7 complete. All tests passing, 0 failures. |
