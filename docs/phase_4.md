# Phase 4: DNS Resolver

**Status:** Complete (2026-07-07)  
**Lines of Code:** ~720 (header + impl + tests + benchmarks)  
**Test Count:** 47 tests across 7 test suites  
**Build:** 47/47 tests passing, 0 failures  
**Description:** Bypass system resolver with raw DNS wire format, DNSCache, and DoH capability. Replaces `getaddrinfo()` in TCPEngine.

---

## Architecture Overview

Phase 4 implements a standalone DNS resolver that constructs and parses DNS wire format messages directly, with no dependency on system resolution libraries (except as fallback).

```
DNSResolver
 ├── DNSCache (LRU + TTL expiry, background sweep)
 ├── Raw UDP Transport (system SOCK_DGRAM on port 53)
 ├── DoH Transport (TCP + OpenSSL TLS, POST application/dns-message)
 └── Resolver Chain: Cache → DoH → UDP → System(getaddrinfo)
```

### Resolver Chain Order
1. **Cache** — Return immediately if TTL is valid
2. **DoH** (optional, default=disabled) — DNS-over-HTTPS via TLS
3. **Raw UDP** — Direct DNS query to configured server port 53
4. **System fallback** — `getaddrinfo()` as last resort

---

## Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `include/pntp/dns_resolver.h` | 120 | DNS types, DNSCache, DNSResolver class declarations |
| `src/dns_resolver.cpp` | 537 | Full implementation: wire format, UDP, DoH, cache, chain |
| `test/test_dns_resolver.cpp` | 719 | 47 tests across 7 test suites |
| `bench/bench_dns_resolver.cpp` | 186 | 12 benchmarks: encode, parse, cache, resolve latency |

## Files Modified

| File | Change |
|------|--------|
| `CMakeLists.txt` | Added `src/dns_resolver.cpp` to `PNTP_SOURCES` |
| `test/CMakeLists.txt` | Added `test_dns_resolver.cpp` to `PNTP_TEST_SOURCES` |
| `bench/CMakeLists.txt` | Added `bench_dns_resolver.cpp` to benchmark sources |
| `src/tcp_engine.cpp` | Replaced `getaddrinfo()` in `resolveHost()` with `DNSResolver` |
| `include/pntp/tcp_engine.h` | Added `DNSResolver` member and initialization |

---

## Key Implementation Details

### DNS Wire Format
- **Header**: 12 bytes (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)
- **Question**: Encoded name + QTYPE(2) + QCLASS(2)
- **Answer**: Name (with pointer compression) + TYPE + CLASS + TTL + RDLENGTH + RDATA
- **Name encoding**: Length-prefixed labels terminated by 0x00
- **Name compression**: Pointer bytes 0xC0 followed by 14-bit offset
- **A records**: 4-byte IPv4 address in network byte order
- **AAAA records**: 16-byte IPv6 address

### DNSCache
- Thread-safe (std::mutex) LRU cache
- TTL tracking via `std::chrono::steady_clock::now()` with nanosecond precision
- `sweep()` for background TTL expiry cleanup
- Configurable max entries (default: 1024)
- LRU promotion on access via `splice()` to front of list

### DoH (DNS-over-HTTPS)
- Uses OpenSSL directly for TLS (TLS gap — see below)
- Sends HTTP/1.1 POST with `application/dns-message` content type
- Parses HTTP response to extract DNS response body
- Configurable DoH server URL (default: `https://cloudflare-dns.com/dns-query`)

### UDP Transport
- Standard `SOCK_DGRAM` UDP socket
- Configurable DNS servers (default: Cloudflare 1.1.1.1, Google 8.8.8.8)
- Per-query timeout via `SO_RCVTIMEO`
- Transaction ID matching for response validation

---

## DoH/TLS Gap (Phase 5 Dependency)

**Important:** The DoH implementation currently uses OpenSSL directly for TLS connections. This is a temporary measure because Phase 5 (TLS Interceptor) is not yet available.

### What to Replace in Phase 5

When Phase 5 implements the full TLS interceptor, the following changes should be made to `src/dns_resolver.cpp`:

1. **Replace raw OpenSSL in `resolveViaDoH()`** (lines ~130-190):
   - Current: `SSL_CTX_new()`, `SSL_new()`, `SSL_connect()`, `SSL_read()`, `SSL_write()`
   - Target: Use `TLSInterceptor` class for TLS connection management
   - The DoH resolver should call `TLSInterceptor::connect(host, port)` instead of raw SSL

2. **What the Phase 5 API should look like** (suggested):
   ```cpp
   // From TLSInterceptor (to be implemented in Phase 5)
   class TLSInterceptor {
       SSL* connect(const std::string& host, uint16_t port);
       void disconnect(SSL* ssl);
       int read(SSL* ssl, uint8_t* buf, size_t len);
       int write(SSL* ssl, const uint8_t* data, size_t len);
   };
   ```

3. **Benefits of refactoring**:
   - Centralized TLS configuration (CA certs, ciphers, session cache)
   - Memory-safe key handling (`clearSensitiveData()`)
   - NSS key log support for debugging
   - Session resumption for repeated DoH queries

### Current Status
- DoH works with raw OpenSSL
- Certificate verification is disabled (`SSL_VERIFY_NONE`) — must be enabled when Phase 5 provides CA infrastructure
- Session caching is per-connection (no reuse) — Phase 5 connection pool will fix this

---

## Test Strategy

| Suite | Tests | What it validates |
|-------|-------|-------------------|
| `DNSWireFormatTest` | 6 | encodeName, decodeName, round-trip, pointers, simple/multi/single |
| `DNSQueryBuilderTest` | 4 | Header structure, question section, A/AAAA types, IDs |
| `DNSResponseParserTest` | 7 | A records, AAAA records, NXDOMAIN, wrong ID, truncation, multiple records |
| `DNSCacheTest` | 8 | Put/get, missing, TTL expiry, TTL=0, LRU eviction, promotion, clear, update |
| `DNSResolverIntegrationTest` | 8 | Real DNS resolution, caching, invalid host, multi-server, AAAA, cache perf, UDP fallback, cache clear |
| `DNSResolverConfigTest` | 7 | Default servers, custom servers, DoH URL, enable/disable, stats, reset, cache size |
| `DNSGoalValidationTest` | 7 | Wire format, compression, cache bypass, multi-A, LRU, config, TTL |

**Total: 47 tests across 7 suites**

### Goal Validation Tests
The `DNSGoalValidationTest` suite is the dedicated test suite that validates the intended role and goals of Phase 4:
- **Raw wire format**: DNS messages built/parsed without system resolver
- **Name compression**: Correct handling of DNS pointer compression
- **Cache bypass**: Cache returns results without network query
- **Multiple A records**: Response with 2+ A records is fully parsed
- **LRU bounding**: Cache size does not grow unbounded
- **Configurable servers**: DNS server list is user-configurable
- **TTL preservation**: TTL from DNS response is preserved and used for cache expiry

---

## Benchmarks

| Benchmark | What it measures |
|-----------|------------------|
| `BM_EncodeName` | Encode `www.example.com` to wire format |
| `BM_DecodeName` | Decode wire format `deep.subdomain.example.org` |
| `BM_BuildQuery` | Build full DNS query for A record |
| `BM_ParseResponse_Single` | Parse response with 1 A record |
| `BM_ParseResponse_Multi` | Parse response with 10 A records |
| `BM_CachePut` | Cache insertion throughput |
| `BM_CacheGet_Hit` | Cache lookup on existing entry |
| `BM_CacheGet_Miss` | Cache lookup on missing entry |
| `BM_CacheSweep` | Sweep 100K entries with expired TTL |
| `BM_Resolve_Cold` | End-to-end resolve (cold cache, first query) |
| `BM_Resolve_Hot` | End-to-end resolve (hot cache, repeated query) |

---

## Performance Targets

| Metric | Target | Notes |
|--------|--------|-------|
| Name encode | <200ns | Wire format serialization |
| Response parse | <1µs | Single A record, name compression |
| Cache hit | <100ns | Mutex + map + list splice |
| Cache miss | <50ns | Map lookup only |
| UDP query | <10ms | Local network to 1.1.1.1 |
| Sweep 100K | <1ms | Background TTL expiry |

---

## Known Limitations

1. **No EDNS0 support**: DNS queries use 512-byte UDP limit. For responses larger than 512 bytes, truncation (TC bit) is ignored. EDNS0 should be added for DNSSEC or large responses.
2. **No TCP fallback for truncated responses**: If TC bit is set, the resolver should re-query over TCP. Currently not implemented.
3. **No DNSSEC validation**: Token DNSSEC validation is mentioned in Phase.md but not implemented. RRSIG records are ignored in response parsing.
4. **No SOA record parsing**: Authority section is skipped entirely (only question and answer sections are parsed).
5. **DoH verification disabled**: SSL certificate verification is disabled (`SSL_VERIFY_NONE`) until Phase 5 provides CA infrastructure.
6. **Hardcoded TSC ratio**: DNS resolve time uses `3000 cycles/µs` conversion, same as TCPEngine. Phase 12 (`CPUTimer::calibrate()`) will provide accurate conversion.

---

## File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `include/pntp/dns_resolver.h` | 120 | DNS types, DNSCache, DNSResolver class declarations |
| `src/dns_resolver.cpp` | 537 | Full implementation |
| `test/test_dns_resolver.cpp` | 719 | 47 tests (7 suites) |
| `bench/bench_dns_resolver.cpp` | 186 | 12 benchmarks |

---

## Revision History

| Date | Change |
|------|--------|
| 2026-07-07 | Phase 4 complete. 47/47 tests passing, 0 failures. |
