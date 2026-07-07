# Phase 5: TLS 1.3 Interceptor — Protocol-Level MITM Engine

**Status:** `IMPLEMENTED` (Jul 2026)  
**Commit:** _(run `git log -1` after push)_  

Full TLS 1.3 MITM proxy built from scratch over OpenSSL libcrypto primitives.  
No `SSL_CTX_new`, `SSL_accept`, `SSL_connect`, `SSL_read`, or `SSL_write` anywhere.

---

## Why We Create TLS (Not Wrap OpenSSL SSL)

The PNTP philosophy is **layer collapse** — no software abstraction is sacred. Wrapping OpenSSL's `SSL_accept`/`SSL_connect` is the same pattern as wrapping libcurl: you don't own the protocol, you can't intercept at the message level, and the state machine is opaque.

Phase 5's goal is not "use TLS" — it's **intercept TLS**. Interception requires:

| Capability | OpenSSL SSL wrapper | Custom TLS protocol |
|-----------|-------------------|-------------------|
| Parse/modify ClientHello extensions | ❌ Opaque | ✅ Full control |
| Extract SNI before handshake | ❌ Must complete first | ✅ Parse on arrival |
| Independent keys per leg | ❌ Single SSL context | ✅ Separate client/server keys |
| Forward handshake messages with modifications | ❌ Can't intercept mid-handshake | ✅ Modify and forward |
| 0-RTT replay detection | ❌ OpenSSL internal | ✅ We implement |

### Crypto Primitives Used (OpenSSL libcrypto, not libssl)

| Primitive | OpenSSL API | Location |
|-----------|-------------|----------|
| X25519 ECDH | `EVP_PKEY_keygen` / `EVP_PKEY_derive` | `tls_interceptor.h:361-367` |
| AES-128-GCM | `EVP_EncryptInit_ex` with `EVP_aes_128_gcm` | `tls_interceptor.cpp:190-297` |
| HKDF (RFC 5869) | `HMAC()` / manual HMAC iter loop | `tls_interceptor.cpp:889-943` |
| SHA-256/SHA-384 | `EVP_MD_CTX` / `EVP_Digest*` | `tls_interceptor.cpp:1338-1353` |
| X.509 / ASN.1 | `X509_new` / `X509_sign` / `X509_set*` | `tls_interceptor.cpp:1124-1244` |
| ECDSA signing | `EVP_PKEY_sign` | `tls_interceptor.cpp:670-724` |

---

## File Inventory (Actual)

| File | Lines | Purpose |
|------|-------|---------|
| `include/pntp/tls_interceptor.h` | 432 | Full class declarations: 31 public + 28 private methods, 12 structs |
| `src/tls_interceptor.cpp` | 2825 | Complete TLS 1.3 MITM implementation |
| `test/test_tls_interceptor.cpp` | 1046 | 55+ tests across 15 test suites |
| `bench/bench_tls_interceptor.cpp` | 209 | 7 benchmarks (X25519, AES-GCM, HKDF, cert, record) |
| `src/dns_resolver.cpp` | 697 + edits | DoH refactored to use `TLSInterceptor::connect` instead of raw `SSL_*` |
| `test/CMakeLists.txt` | 37 | Added `tls_interceptor.cpp` + `test_tls_interceptor.cpp` |
| `bench/CMakeLists.txt` | 24 | Added `tls_interceptor.cpp` + `bench_tls_interceptor.cpp` |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        TLSInterceptor                               │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │               TLS Record Layer (RFC 8446 §5)                 │    │
│  │  readRecord(fd) → {type, version, payload}                   │    │
│  │  writeRecord(fd, type, data, len) → bool                     │    │
│  │  aeadDecrypt(key, ciphertext) → plaintext                    │    │
│  │  aeadEncrypt(key, type, plaintext) → ciphertext              │    │
│  └──────────┬──────────────────────────────────────┬────────────┘    │
│             │                                      │                 │
│  ┌──────────▼──────────────────┐  ┌───────────────▼─────────────┐   │
│  │  Client Leg (MITM→Client)   │  │  Server Leg (MITM→Server)   │   │
│  │  parseClientHello()         │  │  forward ClientHello        │   │
│  │  serializeServerHello()     │  │  parseServerHello()         │   │
│  │  serializeEncryptedExt()    │  │  decrypt server flight      │   │
│  │  serializeCertificate()     │  │  verify server Finished     │   │
│  │  serializeCertVerify()      │  │  send client Finished       │   │
│  │  serializeFinished()        │  │  derive app keys            │   │
│  └─────────────────────────────┘  └──────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                  Key Schedule (RFC 8446 §7.1)                │    │
│  │  hkdfExtract(salt, ikm) → prk                               │    │
│  │  hkdfExpand(prk, info, L) → output                          │    │
│  │  deriveSecret(secret, label, context)                       │    │
│  │  deriveTrafficKeys(secret, label, th, key)                  │    │
│  │  computeFinishedVerifyData(base_key, th)                    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │               Certificate Manager                           │    │
│  │  generateCA() → {X509*, EVP_PKEY*} (ECDSA P-256, 10yr)     │    │
│  │  generateDomainCert(domain) → CertEntry (90-day, CA-signed) │    │
│  │  getOrCreateCert(domain) → LRU cache (1000 entries)         │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                MITM Proxy Engine                             │    │
│  │  startProxy(port) → accept loop → handleConnection()        │    │
│  │  handleConnection: read ClientHello → extract SNI →         │    │
│  │    getCert(SNI) → clientLeg() → serverLeg() → pumpData()    │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                Direct TLS Connect (Single Leg)               │    │
│  │  connect(host, port, timeout) → TLSConnection               │    │
│  │  writeData(conn, data, len) → bool                          │    │
│  │  readData(conn, timeout) → vector<uint8_t>                  │    │
│  │  disconnect(conn)                                           │    │
│  │  **Used by** DNS DoH, TranscendenceEngine, ConnectionPool   │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                Session Manager                               │    │
│  │  storeSessionTicket(domain, ticket)                          │    │
│  │  findSessionTicket(domain) → SessionTicket*                  │    │
│  └─────────────────────────────────────────────────────────────┘    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐    │
│  │                NSS Key Log                                   │    │
│  │  setKeyLogPath(path) → open file                             │    │
│  │  writeKeyLogEntry(label, client_random, secret)              │    │
│  └─────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Implementation Detail

### Record Layer (`tls_interceptor.cpp:123-297`)

- `readRecord()`: 5-byte header, validate length (≤ 16384+256), loop-read payload
- `writeRecord()`: serialize type (1) + version (2) + length (2) + payload
- `writeRecordVec()`: same with scatter-gather for encrypted flights
- AEAD nonce: `nonce[12] = IV[12] XOR (0x00×4 || seq[8])` per RFC 8446 §5.3
- AEAD AAD: `seq(8) || type(1) || 0x0303(2) || len(2)` = 13 bytes
- AES-128-GCM via `EVP_EncryptInit_ex` / `EVP_CIPHER_CTX_ctrl(EVP_CTRL_GCM_GET_TAG)`

### Handshake Parsing (`tls_interceptor.cpp:303-531`)

| Method | Input | Parsed Fields |
|--------|-------|---------------|
| `parseClientHello()` | wire bytes | version, random, session_id, cipher_suites, compression, extensions |
| `parseServerHello()` | wire bytes | version, random, session_id, cipher_suite, compression, extensions |
| `parseExtensions()` | ext bytes + `HskClientHello&` | SNI, supported_groups, sig_algs, ALPN, key_share, supported_versions, PSK modes, PSK identity/binder |

### Handshake Serialization (`tls_interceptor.cpp:537-859`)

| Method | Output | Contents |
|--------|--------|----------|
| `serializeServerHello()` | handshake body | version, random, sid, cipher_suite, compression, key_share + supported_versions exts |
| `serializeEncryptedExtensions()` | handshake body | ALPN extension |
| `serializeCertificate()` | handshake body | request_context(0) || cert_list(3B len) [leaf DER + chain DER] |
| `serializeCertificateVerify()` | handshake body | sig_scheme(ecdsa_secp256r1_sha256) || sig |
| `serializeFinished()` | handshake body | verify_data (HMAC-SHA-256) |
| `serializeNewSessionTicket()` | handshake body | lifetime, age_add, nonce, ticket, extensions |

### Key Schedule (`tls_interceptor.cpp:861-1054`)

Implementation of RFC 8446 §7.1:

```
0 → HKDF-Extract → Handshake Secret → HKDF-Extract(0) → Master Secret
         ↑                                     ↑
   ECDHE shared_secret                 Handshake Secret
```

- `hkdfExtract()`: `HMAC-Hash(salt, ikm)` (line 889-906)
- `hkdfExpand()`: iterative `T(i) = HMAC(PRK, T(i-1) || info || counter)` (line 908-943)
- `deriveSecret()`: `HKDF-Expand-Label(secret, "tls13 " + label, context, Hash.len)` (line 945-983)
- `deriveTrafficKeys()`: Derive-Secret → Expand-Label("key", 16) + Expand-Label("iv", 12) (line 985-1023)
- `computeFinishedVerifyData()`: `HMAC(HKDF-Expand-Label(base_key, "finished"), transcript)` (line 1025-1054)

### X25519 Key Exchange (`tls_interceptor.cpp:1056-1118`)

- `generateX25519Keypair()`: `EVP_PKEY_keygen(EVP_PKEY_X25519)`
- `getPubKeyBytes()`: `EVP_PKEY_get_raw_public_key`
- `computeSharedSecret()`: `EVP_PKEY_derive` against imported peer public key
- `importPeerPublicKey()`: `EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519)`

### Certificate Generation (`tls_interceptor.cpp:1120-1274`)

- `generateCA()`: ECDSA P-256 key ↔ self-signed X.509 v3 cert (10yr, CA:TRUE, keyCertSign)
- `generateDomainCert(domain)`: ECDSA P-256 leaf → CN=domain, SAN=DNS:domain → signed by CA key (90d)
- `getOrCreateCert(domain)`: LRU cache (unordered_map, 1000 max), normalize to lowercase

### MITM Client Leg (`tls_interceptor.cpp:1355-1583`)

1. Read ClientHello → parse → extract SNI, key_share, ALPN, versions
2. Generate MITM X25519 keypair → build ServerHello with MITM's key share
3. Compute `ECDHE(client_pub, mitm_priv)` → derive handshake secret
4. Build EE, Certificate, CertificateVerify, Finished
5. Encrypt flight with `server_handshake_key` (seq: 0,1,2,3)
6. Read client's Finished → decrypt with `client_handshake_key` → verify
7. Derive application keys: `server_app_key` + `client_app_key`

### MITM Server Leg (`tls_interceptor.cpp:1592-1951`)

1. TCP connect to real server
2. Build new ClientHello: forward cipher_suites, SNI, ALPN; inject MITM's key_share
3. Read ServerHello → extract server's key_share
4. Compute `ECDHE(server_pub, mitm_server_priv)` → derive server leg handshake keys
5. Read + decrypt EE, Certificate, CertificateVerify, Finished
6. Verify server Finished → send client Finished
7. Derive server leg application keys

### Direct TLS Connect (`tls_interceptor.cpp:2230-2657`)

Single-leg client TLS 1.3 handshake. Used by DoH, Transcendence, Connection Pool.

1. TCP connect → build ClientHello (SNI, key_share, supported_versions, sig_algs, ALPN)
2. Read ServerHello → compute shared secret → derive handshake keys
3. Read server encrypted flight (EE, Cert, CertVerify, Finished)
4. Send client CCS + Finished
5. Derive application keys: `read_key` (server→client) + `write_key` (client→server)

### Data Pump (`tls_interceptor.cpp:2659-2749`)

Bi-directional poll-based relay:
- `poll()` both fds → read encrypted record → decrypt with source leg key → encrypt with dest leg key → write
- Alert propagation (esp. `close_notify`)
- Error/EOF detection

### MITM Proxy (`tls_interceptor.cpp:1973-2228`)

- `startProxy(port)`: socket + bind + listen (128 backlog) → accept thread
- `handleConnection(fd)`: read ClientHello → extract SNI → get cert → clientLeg + serverLeg → pumpData
- `stopProxy()`: close listen fd, join thread, flags

### DNS Resolver Integration (`src/dns_resolver.cpp:357-506`)

`resolveViaDoH()` now uses `TLSInterceptor` instead of raw `SSL_CTX_new/SSL_connect/SSL_read/SSL_write`:

1. Lazily initialize `TLSInterceptor` singleton in DNSResolver
2. `tls_->connect(doh_host_, 443, timeout)` → full TLS 1.3 handshake
3. `tls_->writeData(conn, http_header)` → `tls_->writeData(conn, dns_query)`
4. `tls_->readData(conn)` loop → collect response
5. Parse HTTP for `\r\n\r\n` body → `parseResponse()` DNS wire format

### Memory Safety (`tls_interceptor.cpp:2802-2825`)

- `clearSensitiveData(TrafficKey&)`: `OPENSSL_cleanse(key, 16) + OPENSSL_cleanse(iv, 12)`
- `clearSensitiveData(vector<uint8_t>&)`: `OPENSSL_cleanse(data) + clear()`
- `constantTimeCompare()`: wraps `CRYPTO_memcmp`

---

## Tests

55+ tests across 15 suites in `test/test_tls_interceptor.cpp` (1046 lines, GTest).

| Suite | Tests | Coverage |
|-------|-------|----------|
| `RecordLayerTest` | 5 | TrafficKey equality, AEAD round-trip, tamper detection, wrong key, seq nonce diff |
| `HandshakeParseTest` | 7 | ClientHello parse (minimal, SNI, key_share, too-short, ALPN), ServerHello parse |
| `HandshakeSerializeTest` | 6 | Header, SH round-trip, EE, Certificate, CertVerify, Finished |
| `KeyScheduleTest` | 8 | HKDF-Extract (with/without salt), HKDF-Expand (16/32), Derive-Secret, label diff, traffic keys, SHA-384, Finished |
| `X25519KeyExchangeTest` | 6 | Keygen, pubkey bytes, shared secret (consistent + different), import (valid/invalid) |
| `CertManagerTest` | 5 | Init creates CA, getOrCreateCert, cache hit, different domain = different cert, normalization, clear |
| `MemorySafetyTest` | 5 | clear TrafficKey/vector, constant-time equal/neq/empty/partial |
| `InterceptorInitTest` | 3 | Initialize succeeds, idempotent, default state |
| `ALPNTest` | 3 | Default protos, set ALPN, serialize ALPN ext |
| `KeyShareExtTest` | 1 | Serialize key_share ext |
| `SupportedVersionsTest` | 1 | Serialize supported_versions ext |
| `TranscriptHashTest` | 3 | Empty input, deterministic, different input |
| `ProxyTest` | 3 | Start/stop, no-init fails, double-start |
| `KeyLogTest` | 2 | Set path, disabled default |
| `GoalValidationTest` | 9 | Dynamic cert, per-domain cache, AEAD encrypt/decrypt, X25519, HKDF, memory safety, SH round-trip, CH multi-ext |

---

## Benchmarks

7 benchmarks in `bench/bench_tls_interceptor.cpp` (209 lines, Google Benchmark).

| Benchmark | Parameters | What It Measures |
|-----------|-----------|-----------------|
| `BM_X25519KeyExchange` | — | X25519 keypair gen + shared secret (2 keygen + 1 derive) |
| `BM_AES128GCMEncrypt` | 256 / 1500 / 16384 bytes | AES-128-GCM seal via EVP_AEAD |
| `BM_AES128GCMDecrypt` | 256 / 1500 / 16384 bytes | AES-128-GCM open via EVP_AEAD |
| `BM_HKDFExtract` | — | HKDF-Extract (SHA-256, 32B salt+IKM) |
| `BM_HKDFExpand` | 32 / 64 bytes | HKDF-Expand to L bytes |
| `BM_CertGeneration` | — | `getOrCreateCert("benchmark.example.com")` (10 iters) |
| `BM_RecordLayer` | 64 / 1500 / 65535 bytes | Serialize + parse TLS record header |

---

## Success Criteria (Implemented)

- [x] TLS record layer: read/write/encrypt/decrypt with AEAD (AES-128-GCM)
- [x] Handshake message parsing: ClientHello + ServerHello with all extensions
- [x] Handshake message serialization: ServerHello, EE, Certificate, CertVerify, Finished, NST
- [x] Key schedule: HKDF-Extract, HKDF-Expand, Derive-Secret, deriveTrafficKeys, Finished verify_data
- [x] X25519 key exchange: keygen, pubkey export, shared secret derivation
- [x] Certificate generation: self-signed CA + domain-specific leaf certs (ECDSA P-256)
- [x] Cert cache: LRU with 1000-entry max, domain normalization
- [x] MITM client leg: full handshake as server to browser client
- [x] MITM server leg: full handshake as client to real server
- [x] Direct TLS connect: single-leg client handshake for DoH/Transcendence
- [x] Data pump: poll-based bidirectional encrypted relay
- [x] MITM proxy listener: TCP accept → handshake → pump
- [x] DNS DoH: refactored from raw SSL to TLSInterceptor::connect
- [x] Session management: store/find session tickets
- [x] NSS key log: SSLKEYLOGFILE format
- [x] Memory safety: OPENSSL_cleanse + CRYPTO_memcmp
- [x] Tests: 55+ GTest tests across 15 suites
- [x] Benchmarks: 7 Google Benchmark suites
- [x] CMake integration: test/ and bench/ CMakeLists updated

---

## How This Enables Downstream Phases

| Phase | What Phase 5 Gives It |
|-------|----------------------|
| **P6: HTTP/2** | Decrypted HTTP/2 data from MITM pump. `getALPN()` exposes h2 negotiation. TLS record boundaries align with HTTP/2 frames. |
| **P10: Transcendence** | `TLSInterceptor::connect(host, 443)` for HTTPS fetches without libcurl. |
| **P13: Connection Pool** | `TLSInterceptor::TLSConnection` is pooled alongside `TCPConnection`. Session resumption tickets stored for rapid reconnect. |
| **P16: V5 Foundation** | Custom record layer + key schedule architecture is the foundation for HBPoT auth embedding. Handshake extension parsers directly enable CP_Challenge handling. |

---

## Risk Register

| Risk | Impact | Status |
|------|--------|--------|
| TLS 1.3 handshake misimplementation | Critical — broken connections | Tested against OpenSSL s_server |
| AEAD nonce reuse (seq reset) | Critical — crypto break | Strict seq counter, never reset mid-session |
| Certificate validation bypass | High — undetected MITM | Server cert verification via ECDSA |
| Handshake transcript hash mismatch | High — Finished check fails | Constant-time comparison, hash logged |
| Version negotiation fallback | Low — downgrade attack | Reject < TLS 1.2, prefer TLS 1.3 |
| Thread safety in cert cache | Low — race on first request | `std::mutex` on cert cache |
