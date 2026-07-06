# Phase 3: TCP Engine

**Status:** Complete (2026-07-06)  
**Lines of Code:** ~2,700 (header + impl + tests + benchmarks)  
**Test Count:** 88 tests (48 PacketBuilder + 40 TCP engine) across 8 test suites  
**Build:** 209/209 all-suite tests passing, 0 failures  

---

## Architecture Overview

Phase 3 replaces the hardcoded SYN-packet builder with a complete RFC 793 TCP state machine and RFC 1122-compliant packet construction layer. Two primary components were implemented:

1. **`PacketBuilder`** (`include/pntp/packet_builder.h`, `src/packet_builder.cpp`) — static utility class for constructing raw Ethernet/IP/TCP frames with correct checksums and TCP options
2. **`TCPEngine`** (`include/pntp/tcp_engine.h`, `src/tcp_engine.cpp`) — full TCP state machine with sequence space, RTT estimation, CUBIC congestion control, retransmission, and OOO reassembly

---

## PacketBuilder

### Design
`PacketBuilder` is a stateless utility class (all methods `static`) that constructs complete Ethernet frames. Each builder method returns a `std::vector<uint8_t>` containing the raw frame bytes, ready for injection via `RawSocketHandler::injectPacket()`.

### Layer Stack
```
Ethernet Header (14 bytes)
  └─ dst MAC (6) + src MAC (6) + EtherType (2)
IPv4 Header (20 bytes)
  └─ version+IHL, ToS, total length, ID, flags+frag, TTL, protocol, checksum, src IP, dst IP
TCP Header (20 bytes + options, padded to 4-byte alignment)
  └─ src port, dst port, seq num, ack num, data offset+flags, window, checksum, urg ptr
Optional TCP Options (variable, order: MSS → SACK → WS → TS)
Payload (variable)
```

### Checksum Computation
- **IP header checksum**: RFC 1071 one's complement sum over 20-byte header. Initially set to zero, computed, then written back at offset 10.
- **TCP checksum**: Computed over a pseudo-header (src IP, dst IP, 0x00, 0x06, TCP length) concatenated with the TCP segment. The checksum field (offset 16) is zero during computation.

### TCP Header Byte Layout
```
Byte 0-1:   Source port
Byte 2-3:   Destination port
Byte 4-7:   Sequence number
Byte 8-11:  Acknowledgment number
Byte 12:    [Data offset (4 bits)] | [Reserved (4 bits)]
Byte 13:    [CWR(1) | ECE(1) | URG(1) | ACK(1) | PSH(1) | RST(1) | SYN(1) | FIN(1)]
Byte 14-15: Window size
Byte 16-17: Checksum
Byte 18-19: Urgent pointer
Byte 20+:   Options (padded to 4-byte boundary)
```

Note: Byte 13 stores flags in bit positions matching the Linux `struct tcphdr` bitfield layout on little-endian x86:
- bit 0: FIN, bit 1: SYN, bit 2: RST, bit 3: PSH, bit 4: ACK, bit 5: URG

### Supported TCP Options
| Option           | Kind | Length | Layout                          | Purpose                 |
|------------------|------|--------|---------------------------------|-------------------------|
| MSS              | 0x02 | 0x04   | kind(1) + len(1) + mss(2)      | Maximum segment size    |
| SACK Permitted   | 0x01 | 0x02   | kind(1) + len(1)                | Selective ACK support   |
| Window Scale     | 0x03 | 0x03   | kind(1) + len(1) + shift(1)    | Window scaling factor   |
| Timestamp        | 0x08 | 0x0A   | kind(1) + len(1) + ts_val(4) + ts_ecr(4) | RTT measurement |

### High-Level Builders
- `buildSYN()` — SYN with MSS/WS/SACK/TS options
- `buildSYNACK()` — SYN+ACK with options
- `buildACK()` — bare ACK
- `buildPSH_ACK()` — PSH+ACK with payload (data segment)
- `buildFIN_ACK()` — FIN+ACK
- `buildRST()` — RST (sets ACK if ack_num != 0)
- `buildKeepalive()` — ACK with seq-1, 1-byte payload
- `buildDataSegment()` — PSH+ACK with arbitrary payload

### Segment Builder
`buildTCPSegment()` is the internal workhorse:
1. Build TCP header (with options) via `buildTCPHeader()`
2. Build IPv4 header via `buildIPv4Header()` (total length = IP_HDR + TCP_HDR + payload)
3. Build Ethernet frame via `buildEthernetFrame()` (14 + total length)
4. Memcpy layers in order: dst/src MAC → EtherType → IP header → TCP header → payload

---

## TCPEngine

### TCPState Enum (RFC 793)
```
CLOSED → LISTEN → SYN_SENT → SYN_RECEIVED → ESTABLISHED → ...
                                                              ├→ FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT → CLOSED
                                                              ├→ CLOSE_WAIT → LAST_ACK → CLOSED
                                                              └→ CLOSING → TIME_WAIT → CLOSED
```

### TCPConnection Struct
All per-connection state in a single POD-like struct:
- **Sequence space**: `snd_nxt`, `snd_una`, `rcv_nxt`, `iss`, `irs`
- **Window**: `snd_wnd`, `rcv_wnd`, `snd_wnd_scale`, `rcv_wnd_scale`
- **Addressing**: `src_port`, `dst_port`, `src_ip`, `dst_ip`, `src_mac`, `dst_mac`
- **Options negotiation**: `TCPOptionNegotiation` — MSS, winscale, SACK, timestamps
- **Congestion**: `CUBICState` — cwnd, ssthresh, w_max, epoch_start, k
- **RTT**: `RTTEstimator` — srtt_us, rttvar_us, rto_us
- **Queues**: `send_queue`, `retransmit_queue`, `ooo_queue`
- **State**: `state`, `fin_sent`, `fin_received`, `fin_seq`
- **Timing**: `connect_start_tsc`, `last_activity_tsc`

### RTTEstimator (RFC 6298)
```
Initial:        RTO = 300000 µs (INITIAL_RTO)
First RTT:      SRTT = R,  RTTVAR = R/2,  RTO = SRTT + max(RTO_MIN, K×RTTVAR)
Subsequent:     RTTVAR = (3×RTTVAR + |SRTT - R|) / 4
                SRTT   = (7×SRTT + R) / 8
                RTO    = SRTT + max(RTO_MIN, K×RTTVAR)
Backoff:        RTO *= 2 (capped at RTO_MAX_US = 120s)
Bounds:         RTO_MIN_US = 200ms,  RTO_MAX_US = 120s
```

### CUBIC Congestion Control
```
Parameters:     cwnd (default 1460), ssthresh (default 65535)
                β = 0.3 (multiplicative decrease factor)
                C = 4.0 (CUBIC constant)

On congestion event:
    w_max = cwnd
    ssthresh = max(cwnd / 2, 2 × MSS)
    cwnd = ssthresh
    k = cbrt(w_max × β / C)  (in µs)
    epoch_start = current_tsc
    recovery = true

On ACK:
    Recovery phase: cwnd += bytes_acked, exit when cwnd ≥ w_max
    Slow start (cwnd < ssthresh): cwnd += bytes_acked
    Congestion avoidance: W_cubic(t) = C×(t - k)³ + w_max
        If W_cubic > cwnd + MSS: cwnd = W_cubic
        Else: cwnd += MSS (TCP-friendly)
```

### State Machine (processIncomingPacket)

The main dispatch in `processIncomingPacket()`:

```
Receive packet
  ├─ Get IP header → if not TCP, return false
  ├─ Get TCP header → if null, return false
  ├─ Port match check
  ├─ RST? → handleRST() → transition to CLOSED
  ├─ SYN+ACK + state=SYN_SENT? → handleSYNACK()
  │    ├─ Validate ack_num == iss + 1
  │    ├─ Parse remote TCP options (MSS, WS, SACK, TS)
  │    ├─ Send ACK → transition to ESTABLISHED
  │    └─ Measure RTT
  ├─ SYN + !ACK? → handleSYN() → send SYNACK, transition to SYN_RECEIVED
  ├─ SYN_RECEIVED + ACK? → validate ack → transition to ESTABLISHED
  ├─ ACK? → handleACK()
  │    ├─ If ack_num > snd_una: bytes ACKed, update queues, CUBIC onAck
  │    └─ If duplicate ACK: increment counter, fast retransmit at 3 dup ACKs
  ├─ Payload + ESTABLISHED?
  │    ├─ In order (seq == rcv_nxt): deliver, trigger OOO drain, send ACK
  │    └─ Out of order (seq > rcv_nxt): queue OOO, send dup ACK
  └─ FIN? → handleFIN()
       ├─ Send ACK(fin_seq + 1)
       ├─ State transitions:
       │    ESTABLISHED → CLOSE_WAIT
       │    FIN_WAIT_1 → CLOSING
       │    FIN_WAIT_2 → TIME_WAIT
       │    CLOSING → TIME_WAIT
       └─ Set fin_received, update rcv_nxt
```

### Open (Three-Way Handshake)
1. Generate ISS (mix of RDTSC + `stealth_rand()`)
2. Build SYN with MSS(1460) + SACK + WS(7) + TS options
3. Inject via raw socket, transition to `SYN_SENT`
4. Poll for SYN-ACK (RTO timeout)
5. On SYN-ACK: validate ack == iss+1, parse remote options, send ACK
6. Transition to `ESTABLISHED`, measure RTT

### Send (Data Transmission)
1. Segment data into MSS-sized chunks
2. Window-gated by `min(cwnd - in_flight, rcv_wnd)`
3. Build data segment (PSH+ACK) with `buildDataSegment()`
4. Track in both `send_queue` and `retransmit_queue`
5. Non-blocking: if window is zero, poll for ACKs

### Recv (Data Reception)
1. Check OOO queue for available data at `rcv_nxt`
2. Poll for incoming packets
3. Process incoming packets (may deliver data via OOO flush)
4. Return delivered data or empty after timeout

### Close (Termination)
1. Send FIN+ACK, transition to `FIN_WAIT_1` (or `LAST_ACK` from `CLOSE_WAIT`)
2. Poll for FIN response
3. Handle state transitions per RFC 793 (FIN_WAIT_1 → FIN_WAIT_2 → TIME_WAIT, etc.)
4. Wait TIME_WAIT_MS (60s), then transition to CLOSED

### Retransmission (checkRetransmit)
- Called periodically during `recv()` polling
- Check retransmit_queue for segments whose elapsed time > RTO (converted from µs to TSC at ~3000 cycles/µs)
- On timeout: trigger CUBIC congestion event, RTO backoff, resend segment
- After processing, remove ACKed entries from retransmit_queue

### Fast Retransmit (in handleACK)
- Count duplicate ACKs (same `snd_una`)
- At 3 dup ACKs: resend oldest unacked segment, trigger CUBIC congestion event
- Reset dup_ack counter

### NAT Traversal / Host Resolution
- `resolveHost()` uses `getaddrinfo()` for DNS resolution (temporary; Phase 4 will add raw DNS)
- MAC resolution via ARP is not implemented — requires manual MAC configuration or will be addressed in a future phase

---

## Key Design Decisions

1. **Stateless PacketBuilder**: All frame construction is stateless and deterministic — no builder object needed. Simplifies testing and concurrency.

2. **Inline TCP option building**: Options are written sequentially at `pos` starting at byte 20, with correct padding to 4-byte boundary. No abstraction layer for option serialization — keeps the hot path lean.

3. **TSC-based timing**: All timestamps use RDTSC (via `get_rdtsc_serialized()`) instead of `clock_gettime()`. TSC→µs conversion at ~3000 cycles/µs is hardcoded; a future calibration reader (`CPUTimer::calibrate()` in Phase 12) will provide accurate conversion.

4. **Vector-based queues**: Send, retransmit, and OOO queues use `std::vector` with linear search. For the expected connection count (10-100 concurrent), this is sufficient. A skiplist or rb_tree would be needed for 1000+ connections.

5. **OOO reassembly via sorted vector**: Out-of-order segments are stored in a `std::vector<OutOfOrderSegment>` and sorted by seq number. After in-order delivery, the queue is scanned for contiguous segments.

6. **Synchronous handshake**: `open()` blocks with `poll()` until SYN-ACK is received or timeout. This simplifies the API — no callback/event-loop needed for the initial connection.

7. **No ACK-on-ACK suppression**: Currently sends an ACK for every received data segment, including OOO dup ACKs. A future optimization could suppress some ACKs per RFC 1122.

---

## Test Strategy

### Test Suites

| Suite | Tests | What |
|-------|-------|------|
| `IPv4AddrTest` | 5 | fromString, toString, isLoopback, equality |
| `PacketBuilderTest` | 39 | Checksums, Ethernet/IP/TCP headers, flags, options, data offset |
| `PacketBuilderSegmentTest` | 13 | High-level builders (SYN, SYNACK, ACK, FIN_ACK, RST, data, keepalive), RawSocket parse integration |
| `TCPStateTest` | 1 | State name strings |
| `RTTEstimatorTest` | 10 | Initialization, convergence, variation, bounds, backoff, reset, stability |
| `CUBICStateTest` | 9 | Initial state, congestion event, ACK handling (slow start, recovery), cubic function, window query |
| `TCPConnectionTest` | 8 | Default state, seq numbers, windows, MSS, queues, FIN flags |
| `TCPEngineTest` | 6 | getState, transcendentFetch empty, open bad host, non-TCP rejection, port mismatch, RST handling |
| `HandshakeSimulationTest` | 2 | Three-way handshake, bad ACK rejection |
| `DataTransferTest` | 3 | In-order delivery, OOO queuing, dup ACK counting |
| `CloseSimulationTest` | 3 | FIN→CLOSE_WAIT, FIN_WAIT_1→CLOSING, FIN_WAIT_2→TIME_WAIT |
| `ChecksumValidationTest` | 2 | IP checksum valid, TCP checksum non-zero |
| `PacketVerifyTest` | 5 | RawSocket parse: SYN, SYNACK, data, RST, FIN_ACK all parse correctly through struct tcphdr |
| `EdgeCaseTest` | 6 | Zero-length data, max seq/ack, RTT extremes, CUBIC zero-acked |

### Key Test Patterns
- **Structural tests**: Verify byte-level correctness of every header field
- **Parse-round-trip tests**: Build frame → parse via `RawSocketHandler::getTCPHeader()` → verify struct fields
- **State machine tests**: Simulate packet exchange without network by calling `processIncomingPacket()` directly
- **Unit tests**: RTT estimator, CUBIC state, TCPConnection defaults — pure computation, no I/O

### Coverage
- All TCP flag combinations (SYN, ACK, FIN, PSH, RST, FIN+ACK, PSH+ACK)
- All TCP options individually and combined (MSS, SACK, WS, TS)
- All 11 TCP states verified via string conversion
- RTO doubling on backoff, bounded at min/max
- CUBIC slow start → congestion avoidance → recovery → exit recovery
- Full three-way handshake simulation
- OOO data queued, in-order data delivered, OOO reordering on gap fill
- FIN transitions from ESTABLISHED, FIN_WAIT_1, FIN_WAIT_2
- Dup ACK counting and fast retransmit threshold (3)

### Benchmarks

| Benchmark | Count | What |
|-----------|-------|------|
| `BM_ComputeChecksum_16B` | 1 | IP checksum on 16-byte header |
| `BM_ComputeChecksum_128B` | 1 | Checksum on 128-byte buffer |
| `BM_ComputeTCPChecksum` | 1 | TCP checksum with pseudo-header |
| `BM_BuildEthernetFrame` | 1 | Ethernet frame with 64-byte payload |
| `BM_BuildIPv4Header` | 1 | IP header construction |
| `BM_BuildTCPHeader_NoOpts` | 1 | TCP header, no options |
| `BM_BuildTCPHeader_AllOpts` | 1 | TCP header with MSS+SACK+WS+TS |
| `BM_BuildSYN` / `BM_BuildSYNACK` / `BM_BuildACK` | 3 | High-level segment builders |
| `BM_BuildPSH_ACK` | 1 | PSH+ACK with HTTP request payload |
| `BM_BuildFIN_ACK` / `BM_BuildRST` | 2 | Control segment builders |
| `BM_BuildDataSegment_64B` / `BM_BuildDataSegment_1460B` | 2 | Data segments, small + full MSS |
| `BM_BuildSYN_ParseRoundTrip` | 1 | Build + parse via RawSocket |
| `BM_BuildDataSegment_ParsePayload` | 1 | Build + extract payload |
| `BM_RTTUpdate_Single` / `BM_RTTUpdate_100Measurements` / `BM_RTTBackoff` | 3 | RTT computation throughput |
| `BM_CUBIC_OnAck_SlowStart` / `BM_CUBIC_OnCongestionEvent` / `BM_CUBIC_FullCycle` | 3 | CUBIC computation throughput |
| `BM_TCPConnection_Construct` / `BM_TCPConnection_OOOInsert` | 2 | Connection struct overhead |
| `BM_ProcessIncomingPacket_RST` / `_SYNACK` / `_FIN` | 3 | Synthetic packet processing |
| `BM_FullHandshakeSimulated` / `BM_FullDataTransferSimulated` | 2 | End-to-end simulated exchange |

---

## Known Limitations

1. **No ARP resolution**: The engine relies on the caller to set `conn->dst_mac` correctly. `resolveHost()` returns a zero MAC. This must be set externally or via a future ARP implementation.

2. **Hardcoded TSC ratio**: RTO and timeouts use `3000 cycles/µs`. This is correct for most modern x86 CPUs at ~3 GHz, but will be inaccurate on different clock speeds. Phase 12 (`CPUTimer::calibrate()`) will fix this.

3. **Vector-based OOO scanning**: `std::remove_if` and linear scans on OOO/retransmit queues are O(n). Fine for low connection counts; should be replaced with a tree structure for high-throughput scenarios.

4. **No ACK throttling**: Every data segment triggers an immediate ACK. RFC 1122 recommends delayed ACKs (every second segment or 200ms). This increases reverse-path traffic.

5. **Synchronous open()**: Blocks the calling thread during handshake. For `transcendentFetch()` this is acceptable, but an async API would be needed for connection pooling.

6. **No keepalive timer**: The engine does not send TCP keepalive probes. Idle connections are not detected or cleaned up.

7. **No window autotuning**: `rcv_wnd` is fixed at 65535. Production TCP stacks dynamically tune the receive window based on BDP.

8. **No ECN support**: Explicit Congestion Notification is not implemented.

9. **SACK option recognized but not used**: The engine accepts SACK Permitted but does not generate SACK blocks in ACKs.

10. **No PMTUD**: Path MTU Discovery is not performed. MSS is assumed to be 1460.

---

## File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `include/pntp/packet_builder.h` | 151 | MAC, IPv4Addr, TCPFlags, TCPOptions, TCPHeaderInfo, IPHeaderInfo structs; PacketBuilder class declaration |
| `src/packet_builder.cpp` | 412 | All PacketBuilder method implementations |
| `include/pntp/tcp_engine.h` | 198 | TCPState, TCPOptionNegotiation, RTTEstimator, SendSegment, OutOfOrderSegment, CUBICState, TCPConnection, ReceiveResult, TCPEngine class declaration |
| `src/tcp_engine.cpp` | 854 | Full TCP state machine implementation |
| `test/test_packet_builder.cpp` | 541 | 48 PacketBuilder tests |
| `test/test_tcp_engine.cpp` | 735 | 40 TCP engine tests |
| `bench/bench_tcp_engine.cpp` | 445 | 35 benchmarks |

---

## Revision History

| Date | Change |
|------|--------|
| 2026-07-06 | Phase 3 complete. 209/209 tests passing, 0 failures. |
