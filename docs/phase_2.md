# Phase 2: Raw Socket Maturity

**Status:** Complete  
**Description:** Zero-copy PACKET_MMAP raw socket handler with BPF filtering, promiscuous mode, packet injection, stateless header parsing, and ring-based packet capture.

---

## Architecture Overview

`RawSocketHandler` wraps a Linux `AF_PACKET`, `SOCK_RAW` socket and provides a production-oriented capture/injection API. On init, it resolves the interface index via `SIOCGIFINDEX`, opens a raw socket bound to `ETH_P_ALL`, and attempts to set up a PACKET_MMAP v2 ring buffer (16 blocks × 2048-byte frames by default). If the ring allocation fails (e.g., old kernel, insufficient memory), it degrades gracefully to a heap-based fallback using `recvfrom()`.

Packets are acquired zero-copy from the ring via `acquirePacket()`, which returns a `PacketView` (a lightweight non-owning span). After processing, the caller calls `releasePacket()` to return the frame to the kernel. An `__sync_synchronize()` barrier ensures proper memory ordering between user and kernel space. The design is single-threaded internally — no worker threads are spawned — but the caller may use the handler from one thread at a time.

Header parsing helpers (`getIPv4Header`, `getTCPHeader`, `getUDPHeader`, `getPayload`) are static methods that perform byte-level offset arithmetic on raw Ethernet frames. They assume a 14-byte Ethernet header and validate bounds before returning pointers into the original `PacketView` data.

BPF filters are constructed as static factory methods that return `std::vector<struct sock_filter>` programs. These are attached via `setsockopt(SO_ATTACH_FILTER)` with a `sock_fprog` structure — no separate compilation step is needed. Promiscuous mode, fanout groups, and receive timeouts are all configured through `setsockopt` calls on the raw socket.

Packet injection uses `sendto()` with a `sockaddr_ll` target, writing raw frames at Layer 2.

---

## File Reference

| File | Lines | Purpose |
|------|-------|---------|
| `include/pntp/raw_socket_handler.h` | 108 | Class declaration: `RawSocketHandler`, `PacketView`, `QueueStats`, `QueueStatsSnapshot` |
| `src/raw_socket_handler.cpp` | 435 | Full implementation — all methods, no stubs |
| `src/test_raw_socket.cpp` | 95 | Standalone test utility: 5-second capture on `eth0`/`lo` with live output |
| `test/test_raw_socket_handler.cpp` | 425 | Google Test suite: 31 tests across 5 suites |
| `bench/bench_raw_socket.cpp` | 132 | Google Benchmark: 8 benchmarks for header parsing, BPF construction, acquire/release, PacketView construction |

---

## Class: RawSocketHandler

### Constructor / Destructor

| Method | Description |
|--------|-------------|
| `RawSocketHandler()` | Initializes all members to zero/null defaults. Does not open a socket. |
| `~RawSocketHandler()` | Calls `teardownRing()` if ring is active, then `close(sock_fd)` if valid. |
| `RawSocketHandler(const RawSocketHandler&) = delete` | Non-copyable (RAII — owns socket fd and mmap). |
| `RawSocketHandler& operator=(const RawSocketHandler&) = delete` | Non-copyable. |

### Public Methods

| Signature | Description |
|-----------|-------------|
| `bool init(const std::string& interface_name)` | Resolves interface index via `SIOCGIFINDEX`, opens raw socket, tries PACKET_MMAP ring (default: 16 blocks × 2048B frames). Falls back to heap mode on failure. |
| `bool setRingParams(uint32_t block_num, uint32_t frame_size)` | Stores ring parameters; takes effect on the *next* `init()` call. |
| `PacketView acquirePacket()` | Returns next available packet. Ring mode: reads `tpacket2_hdr` with `TP_STATUS_USER`. Heap mode: `recvfrom(MSG_DONTWAIT)`. Returns empty `PacketView` if no packet ready. |
| `void releasePacket(const PacketView& pkt)` | Returns frame to kernel. Sets `tp_status = TP_STATUS_KERNEL`, advances `consumer_idx` circularly. No-op in heap mode or if `pkt` is empty. Includes `__sync_synchronize()` barrier. |
| `bool attachBPF(const std::vector<struct sock_filter>& filter)` | Attaches BPF program via `setsockopt(SO_ATTACH_FILTER)`. |
| `bool setPromiscuous(bool enable)` | Adds/drops `PACKET_MR_PROMISC` membership via `setsockopt`. |
| `bool setFanoutGroup(uint16_t group_id, int type)` | Joins fanout group via `PACKET_FANOUT`. `type` is packed with `group_id` into a `uint32_t`. |
| `bool setTimeoutMs(uint64_t ms)` | Sets `SO_RCVTIMEO` as a `timeval`. |
| `bool injectPacket(const uint8_t* data, size_t len)` | Sends raw frame via `sendto()` with `sockaddr_ll` on bound interface. Returns `true` only if all bytes were sent. |
| `QueueStatsSnapshot getStats() const` | Polls kernel drop counter via `getsockopt(PACKET_STATISTICS)` (non-const internally), then returns a `QueueStatsSnapshot`. |
| `bool usingRing() const` | Returns `!use_heap_mode`. |
| `bool isInitialized() const` | Returns `sock_fd >= 0`. |
| `int getFd() const` | Returns raw socket file descriptor. |

### Static Public Methods (Header Parsing & BPF Factories)

| Signature | Description |
|-----------|-------------|
| `static const iphdr* getIPv4Header(const PacketView& pkt)` | Returns IP header at offset 14 (past Ethernet). Validates `pkt.len >= 34` and version nibble `0x40`. Returns `nullptr` for non-IPv4/non-IP frames. |
| `static const tcphdr* getTCPHeader(const PacketView& pkt)` | Walks `getIPv4Header`, checks `ip->protocol == IPPROTO_TCP`, computes offset as `14 + ip_ihl*4`. Validates minimum TCP header (20 bytes). |
| `static const udphdr* getUDPHeader(const PacketView& pkt)` | Same pattern for UDP: checks `IPPROTO_UDP`, offset `14 + ip_ihl*4`. Validates minimum 8 bytes. |
| `static PacketView getPayload(const PacketView& pkt, uint8_t protocol)` | TCP: uses `tcp->doff` for header length, `ip->tot_len` for total. UDP: uses `udp->len`. Both clamp to `pkt.len`. Returns empty if `protocol` is not TCP or UDP. |
| `static std::vector<sock_filter> makeBPF_TCPOnly()` | 8-instruction BPF: accept IPv4 TCP only. |
| `static std::vector<sock_filter> makeBPF_UDPOnly()` | 8-instruction BPF: accept IPv4 UDP only. |
| `static std::vector<sock_filter> makeBPF_PortOnly(uint16_t port)` | 11-instruction BPF: accept IPv4 TCP/UDP matching `dst port == port`. |
| `static std::vector<sock_filter> makeBPF_All()` | 1-instruction BPF: accept all (up to 262144 bytes). |

### Private Methods

| Signature | Description |
|-----------|-------------|
| `bool setupRing()` | Configures `TPACKET_V2`, sets `PACKET_RX_RING` via `setsockopt`, `mmap`s the ring with `PROT_READ | PROT_WRITE, MAP_SHARED`. |
| `void teardownRing()` | `munmap`s ring, nulls pointers, resets frame count. |
| `uint8_t* framePtr(uint32_t idx) const` | Computes pointer to frame at index `idx` by decomposing into block index and frame-within-block. |

### Member Variables

| Type | Name | Description |
|------|------|-------------|
| `int` | `sock_fd` | Raw socket fd, `-1` when uninitialized. |
| `int` | `if_index` | Interface index from `SIOCGIFINDEX`. |
| `std::string` | `interface` | Interface name. |
| `void*` | `ring_ptr` | `mmap`-ed ring buffer base, `nullptr` if no ring. |
| `size_t` | `ring_size` | Total ring size in bytes (`block_size * block_num`). |
| `uint32_t` | `ring_block_num` | Number of blocks (default 16). |
| `uint32_t` | `ring_frame_size` | Size per frame (default 2048). |
| `uint32_t` | `ring_frame_nr` | Total frames (`block_num * frames_per_block`). |
| `uint32_t` | `consumer_idx` | Next frame index to read from the ring. |
| `bool` | `use_heap_mode` | `true` when ring setup failed; fallback to `recvfrom`. |
| `uint8_t[65536]` | `heap_buffer` | Stack-allocated receive buffer for heap fallback. |
| `size_t` | `heap_packet_len` | Length of last packet received via heap mode. |
| `QueueStats` | `stats` | Atomic capture/drop/byte counters. |
| `bool` | `bpf_attached` | Tracks whether a BPF filter has been attached. |

---

## Key Implementation Details

### PACKET_MMAP Ring Buffer

- **TPACKET version:** v2 (`TPACKET_V2` via `setsockopt(PACKET_VERSION)`).
- **Default geometry:**
  - `block_num = 16`, `frame_size = 2048`
  - `frame_per_block >= 16` (minimum, computed to fill a page-aligned block)
  - `block_size = page_aligned(frame_size * 16)`
  - `ring_frame_nr = block_num * frames_per_block`
- Ring is allocated via `mmap(MAP_SHARED, sock_fd, offset=0)` after `setsockopt(PACKET_RX_RING)`.
- Frame layout uses `tpacket2_hdr`:
  - `tp_status & TP_STATUS_USER` → frame ready for user; `tp_status = TP_STATUS_KERNEL` → returned to kernel.
  - `tp_mac` offset from frame start to packet data.
  - `tp_snaplen` captures packet length.
  - `TP_STATUS_DROPPED` (ifdef'd) indicates kernel-side drops for this frame.
- `framePtr(idx)` decomposes `idx` into `block_idx` and `frame_in_block`, then computes byte offset in the `mmap` region.
- `releasePacket()` uses `__sync_synchronize()` (GCC barrier) before writing `tp_status` to ensure all packet data reads complete before the kernel takes ownership.

### BPF Filtering

- BPF programs are constructed as `std::vector<struct sock_filter>` arrays using the static factory methods.
- Attached via: `setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &sock_fprog)`.
- `makeBPF_TCPOnly()` (8 instructions): loads EtherType at offset 12, checks for `ETH_P_IP` (0x0800), rejects ARP (0x0806), loads IP protocol at offset 23, checks for `IPPROTO_TCP`.
- `makeBPF_UDPOnly()` (8 instructions): identical pattern with `IPPROTO_UDP`.
- `makeBPF_PortOnly()` (11 instructions): checks EtherType → IPv4, then checks protocol for TCP *or* UDP, loads destination port at offset 36 (14 eth + 20 ip + 2 src port), and matches against the given port.
- `makeBPF_All()` (1 instruction): unconditional accept with snaplen limit of 262144 bytes.
- The handler stores a `bpf_attached` flag but does not track the specific filter.

### Promiscuous Mode

- Implemented via `setsockopt(sock_fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP / PACKET_DROP_MEMBERSHIP)` with a `packet_mreq` struct set to `PACKET_MR_PROMISC`.
- Requires `CAP_NET_ADMIN` (separate from `CAP_NET_RAW`), so may fail even when the socket opens successfully.

### Packet Injection

- Uses `sendto()` with a `sockaddr_ll` target:
  - `sll_family = AF_PACKET`
  - `sll_ifindex = if_index`
  - `sll_protocol = htons(ETH_P_ALL)`
- Returns `true` only when the full `len` bytes are sent (`sent == len`). No fragmentation or checksum offload handling.

### Header Parsing

All header parsers assume a 14-byte Ethernet header (no VLAN tags).

- **`getIPv4Header`**: Returns `iphdr*` at offset 14 if `pkt.len >= 34` and `data[14] & 0xF0 == 0x40` (IPv4). Does **not** validate IP checksum or header length options.
- **`getTCPHeader`**: Requires IPv4 + `ip->protocol == IPPROTO_TCP`. Offset = `14 + ip_ihl*4`. Validates minimum 20 bytes of TCP header.
- **`getUDPHeader`**: Requires IPv4 + `ip->protocol == IPPROTO_UDP`. Offset = `14 + ip_ihl*4`. Validates minimum 8 bytes.
- **`getPayload(TCP)`**: Uses `tcp->doff` (in 32-bit words) for TCP header length and `ip->tot_len` (network byte order) for total IP datagram length. Clamps to `pkt.len`.
- **`getPayload(UDP)`**: Uses `udp->len` for datagram length. Payload starts at `14 + ip_hdr_len + 8`. Clamps to `pkt.len`.

### Threading & Synchronization

- No internal threads are spawned.
- `releasePacket()` uses `__sync_synchronize()` as a full memory barrier before setting `tp_status`.
- `QueueStats` counters use `std::atomic<uint64_t>` with `memory_order_relaxed`.
- The class is **not** thread-safe for concurrent use — callers must serialize access.

---

## Test Strategy

| Suite | Tests | What it validates |
|-------|-------|-------------------|
| `PacketViewTest` | 3 | Default/value/null construction, bool conversion. |
| `HeaderParsingTest` | 10 (fixture) | `getIPv4Header` (valid, ARP reject, too-short), `getTCPHeader` (valid, UDP reject), `getUDPHeader` (valid, TCP reject), `getPayload` TCP/UDP (with/without payload, empty packet). |
| `BPFFactoryTest` | 4 | `makeBPF_All` (1 inst), `makeBPF_TCPOnly` (8 inst, validates first/last instruction), `makeBPF_UDPOnly` (8 inst), `makeBPF_PortOnly` (11 inst). |
| `RawSocketHandlerTest` | 4 | Init failure on nonexistent interface, acquire/release/stats on uninitialized handler (no crash). |
| `RawSocketHandlerRootTest` | 10 (fixture) | Init on `lo`, ring mode, BPF attach (all/TCP), promiscuous on/off, timeout, inject+capture, acquire/release loop, stats, custom ring params, fanout group. Root-gated with `GTEST_SKIP()`. |

**Total: 31 tests across 5 suites.**  
Root tests detect `CAP_NET_RAW` via a probe `socket(AF_PACKET, SOCK_RAW)` and skip with `GTEST_SKIP()` when unavailable. Promiscuous and fanout tests further tolerate `CAP_NET_ADMIN`/kernel limitations with conditional skip.

---

## Benchmarks

| Benchmark | What it measures |
|-----------|------------------|
| `BM_GetIPv4Header` | Time to parse IP header from a synthetic 54-byte TCP packet. |
| `BM_GetTCPHeader` | Time to parse TCP header (walks through IP header first). |
| `BM_GetPayload_TCP` | Time to extract TCP payload from a packet with payload data. |
| `BM_MakeBPF_TCPOnly` | Time to construct the 8-instruction TCP BPF filter vector. |
| `BM_MakeBPF_PortOnly` | Time to construct the 11-instruction port-match BPF filter vector. |
| `BM_AcquireRelease_Empty` | Overhead of acquire+release on an **uninitialized** handler (no syscall). |
| `BM_AcquireRelease_Root` | Acquire+release on `lo` (requires root; skips with error if `CAP_NET_RAW` missing). |
| `BM_PacketView_Construct` | Time to construct a `PacketView` from a 64-byte buffer. |

All benchmarks use `benchmark::DoNotOptimize()` to prevent elimination of dead code. Root-gated benchmarks use `state.SkipWithError()`. The file includes `BENCHMARK_MAIN()` for standalone execution.

---

## Known Limitations

1. **IPv4 only:** `getIPv4Header` rejects non-IPv4 frames; there is no IPv6 header parser.
2. **No checksum validation:** Header parsers do not verify IP/TCP/UDP checksums.
3. **No IP option support:** `ip_ihl` is used but only for offset computation; options in the IP or TCP header are not parsed or validated beyond length checks.
4. **No VLAN tag handling:** Assumes a flat 14-byte Ethernet header; 802.1Q tags (which add 4 bytes) will cause incorrect offsets.
5. **Single-threaded:** No internal locking; the class is not safe for concurrent use.
6. **No send ring:** Only `PACKET_RX_RING` (receive) is set up; injection uses `sendto()` without a TX ring.
7. **TPACKET_V2, not V3:** V3 adds poll-efficient block-level status; re-evaluate if polling overhead becomes a bottleneck.
8. **heap_buffer is stack-allocated:** 65536 bytes lives inside the `RawSocketHandler` object, which may be large for stack-allocated instances.
9. **getPayload(TCP) recomputes IP header:** After `getTCPHeader` returns, `getPayload` calls `getIPv4Header` again — a small redundancy.
10. **No zero-copy injection:** `injectPacket` copies data from user buffer to kernel via `sendto`.

---

## Key Context for Phase 3

Phase 3 (e.g., higher-level protocol handling, session management, or the PNTP time-sync protocol) should rely on:

- **`acquirePacket()` / `releasePacket()`** as the capture loop primitives. The ring mode provides zero-copy capture; if the ring fails, heap mode is a transparent fallback.
- **`getPayload()`** to extract application-layer data after protocol dispatch.
- **BPF filtering** via `attachBPF()` to pre-filter traffic by protocol or port before it reaches user space, reducing wakeups.
- **`getStats()`** to monitor capture health (kernel drops, captured counts) — useful for adaptive rate limiting.
- **`getFd()`** to integrate the raw socket fd into an `epoll`/`poll` loop, replacing the current busy-wait `acquirePacket` pattern.
- **`setFanoutGroup()`** if Phase 3 uses multiple capture threads to spread load across cores.
- **`injectPacket()`** for sending raw response frames, though Phase 3 may need a higher-level send abstraction that handles checksum offload and L2 header construction.

Potential additions for Phase 3:
- IPv6 header parsers
- VLAN tag support (802.1Q, 802.1ad)
- `SO_ATTACH_FILTER` with cBPF → eBPF migration
- `PACKET_TX_RING` for zero-copy injection
- Multi-queue RSS via fanout with PACKET_FANOUT_CPU or PACKET_FANOUT_RND
- Offload callback to set up NIC flow steering (e.g., ethtool ntuple rules)
