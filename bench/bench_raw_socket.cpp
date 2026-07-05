#include "pntp/raw_socket_handler.h"
#include "pntp/pntp_core.h"
#include <benchmark/benchmark.h>
#include <cstring>
#include <vector>

// ── helpers ─────────────────────────────────────────────────────────────

static std::vector<uint8_t> buildTcpPacket() {
    std::vector<uint8_t> buf(54, 0);  // 14 eth + 20 ip + 20 tcp
    size_t off = 0;
    buf[off+12] = 0x08; buf[off+13] = 0x00;  // EtherType IPv4
    off += 14;
    buf[off+0]  = 0x45;                        // version=4, ihl=5
    buf[off+2]  = 0x00; buf[off+3] = 40;      // tot_len = 40
    buf[off+8]  = 64;
    buf[off+9]  = IPPROTO_TCP;
    buf[off+12] = 10; buf[off+14] = 0; buf[off+15] = 1;  // src 10.0.0.1
    buf[off+16] = 10; buf[off+18] = 0; buf[off+19] = 2;  // dst 10.0.0.2
    off += 20;
    buf[off+0]  = 0x1F; buf[off+1] = 0x90;    // src port 8080
    buf[off+2]  = 0x00; buf[off+3] = 0x50;    // dst port 80
    buf[off+12] = 0x50;                        // doff=5
    return buf;
}

// ── header parsing benchmarks ──────────────────────────────────────────

static void BM_GetIPv4Header(benchmark::State& state) {
    auto raw = buildTcpPacket();
    PacketView pv(raw.data(), raw.size());
    for (auto _ : state) {
        auto* ip = RawSocketHandler::getIPv4Header(pv);
        benchmark::DoNotOptimize(ip);
    }
}
BENCHMARK(BM_GetIPv4Header);

static void BM_GetTCPHeader(benchmark::State& state) {
    auto raw = buildTcpPacket();
    PacketView pv(raw.data(), raw.size());
    for (auto _ : state) {
        auto* tcp = RawSocketHandler::getTCPHeader(pv);
        benchmark::DoNotOptimize(tcp);
    }
}
BENCHMARK(BM_GetTCPHeader);

static void BM_GetPayload_TCP(benchmark::State& state) {
    uint8_t payload[] = "HelloPNTPBenchmark";
    size_t ip_tot_len = 20 + 20 + sizeof(payload);
    std::vector<uint8_t> buf(14 + ip_tot_len, 0);
    size_t off = 0;
    buf[off+12] = 0x08; buf[off+13] = 0x00;
    off += 14;
    buf[off+0]  = 0x45;
    buf[off+2]  = static_cast<uint8_t>((ip_tot_len >> 8) & 0xFF);
    buf[off+3]  = static_cast<uint8_t>( ip_tot_len       & 0xFF);
    buf[off+8]  = 64;
    buf[off+9]  = IPPROTO_TCP;
    buf[off+12] = 10; buf[off+14] = 0; buf[off+15] = 1;
    buf[off+16] = 10; buf[off+18] = 0; buf[off+19] = 2;
    off += 20;
    buf[off+12] = 0x50;
    off += 20;
    memcpy(buf.data() + off, payload, sizeof(payload));

    PacketView pv(buf.data(), buf.size());
    for (auto _ : state) {
        auto p = RawSocketHandler::getPayload(pv, IPPROTO_TCP);
        benchmark::DoNotOptimize(p);
    }
}
BENCHMARK(BM_GetPayload_TCP);

// ── BPF factory benchmarks ────────────────────────────────────────────

static void BM_MakeBPF_TCPOnly(benchmark::State& state) {
    for (auto _ : state) {
        auto f = RawSocketHandler::makeBPF_TCPOnly();
        benchmark::DoNotOptimize(f);
    }
}
BENCHMARK(BM_MakeBPF_TCPOnly);

static void BM_MakeBPF_PortOnly(benchmark::State& state) {
    for (auto _ : state) {
        auto f = RawSocketHandler::makeBPF_PortOnly(443);
        benchmark::DoNotOptimize(f);
    }
}
BENCHMARK(BM_MakeBPF_PortOnly);

// ── acquire+release (with root) ────────────────────────────────────────

static void BM_AcquireRelease_Empty(benchmark::State& state) {
    RawSocketHandler handler;
    // uninitialized handler: acquire returns empty, release is no-op
    for (auto _ : state) {
        auto pkt = handler.acquirePacket();
        benchmark::DoNotOptimize(pkt);
        handler.releasePacket(pkt);
    }
}
BENCHMARK(BM_AcquireRelease_Empty);

static void BM_AcquireRelease_Root(benchmark::State& state) {
    RawSocketHandler handler;
    if (!handler.init("lo")) {
        state.SkipWithError("Need CAP_NET_RAW for acquire+release bench");
        return;
    }
    for (auto _ : state) {
        auto pkt = handler.acquirePacket();
        benchmark::DoNotOptimize(pkt);
        handler.releasePacket(pkt);
    }
}
BENCHMARK(BM_AcquireRelease_Root);

// ── PacketView operations ─────────────────────────────────────────────

static void BM_PacketView_Construct(benchmark::State& state) {
    uint8_t data[64];
    for (auto _ : state) {
        PacketView pv(data, 64);
        benchmark::DoNotOptimize(pv);
    }
}
BENCHMARK(BM_PacketView_Construct);

BENCHMARK_MAIN();
