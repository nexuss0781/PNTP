#include "pntp/packet_builder.h"
#include "pntp/tcp_engine.h"
#include "pntp/raw_socket_handler.h"
#include "pntp/pntp_core.h"
#include <benchmark/benchmark.h>

// ── PacketBuilder: checksum benchmarks ────────────────────────────────

static void BM_ComputeChecksum_16B(benchmark::State& state) {
    uint16_t data[8] = {0x4500, 0x003C, 0x0001, 0x0000, 0x4006, 0x0000, 0xC0A8, 0x0101};
    for (auto _ : state) {
        uint16_t ck = PacketBuilder::computeChecksum(data, sizeof(data));
        benchmark::DoNotOptimize(ck);
    }
}
BENCHMARK(BM_ComputeChecksum_16B);

static void BM_ComputeChecksum_128B(benchmark::State& state) {
    uint16_t data[64];
    for (auto& d : data) d = 0xABCD;
    for (auto _ : state) {
        uint16_t ck = PacketBuilder::computeChecksum(data, sizeof(data));
        benchmark::DoNotOptimize(ck);
    }
}
BENCHMARK(BM_ComputeChecksum_128B);

static void BM_ComputeTCPChecksum(benchmark::State& state) {
    uint8_t tcp[20] = {};
    for (auto _ : state) {
        uint16_t ck = PacketBuilder::computeTCPChecksum(tcp, 20, 0x0A000001, 0x0A000002);
        benchmark::DoNotOptimize(ck);
    }
}
BENCHMARK(BM_ComputeTCPChecksum);

// ── PacketBuilder: frame construction benchmarks ──────────────────────

static void BM_BuildEthernetFrame(benchmark::State& state) {
    MAC dst = MAC::broadcast();
    MAC src = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    uint8_t payload[64];
    memset(payload, 0xAB, sizeof(payload));
    for (auto _ : state) {
        auto frame = PacketBuilder::buildEthernetFrame(dst, src, 0x0800, payload, sizeof(payload));
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildEthernetFrame);

static void BM_BuildIPv4Header(benchmark::State& state) {
    for (auto _ : state) {
        auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0xC0A80101, 0xC0A80102, 60);
        benchmark::DoNotOptimize(hdr);
    }
}
BENCHMARK(BM_BuildIPv4Header);

static void BM_BuildTCPHeader_NoOpts(benchmark::State& state) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.seq_num = 1000;
    info.flags.syn = true;
    info.window = 65535;
    for (auto _ : state) {
        auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
        benchmark::DoNotOptimize(hdr);
    }
}
BENCHMARK(BM_BuildTCPHeader_NoOpts);

static void BM_BuildTCPHeader_AllOpts(benchmark::State& state) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.seq_num = 1000;
    info.flags.syn = true;
    info.window = 65535;
    info.options.mss = 1460;
    info.options.sack_permitted = true;
    info.options.window_scale = 7;
    info.options.has_timestamp = true;
    info.options.ts_val = 12345;
    info.options.ts_ecr = 67890;
    for (auto _ : state) {
        auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
        benchmark::DoNotOptimize(hdr);
    }
}
BENCHMARK(BM_BuildTCPHeader_AllOpts);

// ── PacketBuilder: high-level segment builders ────────────────────────

static MAC bench_dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
static MAC bench_src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};

static void BM_BuildSYN(benchmark::State& state) {
    for (auto _ : state) {
        auto frame = PacketBuilder::buildSYN(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80, 1000);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildSYN);

static void BM_BuildSYNACK(benchmark::State& state) {
    for (auto _ : state) {
        auto frame = PacketBuilder::buildSYNACK(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80, 2000, 1001);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildSYNACK);

static void BM_BuildACK(benchmark::State& state) {
    for (auto _ : state) {
        auto frame = PacketBuilder::buildACK(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80, 2000, 1001);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildACK);

static void BM_BuildPSH_ACK(benchmark::State& state) {
    uint8_t data[] = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    for (auto _ : state) {
        auto frame = PacketBuilder::buildPSH_ACK(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80,
                                                  2000, 1001, data, sizeof(data) - 1);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildPSH_ACK);

static void BM_BuildFIN_ACK(benchmark::State& state) {
    for (auto _ : state) {
        auto frame = PacketBuilder::buildFIN_ACK(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80, 5000, 6000);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildFIN_ACK);

static void BM_BuildRST(benchmark::State& state) {
    for (auto _ : state) {
        auto frame = PacketBuilder::buildRST(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80, 5000, 0);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildRST);

static void BM_BuildDataSegment_64B(benchmark::State& state) {
    uint8_t data[64];
    memset(data, 0x42, sizeof(data));
    for (auto _ : state) {
        auto frame = PacketBuilder::buildDataSegment(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80,
                                                     2000, 1001, data, sizeof(data), true, 65535);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildDataSegment_64B);

static void BM_BuildDataSegment_1460B(benchmark::State& state) {
    uint8_t data[1460];
    memset(data, 0x42, sizeof(data));
    for (auto _ : state) {
        auto frame = PacketBuilder::buildDataSegment(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80,
                                                     2000, 1001, data, sizeof(data), true, 65535);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_BuildDataSegment_1460B);

// ── Full build+parse round-trip ───────────────────────────────────────

static void BM_BuildSYN_ParseRoundTrip(benchmark::State& state) {
    for (auto _ : state) {
        auto frame = PacketBuilder::buildSYN(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80, 1000);
        PacketView pkt(frame.data(), frame.size());
        auto* ip = RawSocketHandler::getIPv4Header(pkt);
        auto* tcp = RawSocketHandler::getTCPHeader(pkt);
        benchmark::DoNotOptimize(ip);
        benchmark::DoNotOptimize(tcp);
    }
}
BENCHMARK(BM_BuildSYN_ParseRoundTrip);

static void BM_BuildDataSegment_ParsePayload(benchmark::State& state) {
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
    for (auto _ : state) {
        auto frame = PacketBuilder::buildDataSegment(bench_dst, bench_src, 0xC0A80101, 0xC0A80102, 12345, 80,
                                                     2000, 1001, data, sizeof(data), true, 65535);
        PacketView pkt(frame.data(), frame.size());
        auto payload = RawSocketHandler::getPayload(pkt, IPPROTO_TCP);
        benchmark::DoNotOptimize(payload);
    }
}
BENCHMARK(BM_BuildDataSegment_ParsePayload);

// ── RTT Estimator benchmarks ──────────────────────────────────────────

static void BM_RTTUpdate_Single(benchmark::State& state) {
    for (auto _ : state) {
        RTTEstimator rtt;
        rtt.update(10000);
        benchmark::DoNotOptimize(rtt);
    }
}
BENCHMARK(BM_RTTUpdate_Single);

static void BM_RTTUpdate_100Measurements(benchmark::State& state) {
    for (auto _ : state) {
        RTTEstimator rtt;
        for (int i = 0; i < 100; ++i) {
            rtt.update(8000 + (i % 10) * 500);
        }
        benchmark::DoNotOptimize(rtt);
    }
}
BENCHMARK(BM_RTTUpdate_100Measurements);

static void BM_RTTBackoff(benchmark::State& state) {
    for (auto _ : state) {
        RTTEstimator rtt;
        rtt.update(10000);
        for (int i = 0; i < 10; ++i) rtt.backoff();
        benchmark::DoNotOptimize(rtt);
    }
}
BENCHMARK(BM_RTTBackoff);

// ── CUBIC congestion control benchmarks ───────────────────────────────

static void BM_CUBIC_OnAck_SlowStart(benchmark::State& state) {
    for (auto _ : state) {
        CUBICState cubic;
        for (int i = 0; i < 100; ++i) {
            cubic.onAck(1460, 1000000ULL + i * 10000);
        }
        benchmark::DoNotOptimize(cubic);
    }
}
BENCHMARK(BM_CUBIC_OnAck_SlowStart);

static void BM_CUBIC_OnCongestionEvent(benchmark::State& state) {
    for (auto _ : state) {
        CUBICState cubic;
        cubic.cwnd = 50000;
        cubic.onCongestionEvent(1000000);
        benchmark::DoNotOptimize(cubic);
    }
}
BENCHMARK(BM_CUBIC_OnCongestionEvent);

static void BM_CUBIC_FullCycle(benchmark::State& state) {
    for (auto _ : state) {
        CUBICState cubic;
        cubic.ssthresh = 65535;
        cubic.cwnd = 4380;
        for (int i = 0; i < 200; ++i) {
            cubic.onAck(1460, 1000000ULL + i * 5000);
        }
        cubic.onCongestionEvent(2000000ULL);
        for (int i = 0; i < 50; ++i) {
            cubic.onAck(1460, 2000000ULL + i * 5000);
        }
        benchmark::DoNotOptimize(cubic);
    }
}
BENCHMARK(BM_CUBIC_FullCycle);

// ── TCPConnection struct benchmarks ───────────────────────────────────

static void BM_TCPConnection_Construct(benchmark::State& state) {
    for (auto _ : state) {
        TCPConnection conn;
        benchmark::DoNotOptimize(conn);
    }
}
BENCHMARK(BM_TCPConnection_Construct);

static void BM_TCPConnection_OOOInsert(benchmark::State& state) {
    for (auto _ : state) {
        TCPConnection conn;
        conn.rcv_nxt = 1000;
        for (int i = 0; i < 10; ++i) {
            uint32_t seq = 1000 + (i + 1) * 100;
            std::vector<uint8_t> data(100, 0x42);
            conn.ooo_queue.push_back({seq, std::move(data)});
        }
        benchmark::DoNotOptimize(conn);
    }
}
BENCHMARK(BM_TCPConnection_OOOInsert);

// ── ProcessIncomingPacket: synthetic packet benchmarks ─────────────────

static void BM_ProcessIncomingPacket_RST(benchmark::State& state) {
    TCPEngine engine;
    engine.setLocalMAC({{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}});
    engine.setLocalIP(0xC0A80101);

    TCPConnection conn;
    conn.state = TCPState::ESTABLISHED;
    conn.src_port = 12345;
    conn.dst_port = 80;
    conn.src_ip = 0xC0A80101;
    conn.dst_ip = 0xC0A80102;

    auto frame = PacketBuilder::buildRST(
        {{0, 0, 0, 0, 0, 0}}, {{0, 0, 0, 0, 0, 0}},
        0xC0A80102, 0xC0A80101, 80, 12345, 2000, 0);

    for (auto _ : state) {
        conn.state = TCPState::ESTABLISHED;
        PacketView pkt(frame.data(), frame.size());
        engine.processIncomingPacket(&conn, pkt);
    }
}
BENCHMARK(BM_ProcessIncomingPacket_RST);

static void BM_ProcessIncomingPacket_SYNACK(benchmark::State& state) {
    TCPEngine engine;
    engine.setLocalMAC({{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}});
    engine.setLocalIP(0xC0A80101);

    auto frame = PacketBuilder::buildSYNACK(
        {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}},
        {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
        0xC0A80102, 0xC0A80101, 80, 12345, 5000, 1001);

    for (auto _ : state) {
        TCPConnection conn;
        conn.state = TCPState::SYN_SENT;
        conn.src_port = 12345;
        conn.dst_port = 80;
        conn.src_ip = 0xC0A80101;
        conn.dst_ip = 0xC0A80102;
        conn.iss = 1000;
        conn.snd_nxt = 1001;
        conn.snd_una = 1000;

        PacketView pkt(frame.data(), frame.size());
        engine.processIncomingPacket(&conn, pkt);
    }
}
BENCHMARK(BM_ProcessIncomingPacket_SYNACK);

static void BM_ProcessIncomingPacket_FIN(benchmark::State& state) {
    TCPEngine engine;
    engine.setLocalMAC({{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}});
    engine.setLocalIP(0xC0A80101);

    auto frame = PacketBuilder::buildFIN_ACK(
        {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}},
        {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}},
        0xC0A80102, 0xC0A80101, 80, 12345, 5000, 2000);

    for (auto _ : state) {
        TCPConnection conn;
        conn.state = TCPState::ESTABLISHED;
        conn.src_port = 12345;
        conn.dst_port = 80;
        conn.src_ip = 0xC0A80101;
        conn.dst_ip = 0xC0A80102;
        conn.snd_nxt = 2000;
        conn.snd_una = 2000;
        conn.rcv_nxt = 5000;
        conn.rcv_wnd = 65535;

        PacketView pkt(frame.data(), frame.size());
        engine.processIncomingPacket(&conn, pkt);
    }
}
BENCHMARK(BM_ProcessIncomingPacket_FIN);

// ── End-to-end: build+send+process loop (synthetic) ──────────────────

static void BM_FullHandshakeSimulated(benchmark::State& state) {
    TCPEngine engine;
    engine.setLocalMAC({{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}});
    engine.setLocalIP(0xC0A80101);

    for (auto _ : state) {
        TCPConnection conn;
        conn.state = TCPState::SYN_SENT;
        conn.src_port = 54321;
        conn.dst_port = 80;
        conn.src_ip = 0xC0A80101;
        conn.dst_ip = 0xC0A80102;
        conn.src_mac = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
        conn.dst_mac = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
        conn.iss = 1000;
        conn.snd_nxt = 1001;
        conn.snd_una = 1000;
        conn.rcv_wnd = 65535;
        conn.opts.local_mss = 1460;
        conn.cubic.cwnd = 43800;

        auto synack = PacketBuilder::buildSYNACK(
            conn.dst_mac, conn.src_mac,
            conn.dst_ip, conn.src_ip,
            conn.dst_port, conn.src_port,
            5000, conn.iss + 1);

        PacketView pkt(synack.data(), synack.size());
        engine.processIncomingPacket(&conn, pkt);
        benchmark::DoNotOptimize(conn.state);
    }
}
BENCHMARK(BM_FullHandshakeSimulated);

static void BM_FullDataTransferSimulated(benchmark::State& state) {
    TCPEngine engine;
    engine.setLocalMAC({{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}});
    engine.setLocalIP(0xC0A80101);

    for (auto _ : state) {
        TCPConnection conn;
        conn.state = TCPState::ESTABLISHED;
        conn.src_port = 54321;
        conn.dst_port = 80;
        conn.src_ip = 0xC0A80101;
        conn.dst_ip = 0xC0A80102;
        conn.snd_nxt = 2000;
        conn.snd_una = 2000;
        conn.rcv_nxt = 5000;
        conn.rcv_wnd = 65535;

        uint8_t payload[1460];
        memset(payload, 0x42, sizeof(payload));

        for (int i = 0; i < 10; ++i) {
            auto frame = PacketBuilder::buildDataSegment(
                conn.dst_mac, conn.src_mac,
                conn.dst_ip, conn.src_ip,
                conn.dst_port, conn.src_port,
                conn.rcv_nxt + i * 1460, conn.snd_nxt,
                payload, sizeof(payload), true, 65535);

            PacketView pkt(frame.data(), frame.size());
            engine.processIncomingPacket(&conn, pkt);
        }
        benchmark::DoNotOptimize(conn.rcv_nxt);
    }
}
BENCHMARK(BM_FullDataTransferSimulated);

// BENCHMARK_MAIN removed - defined in bench_pntp_core.cpp
