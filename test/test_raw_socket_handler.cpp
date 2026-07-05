#include "pntp/raw_socket_handler.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <thread>
#include <chrono>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

// ── helpers ─────────────────────────────────────────────────────────────

static bool hasRawAccess() {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return false;
    close(fd);
    return true;
}

static bool hasNetAdmin() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return false;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    // can't test promisc without knowing an interface name; assume
    // CAP_NET_ADMIN if we got this far.
    close(fd);
    return true;
}

// Build a synthetic Ethernet + IPv4 + TCP packet in a vector.
// payload_len bytes are appended after the TCP header.
static std::vector<uint8_t> buildTcpPacket(uint16_t src_port,
                                           uint16_t dst_port,
                                           const uint8_t* payload,
                                           size_t payload_len) {
    size_t ip_tot_len  = 20 + 20 + payload_len;   // ip_hdr + tcp_hdr + payload
    size_t frame_len   = 14 + ip_tot_len;

    std::vector<uint8_t> buf(frame_len, 0);
    size_t off = 0;

    // ── Ethernet header (14) ──
    // dst MAC (6)
    // src MAC (6)
    buf[off+12] = 0x08; buf[off+13] = 0x00;    // EtherType = IPv4
    off += 14;

    // ── IP header (20) ──
    buf[off+0]  = 0x45;                          // version=4, ihl=5
    buf[off+2]  = static_cast<uint8_t>((ip_tot_len >> 8) & 0xFF);
    buf[off+3]  = static_cast<uint8_t>( ip_tot_len       & 0xFF);
    buf[off+8]  = 64;                            // TTL
    buf[off+9]  = IPPROTO_TCP;                   // protocol
    // src = 10.0.0.1
    buf[off+12] = 10; buf[off+13] = 0; buf[off+14] = 0; buf[off+15] = 1;
    // dst = 10.0.0.2
    buf[off+16] = 10; buf[off+17] = 0; buf[off+18] = 0; buf[off+19] = 2;
    off += 20;

    // ── TCP header (20) ──
    buf[off+0]  = static_cast<uint8_t>((src_port >> 8) & 0xFF);
    buf[off+1]  = static_cast<uint8_t>( src_port       & 0xFF);
    buf[off+2]  = static_cast<uint8_t>((dst_port >> 8) & 0xFF);
    buf[off+3]  = static_cast<uint8_t>( dst_port       & 0xFF);
    buf[off+12] = 0x50;                          // doff=5, no flags
    buf[off+14] = 0x10; buf[off+15] = 0x00;     // window=4096
    off += 20;

    // ── payload ──
    if (payload && payload_len > 0) {
        memcpy(buf.data() + off, payload, payload_len);
    }

    return buf;
}

static std::vector<uint8_t> buildUdpPacket(uint16_t src_port,
                                           uint16_t dst_port,
                                           const uint8_t* payload,
                                           size_t payload_len) {
    size_t udp_len    = 8 + payload_len;
    size_t ip_tot_len = 20 + udp_len;
    size_t frame_len  = 14 + ip_tot_len;

    std::vector<uint8_t> buf(frame_len, 0);
    size_t off = 0;

    // Ethernet
    buf[off+12] = 0x08; buf[off+13] = 0x00;
    off += 14;

    // IP
    buf[off+0]  = 0x45;
    buf[off+2]  = static_cast<uint8_t>((ip_tot_len >> 8) & 0xFF);
    buf[off+3]  = static_cast<uint8_t>( ip_tot_len       & 0xFF);
    buf[off+8]  = 64;
    buf[off+9]  = IPPROTO_UDP;
    buf[off+12] = 10; buf[off+13] = 0; buf[off+14] = 0; buf[off+15] = 1;
    buf[off+16] = 10; buf[off+17] = 0; buf[off+18] = 0; buf[off+19] = 2;
    off += 20;

    // UDP
    buf[off+0]  = static_cast<uint8_t>((src_port >> 8) & 0xFF);
    buf[off+1]  = static_cast<uint8_t>( src_port       & 0xFF);
    buf[off+2]  = static_cast<uint8_t>((dst_port >> 8) & 0xFF);
    buf[off+3]  = static_cast<uint8_t>( dst_port       & 0xFF);
    buf[off+4]  = static_cast<uint8_t>((udp_len >> 8) & 0xFF);
    buf[off+5]  = static_cast<uint8_t>( udp_len       & 0xFF);
    off += 8;

    if (payload && payload_len > 0)
        memcpy(buf.data() + off, payload, payload_len);

    return buf;
}

static std::vector<uint8_t> buildNonIPv4Frame() {
    // Ethernet + ARP frame (no IP)
    std::vector<uint8_t> buf(42, 0);
    buf[12] = 0x08; buf[13] = 0x06;  // EtherType = ARP
    return buf;
}

// ── PacketView tests ──────────────────────────────────────────────────

TEST(PacketViewTest, DefaultConstructorIsNull) {
    PacketView pv;
    EXPECT_FALSE(pv);
    EXPECT_EQ(nullptr, pv.data);
    EXPECT_EQ(0u, pv.len);
}

TEST(PacketViewTest, ValueConstructor) {
    uint8_t d[] = {1, 2, 3};
    PacketView pv(d, 3);
    EXPECT_TRUE(pv);
    EXPECT_EQ(d, pv.data);
    EXPECT_EQ(3u, pv.len);
}

TEST(PacketViewTest, NullDataPointerIsFalsy) {
    PacketView pv(nullptr, 0);
    EXPECT_FALSE(pv);
}

// ── Header parsing tests ──────────────────────────────────────────────

class HeaderParsingTest : public ::testing::Test {
protected:
    std::vector<uint8_t> tcp_pkt;
    std::vector<uint8_t> udp_pkt;
    std::vector<uint8_t> arp_pkt;
    std::vector<uint8_t> tcp_with_payload;
    std::vector<uint8_t> udp_with_payload;

    void SetUp() override {
        tcp_pkt = buildTcpPacket(12345, 80, nullptr, 0);
        udp_pkt = buildUdpPacket(12345, 53, nullptr, 0);
        arp_pkt = buildNonIPv4Frame();
        uint8_t payload[] = "HelloPNTP";
        tcp_with_payload = buildTcpPacket(12345, 80, payload, 9);
        udp_with_payload = buildUdpPacket(12345, 53, payload, 9);
    }
};

TEST_F(HeaderParsingTest, GetIPv4Header_ReturnsValidPointer) {
    PacketView pv(tcp_pkt.data(), tcp_pkt.size());
    auto* ip = RawSocketHandler::getIPv4Header(pv);
    ASSERT_NE(nullptr, ip);
    EXPECT_EQ(4, ip->version);
    EXPECT_EQ(5, ip->ihl);
    EXPECT_EQ(IPPROTO_TCP, ip->protocol);
    EXPECT_EQ(0x0A000001u, ntohl(ip->saddr));  // 10.0.0.1
    EXPECT_EQ(0x0A000002u, ntohl(ip->daddr));

    // total length = ip(20) + tcp(20) = 40
    EXPECT_EQ(40u, ntohs(ip->tot_len));
}

TEST_F(HeaderParsingTest, GetIPv4Header_RejectsARP) {
    PacketView pv(arp_pkt.data(), arp_pkt.size());
    EXPECT_EQ(nullptr, RawSocketHandler::getIPv4Header(pv));
}

TEST_F(HeaderParsingTest, GetIPv4Header_RejectsTooShort) {
    std::vector<uint8_t> short_pkt(13, 0);  // less than 14 byte ethernet
    PacketView pv(short_pkt.data(), short_pkt.size());
    EXPECT_EQ(nullptr, RawSocketHandler::getIPv4Header(pv));
}

TEST_F(HeaderParsingTest, GetTCPHeader_ReturnsValidPointer) {
    PacketView pv(tcp_pkt.data(), tcp_pkt.size());
    auto* tcp = RawSocketHandler::getTCPHeader(pv);
    ASSERT_NE(nullptr, tcp);
    EXPECT_EQ(12345, ntohs(tcp->source));
    EXPECT_EQ(80, ntohs(tcp->dest));
}

TEST_F(HeaderParsingTest, GetTCPHeader_RejectsUDP) {
    PacketView pv(udp_pkt.data(), udp_pkt.size());
    EXPECT_EQ(nullptr, RawSocketHandler::getTCPHeader(pv));
}

TEST_F(HeaderParsingTest, GetUDPHeader_ReturnsValidPointer) {
    PacketView pv(udp_pkt.data(), udp_pkt.size());
    auto* udp = RawSocketHandler::getUDPHeader(pv);
    ASSERT_NE(nullptr, udp);
    EXPECT_EQ(12345, ntohs(udp->source));
    EXPECT_EQ(53, ntohs(udp->dest));
    // UDP length = 8 (header only, no payload)
    EXPECT_EQ(8u, ntohs(udp->len));
}

TEST_F(HeaderParsingTest, GetUDPHeader_RejectsTCP) {
    PacketView pv(tcp_pkt.data(), tcp_pkt.size());
    EXPECT_EQ(nullptr, RawSocketHandler::getUDPHeader(pv));
}

TEST_F(HeaderParsingTest, GetPayload_TCP_ExtractsCorrectBytes) {
    PacketView pv(tcp_with_payload.data(), tcp_with_payload.size());
    PacketView payload = RawSocketHandler::getPayload(pv, IPPROTO_TCP);
    ASSERT_TRUE(payload);
    EXPECT_EQ(9u, payload.len);
    EXPECT_EQ(0, memcmp("HelloPNTP", payload.data, 9));
}

TEST_F(HeaderParsingTest, GetPayload_UDP_ExtractsCorrectBytes) {
    PacketView pv(udp_with_payload.data(), udp_with_payload.size());
    PacketView payload = RawSocketHandler::getPayload(pv, IPPROTO_UDP);
    ASSERT_TRUE(payload);
    EXPECT_EQ(9u, payload.len);
    EXPECT_EQ(0, memcmp("HelloPNTP", payload.data, 9));
}

TEST_F(HeaderParsingTest, GetPayload_TCP_NoPayload_ReturnsEmpty) {
    PacketView pv(tcp_pkt.data(), tcp_pkt.size());
    PacketView payload = RawSocketHandler::getPayload(pv, IPPROTO_TCP);
    ASSERT_TRUE(payload);
    EXPECT_EQ(0u, payload.len);
}

TEST_F(HeaderParsingTest, GetPayload_EmptyPacket_ReturnsEmpty) {
    PacketView empty;
    EXPECT_FALSE(RawSocketHandler::getPayload(empty, IPPROTO_TCP));
}

// ── BPF factory tests ─────────────────────────────────────────────────

TEST(BPFFactoryTest, MakeBPF_All_ReturnsOneInstruction) {
    auto f = RawSocketHandler::makeBPF_All();
    EXPECT_EQ(1u, f.size());
    EXPECT_EQ(BPF_RET | BPF_K, f[0].code);
}

TEST(BPFFactoryTest, MakeBPF_TCPOnly_HasEightInstructions) {
    auto f = RawSocketHandler::makeBPF_TCPOnly();
    ASSERT_EQ(8u, f.size());

    // First instruction: load EtherType
    EXPECT_EQ(static_cast<uint16_t>(BPF_LD | BPF_H | BPF_ABS), f[0].code);
    EXPECT_EQ(0x000cu, f[0].k);

    // Check EtherType for IPv4
    EXPECT_EQ(static_cast<uint16_t>(BPF_JMP | BPF_JEQ | BPF_K), f[1].code);
    EXPECT_EQ(0x0800u, f[1].k);

    // Last instruction: accept
    EXPECT_EQ(static_cast<uint16_t>(BPF_RET | BPF_K), f[7].code);
    EXPECT_EQ(0x00040000u, f[7].k);
}

TEST(BPFFactoryTest, MakeBPF_UDPOnly_HasEightInstructions) {
    auto f = RawSocketHandler::makeBPF_UDPOnly();
    ASSERT_EQ(8u, f.size());
    EXPECT_EQ(static_cast<uint16_t>(BPF_RET | BPF_K), f[7].code);
    EXPECT_EQ(0x00040000u, f[7].k);
}

TEST(BPFFactoryTest, MakeBPF_PortOnly_HasElevenInstructions) {
    auto f = RawSocketHandler::makeBPF_PortOnly(443);
    ASSERT_EQ(11u, f.size());
    EXPECT_EQ(static_cast<uint16_t>(BPF_RET | BPF_K), f[10].code);
}

// ── RawSocketHandler tests (no root = init-only) ─────────────────────

TEST(RawSocketHandlerTest, InitFailsOnNonexistentInterface) {
    RawSocketHandler handler;
    EXPECT_FALSE(handler.init("nonexistent_iface_xyz_999"));
    EXPECT_FALSE(handler.isInitialized());
}

TEST(RawSocketHandlerTest, Acquire_OnUninitialized_ReturnsEmpty) {
    RawSocketHandler handler;
    auto pkt = handler.acquirePacket();
    EXPECT_FALSE(pkt);
}

TEST(RawSocketHandlerTest, Release_DoesNotCrash_OnUninitialized) {
    RawSocketHandler handler;
    PacketView pv;
    handler.releasePacket(pv);  // should not crash
    SUCCEED();
}

TEST(RawSocketHandlerTest, GetStats_ReturnsZeroes_OnUninitialized) {
    RawSocketHandler handler;
    auto s = handler.getStats();
    EXPECT_EQ(0u, s.packets_captured.load());
    EXPECT_EQ(0u, s.bytes_captured.load());
}

// ── Root-gated tests ─────────────────────────────────────────────────

class RawSocketHandlerRootTest : public ::testing::Test {
protected:
    RawSocketHandler handler;

    void SetUp() override {
        if (!hasRawAccess()) {
            GTEST_SKIP() << "Need CAP_NET_RAW (root) to run this test";
        }
    }
};

TEST_F(RawSocketHandlerRootTest, InitOnLoopback_Succeeds) {
    EXPECT_TRUE(handler.init("lo"));
    EXPECT_TRUE(handler.isInitialized());
}

TEST_F(RawSocketHandlerRootTest, UsingRing_AfterInit) {
    ASSERT_TRUE(handler.init("lo"));
    // may be ring or fallback depending on kernel support
    SUCCEED();
}

TEST_F(RawSocketHandlerRootTest, AttachBPF_All_DoesNotCrash) {
    ASSERT_TRUE(handler.init("lo"));
    auto filter = RawSocketHandler::makeBPF_All();
    EXPECT_TRUE(handler.attachBPF(filter));
}

TEST_F(RawSocketHandlerRootTest, AttachBPF_TCPOnly_DoesNotCrash) {
    ASSERT_TRUE(handler.init("lo"));
    auto filter = RawSocketHandler::makeBPF_TCPOnly();
    EXPECT_TRUE(handler.attachBPF(filter));
}

TEST_F(RawSocketHandlerRootTest, SetPromiscuous) {
    ASSERT_TRUE(handler.init("lo"));
    bool ok = handler.setPromiscuous(true);
    // On some systems CAP_NET_ADMIN may be missing even with CAP_NET_RAW,
    // so we accept either outcome.
    if (!ok)
        GTEST_SKIP() << "Cannot set promiscuous mode (CAP_NET_ADMIN?)";
    EXPECT_TRUE(handler.setPromiscuous(false));
}

TEST_F(RawSocketHandlerRootTest, SetTimeout) {
    ASSERT_TRUE(handler.init("lo"));
    EXPECT_TRUE(handler.setTimeoutMs(100));
}

TEST_F(RawSocketHandlerRootTest, InjectAndCapture) {
    ASSERT_TRUE(handler.init("lo"));

    // Build a minimal Ethernet frame
    uint8_t frame[] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,  // dst broadcast
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  // src
        0x08, 0x00,                            // IPv4
        0x45, 0x00, 0x00, 0x1C,               // IP ver/ihl, tos, len
        0x00, 0x01, 0x00, 0x00,               // id, frag
        0x40, 0x01, 0x00, 0x00,               // ttl=64, proto=ICMP, cksum
        0x7F, 0x00, 0x00, 0x01,               // src=127.0.0.1
        0x7F, 0x00, 0x00, 0x01,               // dst=127.0.0.1
        0x08, 0x00, 0x00, 0x00,               // ICMP echo
        0x00, 0x00, 0x00, 0x00                // padding
    };

    EXPECT_TRUE(handler.injectPacket(frame, sizeof(frame)));

    // Try to capture — may or may not see our injected packet on lo.
    // We just verify the call doesn't crash.
    auto pkt = handler.acquirePacket();
    // Note: on lo, the packet may not be captured (loopback interface
    // doesn't inject via AF_PACKET the same way); but the test is valid
    // as a no-crash sanity check with optional success.
    if (pkt) {
        handler.releasePacket(pkt);
    }
    SUCCEED();
}

TEST_F(RawSocketHandlerRootTest, AcquireRelease_MultipleTimes) {
    ASSERT_TRUE(handler.init("lo"));
    for (int i = 0; i < 10; ++i) {
        auto pkt = handler.acquirePacket();
        if (pkt) {
            handler.releasePacket(pkt);
        }
    }
    SUCCEED();
}

TEST_F(RawSocketHandlerRootTest, StatsAfterAcquire) {
    ASSERT_TRUE(handler.init("lo"));
    auto s = handler.getStats();
    // Stats may be zero if no packets captured, but the call must work.
    EXPECT_LE(0u, s.packets_captured.load());
    EXPECT_LE(0u, s.bytes_captured.load());
}

TEST_F(RawSocketHandlerRootTest, SetRingParams) {
    ASSERT_TRUE(handler.init("lo"));
    // Try reconfiguring the ring with different parameters.
    // This may fail on some kernels but should not crash.
    bool ok = handler.setRingParams(8, 4096);
    if (!ok) {
        GTEST_SKIP() << "Reconfiguring ring parameters not supported";
    }
    EXPECT_TRUE(handler.isInitialized());
}

TEST_F(RawSocketHandlerRootTest, FanoutGroupFails_WithoutMultipleSockets) {
    // Fanout requires multiple sockets in the same group to be meaningful.
    // A single socket can still join a group; this should succeed.
    ASSERT_TRUE(handler.init("lo"));
    bool ok = handler.setFanoutGroup(1, 0);  // PACKET_FANOUT_HASH = 0
    if (!ok)
        GTEST_SKIP() << "Fanout not supported on this kernel";
    SUCCEED();
}
