#include "pntp/packet_builder.h"
#include "pntp/raw_socket_handler.h"
#include <gtest/gtest.h>
#include <cstring>
#include <arpa/inet.h>

// ── IPv4Addr Tests ───────────────────────────────────────────────────

TEST(IPv4AddrTest, FromString_Valid) {
    auto addr = IPv4Addr::fromString("192.168.1.1");
    EXPECT_EQ(addr.addr, 0xC0A80101u);
}

TEST(IPv4AddrTest, FromString_Loopback) {
    auto addr = IPv4Addr::fromString("127.0.0.1");
    EXPECT_TRUE(addr.isLoopback());
    EXPECT_EQ(addr.addr, 0x7F000001u);
}

TEST(IPv4AddrTest, FromString_Broadcast) {
    auto addr = IPv4Addr::fromString("255.255.255.255");
    EXPECT_EQ(addr.addr, 0xFFFFFFFFu);
}

TEST(IPv4AddrTest, ToString_RoundTrip) {
    auto addr = IPv4Addr::fromString("10.20.30.40");
    std::string str = addr.toString();
    EXPECT_EQ(str, "10.20.30.40");
}

TEST(IPv4AddrTest, Equality) {
    auto a = IPv4Addr::fromString("1.2.3.4");
    auto b = IPv4Addr::fromString("1.2.3.4");
    auto c = IPv4Addr::fromString("5.6.7.8");
    EXPECT_EQ(a, b);
    EXPECT_NE(a, c);
}

// ── Checksum Tests ───────────────────────────────────────────────────

TEST(PacketBuilderTest, ComputeChecksum_EmptyData) {
    uint16_t result = PacketBuilder::computeChecksum(nullptr, 0);
    EXPECT_EQ(result, 0xFFFF);
}

TEST(PacketBuilderTest, ComputeChecksum_KnownValue) {
    uint16_t data[] = {0x4500, 0x003C};
    uint16_t result = PacketBuilder::computeChecksum(data, 4);
    EXPECT_NE(result, 0);
}

TEST(PacketBuilderTest, ComputeChecksum_AllZeros) {
    uint16_t data[] = {0x0000, 0x0000, 0x0000, 0x0000};
    uint16_t result = PacketBuilder::computeChecksum(data, 8);
    EXPECT_EQ(result, 0xFFFF);
}

TEST(PacketBuilderTest, ComputeTCPChecksum_Deterministic) {
    uint8_t tcp1[20] = {};
    uint8_t tcp2[20] = {};
    uint16_t ck1 = PacketBuilder::computeTCPChecksum(tcp1, 20, 0x0A000001, 0x0A000002);
    uint16_t ck2 = PacketBuilder::computeTCPChecksum(tcp2, 20, 0x0A000001, 0x0A000002);
    EXPECT_EQ(ck1, ck2);
}

TEST(PacketBuilderTest, ComputeTCPChecksum_DiffersWithDifferentIPs) {
    uint8_t tcp[20] = {};
    uint16_t ck1 = PacketBuilder::computeTCPChecksum(tcp, 20, 0x0A000001, 0x0A000002);
    uint16_t ck2 = PacketBuilder::computeTCPChecksum(tcp, 20, 0x0A000001, 0x0A000003);
    EXPECT_NE(ck1, ck2);
}

// ── Ethernet Frame Tests ─────────────────────────────────────────────

TEST(PacketBuilderTest, BuildEthernetFrame_CorrectLength) {
    MAC dst = MAC::broadcast();
    MAC src;
    src.bytes = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};

    auto frame = PacketBuilder::buildEthernetFrame(dst, src, 0x0800, payload, 4);
    EXPECT_EQ(frame.size(), 14 + 4);
}

TEST(PacketBuilderTest, BuildEthernetFrame_DstMacCorrect) {
    MAC dst;
    dst.bytes = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    MAC src;

    auto frame = PacketBuilder::buildEthernetFrame(dst, src, 0x0800, nullptr, 0);
    EXPECT_EQ(frame[0], 0xAA);
    EXPECT_EQ(frame[1], 0xBB);
    EXPECT_EQ(frame[2], 0xCC);
    EXPECT_EQ(frame[3], 0xDD);
    EXPECT_EQ(frame[4], 0xEE);
    EXPECT_EQ(frame[5], 0xFF);
}

TEST(PacketBuilderTest, BuildEthernetFrame_SrcMacCorrect) {
    MAC dst;
    MAC src;
    src.bytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};

    auto frame = PacketBuilder::buildEthernetFrame(dst, src, 0x0800, nullptr, 0);
    EXPECT_EQ(frame[6], 0x01);
    EXPECT_EQ(frame[7], 0x02);
    EXPECT_EQ(frame[8], 0x03);
    EXPECT_EQ(frame[9], 0x04);
    EXPECT_EQ(frame[10], 0x05);
    EXPECT_EQ(frame[11], 0x06);
}

TEST(PacketBuilderTest, BuildEthernetFrame_EtherTypeCorrect) {
    MAC dst, src;
    auto frame = PacketBuilder::buildEthernetFrame(dst, src, 0x0800, nullptr, 0);
    EXPECT_EQ(frame[12], 0x08);
    EXPECT_EQ(frame[13], 0x00);
}

TEST(PacketBuilderTest, BuildEthernetFrame_PayloadCopied) {
    MAC dst, src;
    uint8_t payload[] = {0xCA, 0xFE, 0xBA, 0xBE};
    auto frame = PacketBuilder::buildEthernetFrame(dst, src, 0x0800, payload, 4);
    EXPECT_EQ(frame[14], 0xCA);
    EXPECT_EQ(frame[15], 0xFE);
    EXPECT_EQ(frame[16], 0xBA);
    EXPECT_EQ(frame[17], 0xBE);
}

// ── IPv4 Header Tests ────────────────────────────────────────────────

TEST(PacketBuilderTest, BuildIPv4Header_CorrectLength) {
    auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0x0A000001, 0x0A000002, 60);
    EXPECT_EQ(hdr.size(), 20);
}

TEST(PacketBuilderTest, BuildIPv4Header_VersionAndIHL) {
    auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0x0A000001, 0x0A000002, 60);
    EXPECT_EQ(hdr[0], 0x45);
}

TEST(PacketBuilderTest, BuildIPv4Header_TTL) {
    auto hdr = PacketBuilder::buildIPv4Header(128, 6, 0x0A000001, 0x0A000002, 60);
    EXPECT_EQ(hdr[8], 128);
}

TEST(PacketBuilderTest, BuildIPv4Header_Protocol) {
    auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0x0A000001, 0x0A000002, 60);
    EXPECT_EQ(hdr[9], 6);
}

TEST(PacketBuilderTest, BuildIPv4Header_TotalLength) {
    auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0x0A000001, 0x0A000002, 1500);
    uint16_t total_len;
    std::memcpy(&total_len, hdr.data() + 2, 2);
    EXPECT_EQ(ntohs(total_len), 1500);
}

TEST(PacketBuilderTest, BuildIPv4Header_SrcIP) {
    auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0xC0A80101, 0xC0A80102, 60);
    uint32_t src_ip;
    std::memcpy(&src_ip, hdr.data() + 12, 4);
    EXPECT_EQ(ntohl(src_ip), 0xC0A80101u);
}

TEST(PacketBuilderTest, BuildIPv4Header_DstIP) {
    auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0xC0A80101, 0xC0A80102, 60);
    uint32_t dst_ip;
    std::memcpy(&dst_ip, hdr.data() + 16, 4);
    EXPECT_EQ(ntohl(dst_ip), 0xC0A80102u);
}

TEST(PacketBuilderTest, BuildIPv4Header_ChecksumNonZero) {
    auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0xC0A80101, 0xC0A80102, 60);
    uint16_t ck;
    std::memcpy(&ck, hdr.data() + 10, 2);
    EXPECT_NE(ck, 0);
}

TEST(PacketBuilderTest, BuildIPv4Header_ChecksumValid) {
    auto hdr = PacketBuilder::buildIPv4Header(64, 6, 0xC0A80101, 0xC0A80102, 60);
    uint16_t ck = PacketBuilder::computeChecksum(reinterpret_cast<const uint16_t*>(hdr.data()), 20);
    EXPECT_EQ(ck, 0);
}

// ── TCP Header Tests ─────────────────────────────────────────────────

TEST(PacketBuilderTest, BuildTCPHeader_MinimalLength) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.seq_num = 1000;
    info.ack_num = 0;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    EXPECT_GE(hdr.size(), 20u);
}

TEST(PacketBuilderTest, BuildTCPHeader_SourcePort) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint16_t sp;
    std::memcpy(&sp, hdr.data() + 0, 2);
    EXPECT_EQ(ntohs(sp), 12345);
}

TEST(PacketBuilderTest, BuildTCPHeader_DestPort) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint16_t dp;
    std::memcpy(&dp, hdr.data() + 2, 2);
    EXPECT_EQ(ntohs(dp), 80);
}

TEST(PacketBuilderTest, BuildTCPHeader_SeqNum) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.seq_num = 0xDEADBEEF;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint32_t seq;
    std::memcpy(&seq, hdr.data() + 4, 4);
    EXPECT_EQ(ntohl(seq), 0xDEADBEEFu);
}

TEST(PacketBuilderTest, BuildTCPHeader_AckNum) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.ack_num = 0xCAFEBABE;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint32_t ack;
    std::memcpy(&ack, hdr.data() + 8, 4);
    EXPECT_EQ(ntohl(ack), 0xCAFEBABEu);
}

TEST(PacketBuilderTest, BuildTCPHeader_FlagsSYN) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.flags.syn = true;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    EXPECT_EQ(hdr[13] & 0x02, 0x02);
}

TEST(PacketBuilderTest, BuildTCPHeader_FlagsACK) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.flags.ack = true;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    EXPECT_EQ(hdr[13] & 0x10, 0x10);
}

TEST(PacketBuilderTest, BuildTCPHeader_FlagsFIN) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.flags.fin = true;
    info.flags.ack = true;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    EXPECT_EQ(hdr[13] & 0x01, 0x01);
}

TEST(PacketBuilderTest, BuildTCPHeader_FlagsPSH) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.flags.psh = true;
    info.flags.ack = true;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    EXPECT_EQ(hdr[13] & 0x08, 0x08);
}

TEST(PacketBuilderTest, BuildTCPHeader_FlagsRST) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.flags.rst = true;
    info.window = 0;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    EXPECT_EQ(hdr[13] & 0x04, 0x04);
}

TEST(PacketBuilderTest, BuildTCPHeader_WindowSize) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.window = 32768;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint16_t win;
    std::memcpy(&win, hdr.data() + 14, 2);
    EXPECT_EQ(ntohs(win), 32768);
}

TEST(PacketBuilderTest, BuildTCPHeader_ChecksumNonZero) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint16_t ck;
    std::memcpy(&ck, hdr.data() + 16, 2);
    EXPECT_NE(ck, 0);
}

// ── TCP Options Tests ────────────────────────────────────────────────

TEST(PacketBuilderTest, TCPOptions_MSS) {
    TCPOptions opts;
    opts.mss = 1460;
    size_t len = PacketBuilder::tcpHeaderWithOptionsLen(opts);
    EXPECT_EQ(len, 24u);
}

TEST(PacketBuilderTest, TCPOptions_SACK) {
    TCPOptions opts;
    opts.sack_permitted = true;
    size_t len = PacketBuilder::tcpHeaderWithOptionsLen(opts);
    EXPECT_EQ(len, 24u);
}

TEST(PacketBuilderTest, TCPOptions_WindowScale) {
    TCPOptions opts;
    opts.window_scale = 7;
    size_t len = PacketBuilder::tcpHeaderWithOptionsLen(opts);
    EXPECT_EQ(len, 24u);
}

TEST(PacketBuilderTest, TCPOptions_Timestamp) {
    TCPOptions opts;
    opts.has_timestamp = true;
    opts.ts_val = 12345;
    opts.ts_ecr = 67890;
    size_t len = PacketBuilder::tcpHeaderWithOptionsLen(opts);
    EXPECT_EQ(len, 32u);
}

TEST(PacketBuilderTest, TCPOptions_All) {
    TCPOptions opts;
    opts.mss = 1460;
    opts.sack_permitted = true;
    opts.window_scale = 7;
    opts.has_timestamp = true;
    opts.ts_val = 12345;
    opts.ts_ecr = 67890;
    size_t len = PacketBuilder::tcpHeaderWithOptionsLen(opts);
    EXPECT_EQ(len, 40u);
}

TEST(PacketBuilderTest, BuildTCPHeader_WithMSS) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.window = 65535;
    info.options.mss = 1460;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    EXPECT_GE(hdr.size(), 24u);
    EXPECT_EQ(hdr[20], 0x02);
    EXPECT_EQ(hdr[21], 0x04);
    uint16_t mss;
    std::memcpy(&mss, hdr.data() + 22, 2);
    EXPECT_EQ(ntohs(mss), 1460);
}

TEST(PacketBuilderTest, BuildTCPHeader_WithTimestamp) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.window = 65535;
    info.options.has_timestamp = true;
    info.options.ts_val = 0x12345678;
    info.options.ts_ecr = 0x9ABCDEF0;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    EXPECT_GE(hdr.size(), 32u);
    size_t ts_offset = 20;
    EXPECT_EQ(hdr[ts_offset], 0x08);
    EXPECT_EQ(hdr[ts_offset + 1], 0x0A);
    uint32_t ts_val;
    std::memcpy(&ts_val, hdr.data() + ts_offset + 2, 4);
    EXPECT_EQ(ntohl(ts_val), 0x12345678u);
}

TEST(PacketBuilderTest, BuildTCPHeader_DataOffsetCorrect) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.window = 65535;
    info.options.mss = 1460;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint8_t doff = (hdr[12] >> 4) & 0x0F;
    EXPECT_EQ(doff, 6);
}

// ── High-Level Builder Tests ─────────────────────────────────────────

class PacketBuilderSegmentTest : public ::testing::Test {
protected:
    MAC dst_mac = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src_mac = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    uint32_t src_ip = 0xC0A80101;
    uint32_t dst_ip = 0xC0A80102;
    uint16_t src_port = 54321;
    uint16_t dst_port = 80;
};

TEST_F(PacketBuilderSegmentTest, BuildSYN_CorrectLength) {
    auto frame = PacketBuilder::buildSYN(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 1000);
    EXPECT_GE(frame.size(), 14u + 20u + 20u);
}

TEST_F(PacketBuilderSegmentTest, BuildSYN_HasSYNFlag) {
    auto frame = PacketBuilder::buildSYN(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 1000);
    const uint8_t* tcp = frame.data() + 14 + 20;
    EXPECT_EQ(tcp[13] & 0x02, 0x02);
}

TEST_F(PacketBuilderSegmentTest, BuildSYN_AcceptsPacketView) {
    auto frame = PacketBuilder::buildSYN(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 1000);
    EXPECT_GE(frame.size(), 54u);
}

TEST_F(PacketBuilderSegmentTest, BuildSYNACK_HasBothFlags) {
    auto frame = PacketBuilder::buildSYNACK(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 2000, 1001);
    const uint8_t* tcp = frame.data() + 14 + 20;
    EXPECT_NE(tcp[13] & 0x02, 0);
    EXPECT_NE(tcp[13] & 0x10, 0);
}

TEST_F(PacketBuilderSegmentTest, BuildACK_HasACKFlag) {
    auto frame = PacketBuilder::buildACK(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 2000, 1001);
    const uint8_t* tcp = frame.data() + 14 + 20;
    EXPECT_NE(tcp[13] & 0x10, 0);
}

TEST_F(PacketBuilderSegmentTest, BuildFIN_ACK_HasBothFlags) {
    auto frame = PacketBuilder::buildFIN_ACK(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 5000, 6000);
    const uint8_t* tcp = frame.data() + 14 + 20;
    EXPECT_NE(tcp[13] & 0x01, 0);
    EXPECT_NE(tcp[13] & 0x10, 0);
}

TEST_F(PacketBuilderSegmentTest, BuildRST_HasRSTFlag) {
    auto frame = PacketBuilder::buildRST(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 5000, 0);
    const uint8_t* tcp = frame.data() + 14 + 20;
    EXPECT_NE(tcp[13] & 0x04, 0);
}

TEST_F(PacketBuilderSegmentTest, BuildDataSegment_WithPayload) {
    uint8_t data[] = "Hello, TCP!";
    auto frame = PacketBuilder::buildDataSegment(
        dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port,
        1000, 2000, data, sizeof(data) - 1, true, 65535);
    EXPECT_GE(frame.size(), 14u + 20u + 20u + 11u);
}

TEST_F(PacketBuilderSegmentTest, BuildDataSegment_PSHFlagSet) {
    uint8_t data[] = "Test";
    auto frame = PacketBuilder::buildDataSegment(
        dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port,
        1000, 2000, data, 4, true, 65535);
    const uint8_t* tcp = frame.data() + 14 + 20;
    EXPECT_NE(tcp[13] & 0x08, 0);
}

TEST_F(PacketBuilderSegmentTest, BuildKeepalive_HasACKFlag) {
    auto frame = PacketBuilder::buildKeepalive(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 5000, 6000);
    const uint8_t* tcp = frame.data() + 14 + 20;
    EXPECT_NE(tcp[13] & 0x10, 0);
}

TEST_F(PacketBuilderSegmentTest, BuildSYN_WithTimestamp) {
    TCPOptions opts;
    opts.has_timestamp = true;
    opts.ts_val = 12345;
    opts.ts_ecr = 0;
    opts.mss = 1460;

    auto frame = PacketBuilder::buildSYN(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 1000, opts);
    EXPECT_GE(frame.size(), 14u + 20u + 36u);
}

// ── Full Segment Integration ─────────────────────────────────────────

TEST_F(PacketBuilderSegmentTest, BuildSYN_CanBeParsedByRawSocket) {
    auto frame = PacketBuilder::buildSYN(dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port, 1000);

    PacketView pkt(frame.data(), frame.size());
    auto* ip = RawSocketHandler::getIPv4Header(pkt);
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->protocol, IPPROTO_TCP);

    auto* tcp = RawSocketHandler::getTCPHeader(pkt);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(ntohs(tcp->source), src_port);
    EXPECT_EQ(ntohs(tcp->dest), dst_port);
}

TEST_F(PacketBuilderSegmentTest, BuildDataSegment_PayloadParsed) {
    uint8_t data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    auto frame = PacketBuilder::buildDataSegment(
        dst_mac, src_mac, src_ip, dst_ip, src_port, dst_port,
        1000, 2000, data, 5, true, 65535);

    PacketView pkt(frame.data(), frame.size());
    auto payload = RawSocketHandler::getPayload(pkt, IPPROTO_TCP);
    ASSERT_TRUE(payload);
    EXPECT_EQ(payload.len, 5u);
    EXPECT_EQ(payload.data[0], 0x48);
    EXPECT_EQ(payload.data[1], 0x65);
    EXPECT_EQ(payload.data[2], 0x6C);
    EXPECT_EQ(payload.data[3], 0x6C);
    EXPECT_EQ(payload.data[4], 0x6F);
}

// ═════════════════════════════════════════════════════════════════════
// ARP Tests (RFC 826)
// ═════════════════════════════════════════════════════════════════════

TEST(ARPTest, BuildARPRequest_Length) {
    MAC src;
    src.bytes = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    auto frame = PacketBuilder::buildARPRequest(
        src, 0xC0A80101, 0xC0A801FE);
    EXPECT_EQ(frame.size(), PacketBuilder::ETH_HDR_LEN + PacketBuilder::ARP_HDR_LEN);
}

TEST(ARPTest, BuildARPRequest_EthernetHeader) {
    MAC src;
    src.bytes = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    auto frame = PacketBuilder::buildARPRequest(
        src, 0xC0A80101, 0xC0A801FE);

    // dst is broadcast
    for (int i = 0; i < 6; ++i) EXPECT_EQ(frame[i], 0xFF);
    for (int i = 0; i < 6; ++i) EXPECT_EQ(frame[6 + i], src.bytes[i]);
    uint16_t etype = static_cast<uint16_t>(frame[12]) << 8 | frame[13];
    EXPECT_EQ(etype, 0x0806);
}

TEST(ARPTest, BuildARPRequest_Body) {
    MAC src;
    src.bytes = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    auto frame = PacketBuilder::buildARPRequest(
        src, 0xC0A80101, 0xC0A801FE);
    const uint8_t* arp = frame.data() + PacketBuilder::ETH_HDR_LEN;

    EXPECT_EQ(arp[0], 0x00);
    EXPECT_EQ(arp[1], 0x01); // htype = ethernet
    EXPECT_EQ(arp[2], 0x08);
    EXPECT_EQ(arp[3], 0x00); // ptype = IPv4
    EXPECT_EQ(arp[4], 6);    // hlen
    EXPECT_EQ(arp[5], 4);    // plen
    EXPECT_EQ(arp[6], 0x00);
    EXPECT_EQ(arp[7], 0x01); // op = request
    for (int i = 0; i < 6; ++i) EXPECT_EQ(arp[8 + i], src.bytes[i]);
    // sender proto = 192.168.1.1
    EXPECT_EQ(arp[14], 0xC0);
    EXPECT_EQ(arp[15], 0xA8);
    EXPECT_EQ(arp[16], 0x01);
    EXPECT_EQ(arp[17], 0x01);
    // target hw = zero
    for (int i = 0; i < 6; ++i) EXPECT_EQ(arp[18 + i], 0);
    // target proto = 192.168.1.254
    EXPECT_EQ(arp[24], 0xC0);
    EXPECT_EQ(arp[25], 0xA8);
    EXPECT_EQ(arp[26], 0x01);
    EXPECT_EQ(arp[27], 0xFE);
}

TEST(ARPTest, ParseARPReply_Valid) {
    uint8_t reply_mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    std::vector<uint8_t> frame(14 + 28, 0);
    for (int i = 0; i < 6; ++i) frame[i] = 0x11;           // eth dst
    for (int i = 0; i < 6; ++i) frame[6 + i] = 0xaa;       // eth src
    frame[12] = 0x08;
    frame[13] = 0x06;                                       // ARP
    uint8_t* arp = frame.data() + 14;
    arp[4] = 6; arp[5] = 4;                             // hlen/plen
    arp[6] = 0x00; arp[7] = 0x02;                          // op = reply
    std::memcpy(arp + 8, reply_mac, 6);                    // sender ha
    arp[14] = 0xC0; arp[15] = 0xA8; arp[16] = 0x01; arp[17] = 0xFE;
    arp[18] = 0; arp[19] = 0; arp[20] = 0; arp[21] = 0; arp[22] = 0; arp[23] = 0;
    arp[24] = 0xC0; arp[25] = 0xA8; arp[26] = 0x01; arp[27] = 0x01;

    MAC mac;
    uint32_t ip = 0;
    ASSERT_TRUE(PacketBuilder::parseARPReply(frame.data(), frame.size(), mac, ip));
    for (int i = 0; i < 6; ++i) ASSERT_EQ(mac.bytes[i], reply_mac[i]);
    EXPECT_EQ(ip, 0xC0A801FE);
}

TEST(ARPTest, ParseARPReply_RejectsRequest) {
    auto frame = PacketBuilder::buildARPRequest(
        MAC::zero(), 0xC0A80101, 0xC0A801FE);
    MAC mac;
    uint32_t ip = 0;
    EXPECT_FALSE(PacketBuilder::parseARPReply(frame.data(), frame.size(), mac, ip));
}

TEST(ARPTest, ParseARPReply_RejectsNonARP) {
    uint8_t frame[20] = {0};
    frame[12] = 0x08;
    frame[13] = 0x00; // IP, not ARP
    MAC mac;
    uint32_t ip = 0;
    EXPECT_FALSE(PacketBuilder::parseARPReply(frame, sizeof(frame), mac, ip));
}
