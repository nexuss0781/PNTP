#include "pntp/tcp_engine.h"
#include "pntp/packet_builder.h"
#include "pntp/pntp_core.h"
#include <gtest/gtest.h>
#include <cstring>
#include <arpa/inet.h>

// ── TCPState String Conversion ───────────────────────────────────────

TEST(TCPStateTest, StateToString_AllStates) {
    EXPECT_STREQ(tcpStateToString(TCPState::CLOSED), "CLOSED");
    EXPECT_STREQ(tcpStateToString(TCPState::LISTEN), "LISTEN");
    EXPECT_STREQ(tcpStateToString(TCPState::SYN_SENT), "SYN_SENT");
    EXPECT_STREQ(tcpStateToString(TCPState::SYN_RECEIVED), "SYN_RECEIVED");
    EXPECT_STREQ(tcpStateToString(TCPState::ESTABLISHED), "ESTABLISHED");
    EXPECT_STREQ(tcpStateToString(TCPState::FIN_WAIT_1), "FIN_WAIT_1");
    EXPECT_STREQ(tcpStateToString(TCPState::FIN_WAIT_2), "FIN_WAIT_2");
    EXPECT_STREQ(tcpStateToString(TCPState::CLOSE_WAIT), "CLOSE_WAIT");
    EXPECT_STREQ(tcpStateToString(TCPState::CLOSING), "CLOSING");
    EXPECT_STREQ(tcpStateToString(TCPState::LAST_ACK), "LAST_ACK");
    EXPECT_STREQ(tcpStateToString(TCPState::TIME_WAIT), "TIME_WAIT");
}

// ── RTT Estimator Tests ──────────────────────────────────────────────

class RTTEstimatorTest : public ::testing::Test {
protected:
    RTTEstimator rtt;
};

TEST_F(RTTEstimatorTest, InitialState) {
    EXPECT_EQ(rtt.srtt_us, 0u);
    EXPECT_EQ(rtt.rttvar_us, 0u);
    EXPECT_EQ(rtt.rto_us, RTTEstimator::INITIAL_RTO);
    EXPECT_FALSE(rtt.initialized);
}

TEST_F(RTTEstimatorTest, FirstMeasurement) {
    rtt.update(10000);
    EXPECT_TRUE(rtt.initialized);
    EXPECT_EQ(rtt.srtt_us, 10000u);
    EXPECT_EQ(rtt.rttvar_us, 5000u);
}

TEST_F(RTTEstimatorTest, SubsequentMeasurement_Converges) {
    rtt.update(10000);
    rtt.update(10000);
    rtt.update(10000);
    EXPECT_NEAR(rtt.srtt_us, 10000u, 1000);
}

TEST_F(RTTEstimatorTest, RTTVar_IncreasesWithVariation) {
    rtt.update(10000);
    uint64_t rttvar_before = rtt.rttvar_us;
    rtt.update(20000);
    EXPECT_GT(rtt.rttvar_us, rttvar_before);
}

TEST_F(RTTEstimatorTest, RTO_Bounded) {
    rtt.update(1000000);
    EXPECT_LE(rtt.rto_us, RTTEstimator::RTO_MAX_US);
}

TEST_F(RTTEstimatorTest, RTO_MinimumBounded) {
    rtt.update(1);
    EXPECT_GE(rtt.rto_us, RTTEstimator::RTO_MIN_US);
}

TEST_F(RTTEstimatorTest, Backoff_Doubles) {
    rtt.update(10000);
    uint64_t rto_before = rtt.rto_us;
    rtt.backoff();
    EXPECT_EQ(rtt.rto_us, rto_before * 2);
}

TEST_F(RTTEstimatorTest, Backoff_Bounded) {
    rtt.update(10000);
    for (int i = 0; i < 20; ++i) rtt.backoff();
    EXPECT_LE(rtt.rto_us, RTTEstimator::RTO_MAX_US);
}

TEST_F(RTTEstimatorTest, Reset) {
    rtt.update(10000);
    rtt.reset();
    EXPECT_EQ(rtt.rto_us, RTTEstimator::INITIAL_RTO);
}

TEST_F(RTTEstimatorTest, ManyMeasurements_Stable) {
    for (int i = 0; i < 100; ++i) {
        rtt.update(10000 + (i % 5) * 100);
    }
    EXPECT_NEAR(rtt.srtt_us, 10000u, 2000);
    EXPECT_GE(rtt.rto_us, RTTEstimator::RTO_MIN_US);
    EXPECT_LE(rtt.rto_us, RTTEstimator::RTO_MAX_US);
}

// ── CUBIC State Tests ────────────────────────────────────────────────

class CUBICStateTest : public ::testing::Test {
protected:
    CUBICState cubic;
};

TEST_F(CUBICStateTest, InitialState) {
    EXPECT_EQ(cubic.cwnd, 1460u);
    EXPECT_EQ(cubic.ssthresh, 65535u);
    EXPECT_FALSE(cubic.recovery);
    EXPECT_EQ(cubic.dup_acks, 0u);
}

TEST_F(CUBICStateTest, OnCongestionEvent_SetsRecovery) {
    cubic.cwnd = 50000;
    cubic.onCongestionEvent(1000000);
    EXPECT_TRUE(cubic.recovery);
}

TEST_F(CUBICStateTest, OnCongestionEvent_ReducesCwnd) {
    cubic.cwnd = 50000;
    cubic.onCongestionEvent(1000000);
    EXPECT_LT(cubic.cwnd, 50000u);
}

TEST_F(CUBICStateTest, OnCongestionEvent_SetsWMax) {
    cubic.cwnd = 50000;
    cubic.onCongestionEvent(1000000);
    EXPECT_EQ(cubic.w_max, 50000.0);
}

TEST_F(CUBICStateTest, OnAck_InSlowStart_IncreasesLinearly) {
    cubic.cwnd = 1460;
    cubic.ssthresh = 65535;
    cubic.recovery = false;
    uint32_t cwnd_before = cubic.cwnd;
    cubic.onAck(1460, 1000000);
    EXPECT_GT(cubic.cwnd, cwnd_before);
}

TEST_F(CUBICStateTest, OnAck_InRecovery_Increases) {
    cubic.cwnd = 10000;
    cubic.recovery = true;
    cubic.w_max = 20000;
    cubic.onAck(1460, 1000000);
    EXPECT_GT(cubic.cwnd, 10000u);
}

TEST_F(CUBICStateTest, OnAck_RecoveryComplete) {
    cubic.cwnd = 19000;
    cubic.recovery = true;
    cubic.w_max = 20000;
    cubic.onAck(2000, 1000000);
    EXPECT_FALSE(cubic.recovery);
}

TEST_F(CUBICStateTest, CubicFunction_Increasing) {
    cubic.w_max = 10000;
    cubic.k = 1000000;
    double w1 = cubic.cubicFunction(2000000);
    double w2 = cubic.cubicFunction(3000000);
    EXPECT_GT(w2, w1);
}

TEST_F(CUBICStateTest, GetWindowSize) {
    cubic.cwnd = 29200;
    EXPECT_EQ(cubic.getWindowSize(), 29200u);
}

// ── TCPConnection Tests ──────────────────────────────────────────────

TEST(TCPConnectionTest, DefaultState_CLOSED) {
    TCPConnection conn;
    EXPECT_EQ(conn.state, TCPState::CLOSED);
}

TEST(TCPConnectionTest, SequenceNumbers_InitiallyZero) {
    TCPConnection conn;
    EXPECT_EQ(conn.snd_nxt, 0u);
    EXPECT_EQ(conn.snd_una, 0u);
    EXPECT_EQ(conn.rcv_nxt, 0u);
}

TEST(TCPConnectionTest, WindowSizes_Default) {
    TCPConnection conn;
    EXPECT_EQ(conn.rcv_wnd, 65535u);
}

TEST(TCPConnectionTest, MSS_Default) {
    TCPConnection conn;
    EXPECT_EQ(conn.opts.local_mss, 1460u);
}

TEST(TCPConnectionTest, SendQueue_Empty) {
    TCPConnection conn;
    EXPECT_TRUE(conn.send_queue.empty());
}

TEST(TCPConnectionTest, RetransmitQueue_Empty) {
    TCPConnection conn;
    EXPECT_TRUE(conn.retransmit_queue.empty());
}

TEST(TCPConnectionTest, OOOQueue_Empty) {
    TCPConnection conn;
    EXPECT_TRUE(conn.ooo_queue.empty());
}

TEST(TCPConnectionTest, FINFlags_Default) {
    TCPConnection conn;
    EXPECT_FALSE(conn.fin_sent);
    EXPECT_FALSE(conn.fin_received);
}

// ── TCPEngine Tests (Non-Network) ────────────────────────────────────

class TCPEngineTest : public ::testing::Test {
protected:
    TCPEngine engine;

    void SetUp() override {
        engine.setLocalMAC({{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}});
        engine.setLocalIP(0xC0A80101);
    }
};

TEST_F(TCPEngineTest, GetState_ClosedConn) {
    EXPECT_EQ(engine.getState(nullptr), TCPState::CLOSED);
}

TEST_F(TCPEngineTest, TranscendentFetch_EmptyUrl) {
    std::string result = engine.transcendentFetch("");
    EXPECT_TRUE(result.empty());
}

TEST_F(TCPEngineTest, Open_BadHost_ReturnsNull) {
    TCPConnection* conn = engine.open("nonexistent.invalid", 80, 500);
    EXPECT_EQ(conn, nullptr);
}

// ── Packet Processing Tests ──────────────────────────────────────────

TEST_F(TCPEngineTest, ProcessIncomingPacket_NonTCP_ReturnsFalse) {
    TCPConnection conn;
    conn.state = TCPState::ESTABLISHED;
    conn.src_port = 12345;
    conn.dst_port = 80;

    uint8_t frame[54] = {};
    frame[12] = 0x08;
    frame[13] = 0x00;
    frame[14] = 0x45;
    frame[23] = 17;

    PacketView pkt(frame, sizeof(frame));
    bool result = engine.processIncomingPacket(&conn, pkt);
    EXPECT_FALSE(result);
}

TEST_F(TCPEngineTest, ProcessIncomingPacket_WrongPorts_ReturnsFalse) {
    TCPConnection conn;
    conn.state = TCPState::ESTABLISHED;
    conn.src_port = 12345;
    conn.dst_port = 80;

    auto frame = PacketBuilder::buildACK(
        {{0, 0, 0, 0, 0, 0}}, {{0, 0, 0, 0, 0, 0}},
        0xC0A80102, 0xC0A80101,
        9999, 54321,
        2000, 1000);

    PacketView pkt(frame.data(), frame.size());
    bool result = engine.processIncomingPacket(&conn, pkt);
    EXPECT_FALSE(result);
}

TEST_F(TCPEngineTest, ProcessIncomingPacket_RST_ClosesConn) {
    TCPConnection conn;
    conn.state = TCPState::ESTABLISHED;
    conn.src_port = 12345;
    conn.dst_port = 80;
    conn.src_ip = 0xC0A80101;
    conn.dst_ip = 0xC0A80102;

    auto frame = PacketBuilder::buildRST(
        {{0, 0, 0, 0, 0, 0}}, {{0, 0, 0, 0, 0, 0}},
        0xC0A80102, 0xC0A80101,
        80, 12345,
        2000, 0);

    PacketView pkt(frame.data(), frame.size());
    engine.processIncomingPacket(&conn, pkt);
    EXPECT_EQ(conn.state, TCPState::CLOSED);
}

// ── RTT Integration Tests ────────────────────────────────────────────

TEST(RTTIntegrationTest, RTTUsedInConnection) {
    TCPConnection conn;
    conn.rtt.update(5000);
    conn.rtt.update(6000);
    conn.rtt.update(4000);
    EXPECT_GE(conn.rtt.rto_us, RTTEstimator::RTO_MIN_US);
    EXPECT_LE(conn.rtt.rto_us, RTTEstimator::RTO_MAX_US);
}

TEST(RTTIntegrationTest, CUBICUsedInConnection) {
    TCPConnection conn;
    conn.cubic.cwnd = 20000;
    conn.cubic.onCongestionEvent(1000000);
    EXPECT_TRUE(conn.cubic.recovery);
    EXPECT_LT(conn.cubic.cwnd, 20000u);
}

// ── Handshake Simulation Tests ───────────────────────────────────────

class HandshakeSimulationTest : public ::testing::Test {
protected:
    TCPEngine engine;
    MAC client_mac = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC server_mac = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    uint32_t client_ip = 0xC0A80101;
    uint32_t server_ip = 0xC0A80102;
    uint16_t client_port = 54321;
    uint16_t server_port = 80;

    void SetUp() override {
        engine.setLocalMAC(client_mac);
        engine.setLocalIP(client_ip);
    }
};

TEST_F(HandshakeSimulationTest, SimulateThreeWayHandshake) {
    TCPConnection conn;
    conn.state = TCPState::CLOSED;
    conn.src_port = client_port;
    conn.dst_port = server_port;
    conn.src_ip = client_ip;
    conn.dst_ip = server_ip;
    conn.src_mac = client_mac;
    conn.dst_mac = server_mac;
    conn.iss = 1000;
    conn.snd_nxt = conn.iss;
    conn.snd_una = conn.iss;
    conn.rcv_wnd = 65535;

    conn.state = TCPState::SYN_SENT;
    conn.snd_nxt = conn.iss + 1;

    auto synack_frame = PacketBuilder::buildSYNACK(
        server_mac, client_mac,
        server_ip, client_ip,
        server_port, client_port,
        5000, conn.iss + 1);

    PacketView pkt(synack_frame.data(), synack_frame.size());
    bool result = engine.processIncomingPacket(&conn, pkt);
    EXPECT_TRUE(result);
    EXPECT_EQ(conn.state, TCPState::ESTABLISHED);
    EXPECT_EQ(conn.rcv_nxt, 5001u);
    EXPECT_EQ(conn.snd_una, conn.iss + 1);
}

TEST_F(HandshakeSimulationTest, SimulateSYN_BadAck_ClosesConn) {
    TCPConnection conn;
    conn.state = TCPState::SYN_SENT;
    conn.src_port = client_port;
    conn.dst_port = server_port;
    conn.src_ip = client_ip;
    conn.dst_ip = server_ip;
    conn.src_mac = client_mac;
    conn.dst_mac = server_mac;
    conn.iss = 1000;
    conn.snd_nxt = 1001;
    conn.snd_una = 1000;

    auto synack_frame = PacketBuilder::buildSYNACK(
        server_mac, client_mac,
        server_ip, client_ip,
        server_port, client_port,
        5000, 9999);

    PacketView pkt(synack_frame.data(), synack_frame.size());
    engine.processIncomingPacket(&conn, pkt);
    EXPECT_EQ(conn.state, TCPState::CLOSED);
}

// ── Data Transfer Simulation Tests ───────────────────────────────────

class DataTransferTest : public ::testing::Test {
protected:
    TCPEngine engine;
    MAC client_mac = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC server_mac = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    uint32_t client_ip = 0xC0A80101;
    uint32_t server_ip = 0xC0A80102;
    uint16_t client_port = 54321;
    uint16_t server_port = 80;

    TCPConnection establishedConn() {
        TCPConnection conn;
        conn.state = TCPState::ESTABLISHED;
        conn.src_port = client_port;
        conn.dst_port = server_port;
        conn.src_ip = client_ip;
        conn.dst_ip = server_ip;
        conn.src_mac = client_mac;
        conn.dst_mac = server_mac;
        conn.snd_nxt = 2000;
        conn.snd_una = 2000;
        conn.rcv_nxt = 5000;
        conn.rcv_wnd = 65535;
        conn.snd_wnd = 65535;
        conn.opts.local_mss = 1460;
        conn.cubic.cwnd = 43800;
        return conn;
    }
};

TEST_F(DataTransferTest, Recv_InOrderData_Delivered) {
    auto conn = establishedConn();

    uint8_t payload[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};
    auto frame = PacketBuilder::buildDataSegment(
        client_mac, server_mac,
        server_ip, client_ip,
        server_port, client_port,
        5000, 2000,
        payload, 5, true, 65535);

    PacketView pkt(frame.data(), frame.size());
    bool delivered = engine.processIncomingPacket(&conn, pkt);
    EXPECT_TRUE(delivered);
    EXPECT_EQ(conn.rcv_nxt, 5005u);
    EXPECT_FALSE(conn.ooo_queue.empty());
}

TEST_F(DataTransferTest, Recv_OutOfOrder_Queued) {
    auto conn = establishedConn();

    uint8_t data1[] = {0x01, 0x02};
    uint8_t data2[] = {0x03, 0x04};

    auto frame1 = PacketBuilder::buildDataSegment(
        client_mac, server_mac,
        server_ip, client_ip,
        server_port, client_port,
        5004, 2000,
        data1, 2, true, 65535);

    auto frame2 = PacketBuilder::buildDataSegment(
        client_mac, server_mac,
        server_ip, client_ip,
        server_port, client_port,
        5000, 2000,
        data2, 2, true, 65535);

    PacketView pkt1(frame1.data(), frame1.size());
    engine.processIncomingPacket(&conn, pkt1);

    PacketView pkt2(frame2.data(), frame2.size());
    engine.processIncomingPacket(&conn, pkt2);

    EXPECT_EQ(conn.rcv_nxt, 5006u);
}

TEST_F(DataTransferTest, Recv_DupACK_IncrementsCounter) {
    auto conn = establishedConn();

    auto frame = PacketBuilder::buildACK(
        client_mac, server_mac,
        server_ip, client_ip,
        server_port, client_port,
        5000, 2000, 65535);

    PacketView pkt(frame.data(), frame.size());
    engine.processIncomingPacket(&conn, pkt);
    EXPECT_EQ(conn.dup_ack_count, 1u);
}

// ── FIN/CLOSE Simulation Tests ───────────────────────────────────────

class CloseSimulationTest : public ::testing::Test {
protected:
    TCPEngine engine;
    MAC client_mac = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC server_mac = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    uint32_t client_ip = 0xC0A80101;
    uint32_t server_ip = 0xC0A80102;
    uint16_t client_port = 54321;
    uint16_t server_port = 80;

    TCPConnection establishedConn() {
        TCPConnection conn;
        conn.state = TCPState::ESTABLISHED;
        conn.src_port = client_port;
        conn.dst_port = server_port;
        conn.src_ip = client_ip;
        conn.dst_ip = server_ip;
        conn.src_mac = client_mac;
        conn.dst_mac = server_mac;
        conn.snd_nxt = 2000;
        conn.snd_una = 2000;
        conn.rcv_nxt = 5000;
        conn.rcv_wnd = 65535;
        return conn;
    }
};

TEST_F(CloseSimulationTest, RecvFIN_SendsACK_GoesToCloseWait) {
    auto conn = establishedConn();

    auto fin_frame = PacketBuilder::buildFIN_ACK(
        client_mac, server_mac,
        server_ip, client_ip,
        server_port, client_port,
        5000, 2000);

    PacketView pkt(fin_frame.data(), fin_frame.size());
    bool result = engine.processIncomingPacket(&conn, pkt);
    EXPECT_TRUE(result);
    EXPECT_EQ(conn.state, TCPState::CLOSE_WAIT);
    EXPECT_TRUE(conn.fin_received);
    EXPECT_EQ(conn.rcv_nxt, 5001u);
}

TEST_F(CloseSimulationTest, FINWAIT1_RecvFIN_GoesToCLOSING) {
    auto conn = establishedConn();
    conn.state = TCPState::FIN_WAIT_1;
    conn.fin_sent = true;
    conn.fin_seq = 2000;
    conn.snd_nxt = 2001;

    auto fin_frame = PacketBuilder::buildFIN_ACK(
        client_mac, server_mac,
        server_ip, client_ip,
        server_port, client_port,
        5000, 2001);

    PacketView pkt(fin_frame.data(), fin_frame.size());
    engine.processIncomingPacket(&conn, pkt);
    EXPECT_EQ(conn.state, TCPState::CLOSING);
}

TEST_F(CloseSimulationTest, FINWAIT2_RecvFIN_GoesToTIMEWAIT) {
    auto conn = establishedConn();
    conn.state = TCPState::FIN_WAIT_2;

    auto fin_frame = PacketBuilder::buildFIN_ACK(
        client_mac, server_mac,
        server_ip, client_ip,
        server_port, client_port,
        5000, 2001);

    PacketView pkt(fin_frame.data(), fin_frame.size());
    engine.processIncomingPacket(&conn, pkt);
    EXPECT_EQ(conn.state, TCPState::TIME_WAIT);
}

// ── Checksum Validation Tests ────────────────────────────────────────

TEST(ChecksumValidationTest, BuildSYN_IPChecksumValid) {
    MAC dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};

    auto frame = PacketBuilder::buildSYN(dst, src, 0xC0A80101, 0xC0A80102, 12345, 80, 1000);

    PacketView pkt(frame.data(), frame.size());
    auto* ip = RawSocketHandler::getIPv4Header(pkt);
    ASSERT_NE(ip, nullptr);

    uint16_t ck = PacketBuilder::computeChecksum(
        reinterpret_cast<const uint16_t*>(frame.data() + 14), 20);
    EXPECT_EQ(ck, 0);
}

TEST(ChecksumValidationTest, BuildDataSegment_TCPChecksumNonZero) {
    MAC dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    uint8_t data[] = "Hello";

    auto frame = PacketBuilder::buildDataSegment(
        dst, src, 0xC0A80101, 0xC0A80102, 12345, 80,
        1000, 2000, data, 5, true, 65535);

    PacketView pkt(frame.data(), frame.size());
    auto* tcp = RawSocketHandler::getTCPHeader(pkt);
    ASSERT_NE(tcp, nullptr);

    uint16_t tcp_ck;
    std::memcpy(&tcp_ck, reinterpret_cast<const uint8_t*>(tcp) + 16, 2);
    EXPECT_NE(tcp_ck, 0);
}

// ── Packet Builder Verify Parse ──────────────────────────────────────

TEST(PacketVerifyTest, SYN_ParsesCorrectly) {
    MAC dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};

    auto frame = PacketBuilder::buildSYN(dst, src, 0xC0A80101, 0xC0A80102, 12345, 80, 1000);

    PacketView pkt(frame.data(), frame.size());
    auto* tcp = RawSocketHandler::getTCPHeader(pkt);
    ASSERT_NE(tcp, nullptr);

    EXPECT_EQ(ntohs(tcp->source), 12345);
    EXPECT_EQ(ntohs(tcp->dest), 80);
    EXPECT_NE(tcp->syn, 0);
    EXPECT_EQ(tcp->ack, 0);

    uint32_t seq;
    std::memcpy(&seq, &tcp->seq, 4);
    EXPECT_EQ(ntohl(seq), 1000u);
}

TEST(PacketVerifyTest, SYNACK_ParsesCorrectly) {
    MAC dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};

    auto frame = PacketBuilder::buildSYNACK(dst, src, 0xC0A80101, 0xC0A80102, 12345, 80, 2000, 1001);

    PacketView pkt(frame.data(), frame.size());
    auto* tcp = RawSocketHandler::getTCPHeader(pkt);
    ASSERT_NE(tcp, nullptr);

    EXPECT_NE(tcp->syn, 0);
    EXPECT_NE(tcp->ack, 0);

    uint32_t ack;
    std::memcpy(&ack, &tcp->ack_seq, 4);
    EXPECT_EQ(ntohl(ack), 1001u);
}

TEST(PacketVerifyTest, DataSegment_PayloadMatches) {
    MAC dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};
    uint8_t original[] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};

    auto frame = PacketBuilder::buildDataSegment(
        dst, src, 0xC0A80101, 0xC0A80102, 12345, 80,
        1000, 2000, original, 6, true, 65535);

    PacketView pkt(frame.data(), frame.size());
    auto payload = RawSocketHandler::getPayload(pkt, IPPROTO_TCP);
    ASSERT_TRUE(payload);
    EXPECT_EQ(payload.len, 6u);
    EXPECT_EQ(payload.data[0], 0xDE);
    EXPECT_EQ(payload.data[1], 0xAD);
    EXPECT_EQ(payload.data[2], 0xBE);
    EXPECT_EQ(payload.data[3], 0xEF);
    EXPECT_EQ(payload.data[4], 0xCA);
    EXPECT_EQ(payload.data[5], 0xFE);
}

TEST(PacketVerifyTest, RST_ParsesCorrectly) {
    MAC dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};

    auto frame = PacketBuilder::buildRST(dst, src, 0xC0A80101, 0xC0A80102, 12345, 80, 5000, 0);

    PacketView pkt(frame.data(), frame.size());
    auto* tcp = RawSocketHandler::getTCPHeader(pkt);
    ASSERT_NE(tcp, nullptr);
    EXPECT_NE(tcp->rst, 0);
}

TEST(PacketVerifyTest, FIN_ACK_ParsesCorrectly) {
    MAC dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};

    auto frame = PacketBuilder::buildFIN_ACK(dst, src, 0xC0A80101, 0xC0A80102, 12345, 80, 5000, 6000);

    PacketView pkt(frame.data(), frame.size());
    auto* tcp = RawSocketHandler::getTCPHeader(pkt);
    ASSERT_NE(tcp, nullptr);
    EXPECT_NE(tcp->fin, 0);
    EXPECT_NE(tcp->ack, 0);
}

// ── Edge Case Tests ──────────────────────────────────────────────────

TEST(EdgeCaseTest, ZeroLengthDataSegment) {
    MAC dst = {{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}};
    MAC src = {{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}};

    auto frame = PacketBuilder::buildDataSegment(
        dst, src, 0xC0A80101, 0xC0A80102, 12345, 80,
        1000, 2000, nullptr, 0, true, 65535);

    EXPECT_GE(frame.size(), 54u);
}

TEST(EdgeCaseTest, MaxSeqNum) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.seq_num = 0xFFFFFFFF;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint32_t seq;
    std::memcpy(&seq, hdr.data() + 4, 4);
    EXPECT_EQ(ntohl(seq), 0xFFFFFFFFu);
}

TEST(EdgeCaseTest, MaxAckNum) {
    TCPHeaderInfo info{};
    info.src_port = 12345;
    info.dst_port = 80;
    info.ack_num = 0xFFFFFFFF;
    info.flags.ack = true;
    info.window = 65535;

    auto hdr = PacketBuilder::buildTCPHeader(info, 0x0A000001, 0x0A000002);
    uint32_t ack;
    std::memcpy(&ack, hdr.data() + 8, 4);
    EXPECT_EQ(ntohl(ack), 0xFFFFFFFFu);
}

TEST(EdgeCaseTest, RTT_MeasurementNearZero) {
    RTTEstimator rtt;
    rtt.update(1);
    EXPECT_GE(rtt.rto_us, RTTEstimator::RTO_MIN_US);
}

TEST(EdgeCaseTest, RTT_MeasurementVeryLarge) {
    RTTEstimator rtt;
    rtt.update(100000000);
    EXPECT_LE(rtt.rto_us, RTTEstimator::RTO_MAX_US);
}

TEST(EdgeCaseTest, CUBIC_ZeroBytesAcked) {
    CUBICState cubic;
    cubic.cwnd = 10000;
    cubic.onAck(0, 1000000);
    EXPECT_EQ(cubic.cwnd, 10000u);
}
