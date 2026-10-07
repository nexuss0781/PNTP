#ifndef PNTP_PACKET_BUILDER_H
#define PNTP_PACKET_BUILDER_H

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <string>
#include <vector>
#include <array>

struct MAC {
    std::array<uint8_t, 6> bytes{};
    static MAC broadcast() { return {{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}}; }
    static MAC zero() { return {}; }
    bool operator==(const MAC& o) const { return bytes == o.bytes; }
    bool operator!=(const MAC& o) const { return bytes != o.bytes; }
};

struct IPv4Addr {
    uint32_t addr{};
    static IPv4Addr fromString(const char* str);
    std::string toString() const;
    bool isLoopback() const { return (addr >> 24) == 0x7F; }
    bool operator==(const IPv4Addr& o) const { return addr == o.addr; }
    bool operator!=(const IPv4Addr& o) const { return addr != o.addr; }
};

struct TCPFlags {
    bool fin = false;
    bool syn = false;
    bool rst = false;
    bool psh = false;
    bool ack = false;
    bool urg = false;
};

struct TCPOptions {
    uint16_t mss = 0;
    bool     sack_permitted = false;
    uint8_t  window_scale = 0;
    bool     has_timestamp = false;
    uint32_t ts_val = 0;
    uint32_t ts_ecr = 0;
};

struct TCPHeaderInfo {
    uint16_t    src_port;
    uint16_t    dst_port;
    uint32_t    seq_num;
    uint32_t    ack_num;
    TCPFlags    flags;
    uint16_t    window;
    uint16_t    checksum;
    TCPOptions  options;
};

struct IPHeaderInfo {
    uint8_t     ttl;
    uint8_t     protocol;
    IPv4Addr    src_ip;
    IPv4Addr    dst_ip;
};

class PacketBuilder {
public:
    static constexpr size_t ETH_HDR_LEN  = 14;
    static constexpr size_t IP_HDR_LEN   = 20;
    static constexpr size_t TCP_HDR_LEN  = 20;
    static constexpr size_t ETH_P_IP     = 0x0800;
    static constexpr size_t ARP_ETHERTYPE = 0x0806;
    static constexpr size_t ARP_HDR_LEN  = 28;

    static uint16_t computeChecksum(const uint16_t* data, size_t len);
    static uint16_t computeTCPChecksum(
        const uint8_t* tcp_segment, size_t tcp_len,
        uint32_t src_ip, uint32_t dst_ip);

    static std::vector<uint8_t> buildEthernetFrame(
        const MAC& dst_mac, const MAC& src_mac, uint16_t ether_type,
        const uint8_t* payload, size_t payload_len);

    static std::vector<uint8_t> buildIPv4Header(
        uint8_t ttl, uint8_t protocol,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t total_len, uint16_t identification = 0);

    static std::vector<uint8_t> buildTCPHeader(
        const TCPHeaderInfo& info,
        uint32_t src_ip, uint32_t dst_ip);

    static std::vector<uint8_t> buildTCPSegment(
        const MAC& dst_mac, const MAC& src_mac,
        const IPHeaderInfo& ip_info,
        const TCPHeaderInfo& tcp_info,
        const uint8_t* payload, size_t payload_len);

    static std::vector<uint8_t> buildSYN(
        const MAC& dst_mac, const MAC& src_mac,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq_num,
        const TCPOptions& opts = {});

    static std::vector<uint8_t> buildSYNACK(
        const MAC& dst_mac, const MAC& src_mac,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq_num, uint32_t ack_num,
        const TCPOptions& opts = {});

    static std::vector<uint8_t> buildACK(
        const MAC& dst_mac, const MAC& src_mac,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq_num, uint32_t ack_num,
        uint16_t window = 65535);

    static std::vector<uint8_t> buildPSH_ACK(
        const MAC& dst_mac, const MAC& src_mac,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq_num, uint32_t ack_num,
        const uint8_t* payload, size_t payload_len,
        uint16_t window = 65535);

    static std::vector<uint8_t> buildFIN_ACK(
        const MAC& dst_mac, const MAC& src_mac,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq_num, uint32_t ack_num);

    static std::vector<uint8_t> buildRST(
        const MAC& dst_mac, const MAC& src_mac,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq_num, uint32_t ack_num);

    static std::vector<uint8_t> buildKeepalive(
        const MAC& dst_mac, const MAC& src_mac,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq_num, uint32_t ack_num);

    static std::vector<uint8_t> buildDataSegment(
        const MAC& dst_mac, const MAC& src_mac,
        uint32_t src_ip, uint32_t dst_ip,
        uint16_t src_port, uint16_t dst_port,
        uint32_t seq_num, uint32_t ack_num,
        const uint8_t* data, size_t data_len,
        bool push = true, uint16_t window = 65535);

    static size_t tcpHeaderWithOptionsLen(const TCPOptions& opts);

    // ── ARP (RFC 826) ──────────────────────────────────────────────
    // Build a full Ethernet+ARP request frame asking for the MAC of
    // target_ip. sender_ip/target_ip are host byte order.
    static std::vector<uint8_t> buildARPRequest(
        const MAC& src_mac, uint32_t sender_ip, uint32_t target_ip);

    // Parse an Ethernet+ARP reply frame. On success fills the sender
    // MAC/IP (host byte order) and returns true.
    static bool parseARPReply(const uint8_t* frame, size_t len,
                              MAC& out_mac, uint32_t& out_ip);
};

#endif
