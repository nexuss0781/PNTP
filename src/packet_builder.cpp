#include "pntp/packet_builder.h"
#include <string>
#include <arpa/inet.h>

IPv4Addr IPv4Addr::fromString(const char* str) {
    IPv4Addr a;
    struct in_addr in;
    if (inet_pton(AF_INET, str, &in) == 1) {
        a.addr = ntohl(in.s_addr);
    }
    return a;
}

std::string IPv4Addr::toString() const {
    uint32_t n = htonl(addr);
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &n, buf, sizeof(buf));
    return buf;
}

uint16_t PacketBuilder::computeChecksum(const uint16_t* data, size_t len) {
    uint32_t sum = 0;
    const uint16_t* ptr = data;
    size_t remaining = len;

    while (remaining > 1) {
        sum += *ptr++;
        remaining -= 2;
    }
    if (remaining == 1) {
        sum += *reinterpret_cast<const uint8_t*>(ptr);
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return static_cast<uint16_t>(~sum);
}

uint16_t PacketBuilder::computeTCPChecksum(
    const uint8_t* tcp_segment, size_t tcp_len,
    uint32_t src_ip, uint32_t dst_ip)
{
    struct PseudoHeader {
        uint32_t src;
        uint32_t dst;
        uint8_t  placeholder;
        uint8_t  protocol;
        uint16_t tcp_length;
    };

    PseudoHeader ph;
    ph.src = htonl(src_ip);
    ph.dst = htonl(dst_ip);
    ph.placeholder = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_length = htons(static_cast<uint16_t>(tcp_len));

    std::vector<uint8_t> buf(sizeof(PseudoHeader) + tcp_len);
    std::memcpy(buf.data(), &ph, sizeof(PseudoHeader));
    std::memcpy(buf.data() + sizeof(PseudoHeader), tcp_segment, tcp_len);

    return computeChecksum(reinterpret_cast<const uint16_t*>(buf.data()), buf.size());
}

std::vector<uint8_t> PacketBuilder::buildEthernetFrame(
    const MAC& dst_mac, const MAC& src_mac, uint16_t ether_type,
    const uint8_t* payload, size_t payload_len)
{
    std::vector<uint8_t> frame(ETH_HDR_LEN + payload_len);
    std::memcpy(frame.data() + 0, dst_mac.bytes.data(), 6);
    std::memcpy(frame.data() + 6, src_mac.bytes.data(), 6);
    uint16_t et = htons(ether_type);
    std::memcpy(frame.data() + 12, &et, 2);
    if (payload && payload_len > 0) {
        std::memcpy(frame.data() + ETH_HDR_LEN, payload, payload_len);
    }
    return frame;
}

std::vector<uint8_t> PacketBuilder::buildIPv4Header(
    uint8_t ttl, uint8_t protocol,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t total_len, uint16_t identification)
{
    std::vector<uint8_t> hdr(IP_HDR_LEN);
    hdr[0] = 0x45;
    hdr[1] = 0x00;
    uint16_t tl = htons(total_len);
    std::memcpy(hdr.data() + 2, &tl, 2);
    uint16_t id = htons(identification);
    std::memcpy(hdr.data() + 4, &id, 2);
    hdr[6] = 0x40;
    hdr[7] = 0x00;
    hdr[8] = ttl;
    hdr[9] = protocol;
    hdr[10] = 0;
    hdr[11] = 0;
    uint32_t si = htonl(src_ip);
    std::memcpy(hdr.data() + 12, &si, 4);
    uint32_t di = htonl(dst_ip);
    std::memcpy(hdr.data() + 16, &di, 4);
    uint16_t ck = computeChecksum(reinterpret_cast<const uint16_t*>(hdr.data()), IP_HDR_LEN);
    std::memcpy(hdr.data() + 10, &ck, 2);
    return hdr;
}

size_t PacketBuilder::tcpHeaderWithOptionsLen(const TCPOptions& opts) {
    size_t len = TCP_HDR_LEN;
    if (opts.mss > 0) len += 4;
    if (opts.sack_permitted) len += 2;
    if (opts.window_scale > 0) len += 3;
    if (opts.has_timestamp) len += 10;
    len = (len + 3) & ~static_cast<size_t>(3);
    return len;
}

std::vector<uint8_t> PacketBuilder::buildTCPHeader(
    const TCPHeaderInfo& info,
    uint32_t src_ip, uint32_t dst_ip)
{
    size_t opt_len = tcpHeaderWithOptionsLen(info.options);
    size_t data_offset = opt_len / 4;
    std::vector<uint8_t> hdr(opt_len, 0);

    uint16_t sp = htons(info.src_port);
    std::memcpy(hdr.data() + 0, &sp, 2);
    uint16_t dp = htons(info.dst_port);
    std::memcpy(hdr.data() + 2, &dp, 2);
    uint32_t sn = htonl(info.seq_num);
    std::memcpy(hdr.data() + 4, &sn, 4);
    uint32_t an = htonl(info.ack_num);
    std::memcpy(hdr.data() + 8, &an, 4);

    hdr[12] = static_cast<uint8_t>((data_offset << 4) & 0xF0);
    hdr[13] = 0;
    if (info.flags.fin) hdr[13] |= 0x01;
    if (info.flags.syn) hdr[13] |= 0x02;
    if (info.flags.rst) hdr[13] |= 0x04;
    if (info.flags.psh) hdr[13] |= 0x08;
    if (info.flags.ack) hdr[13] |= 0x10;
    if (info.flags.urg) hdr[13] |= 0x20;

    uint16_t win = htons(info.window);
    std::memcpy(hdr.data() + 14, &win, 2);

    hdr[16] = 0;
    hdr[17] = 0;

    hdr[18] = 0;
    hdr[19] = 0;

    size_t pos = TCP_HDR_LEN;
    if (info.options.mss > 0) {
        hdr[pos] = 0x02;
        hdr[pos + 1] = 0x04;
        uint16_t mss = htons(info.options.mss);
        std::memcpy(hdr.data() + pos + 2, &mss, 2);
        pos += 4;
    }
    if (info.options.sack_permitted) {
        hdr[pos] = 0x01;
        hdr[pos + 1] = 0x01;
        pos += 2;
    }
    if (info.options.window_scale > 0) {
        hdr[pos] = 0x03;
        hdr[pos + 1] = 0x03;
        hdr[pos + 2] = info.options.window_scale;
        pos += 3;
    }
    if (info.options.has_timestamp) {
        hdr[pos] = 0x08;
        hdr[pos + 1] = 0x0A;
        uint32_t tv = htonl(info.options.ts_val);
        std::memcpy(hdr.data() + pos + 2, &tv, 4);
        uint32_t te = htonl(info.options.ts_ecr);
        std::memcpy(hdr.data() + pos + 6, &te, 4);
        pos += 10;
    }

    uint16_t ck = computeTCPChecksum(hdr.data(), hdr.size(), src_ip, dst_ip);
    std::memcpy(hdr.data() + 16, &ck, 2);

    return hdr;
}

std::vector<uint8_t> PacketBuilder::buildTCPSegment(
    const MAC& dst_mac, const MAC& src_mac,
    const IPHeaderInfo& ip_info,
    const TCPHeaderInfo& tcp_info,
    const uint8_t* payload, size_t payload_len)
{
    auto tcp_hdr = buildTCPHeader(tcp_info, ip_info.src_ip.addr, ip_info.dst_ip.addr);

    uint16_t ip_total = static_cast<uint16_t>(IP_HDR_LEN + tcp_hdr.size() + payload_len);
    auto ip_hdr = buildIPv4Header(ip_info.ttl, ip_info.protocol,
                                   ip_info.src_ip.addr, ip_info.dst_ip.addr, ip_total);

    size_t frame_len = ETH_HDR_LEN + ip_total;
    std::vector<uint8_t> frame(frame_len);
    std::memcpy(frame.data() + 0, dst_mac.bytes.data(), 6);
    std::memcpy(frame.data() + 6, src_mac.bytes.data(), 6);
    uint16_t et = htons(ETH_P_IP);
    std::memcpy(frame.data() + 12, &et, 2);
    std::memcpy(frame.data() + ETH_HDR_LEN, ip_hdr.data(), IP_HDR_LEN);
    std::memcpy(frame.data() + ETH_HDR_LEN + IP_HDR_LEN, tcp_hdr.data(), tcp_hdr.size());
    if (payload && payload_len > 0) {
        std::memcpy(frame.data() + ETH_HDR_LEN + IP_HDR_LEN + tcp_hdr.size(), payload, payload_len);
    }

    return frame;
}

std::vector<uint8_t> PacketBuilder::buildSYN(
    const MAC& dst_mac, const MAC& src_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num,
    const TCPOptions& opts)
{
    TCPHeaderInfo ti{};
    ti.src_port = src_port;
    ti.dst_port = dst_port;
    ti.seq_num = seq_num;
    ti.ack_num = 0;
    ti.flags.syn = true;
    ti.window = 65535;
    ti.options = opts;

    IPHeaderInfo ii{};
    ii.ttl = 64;
    ii.protocol = IPPROTO_TCP;
    ii.src_ip.addr = src_ip;
    ii.dst_ip.addr = dst_ip;

    return buildTCPSegment(dst_mac, src_mac, ii, ti, nullptr, 0);
}

std::vector<uint8_t> PacketBuilder::buildSYNACK(
    const MAC& dst_mac, const MAC& src_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num,
    const TCPOptions& opts)
{
    TCPHeaderInfo ti{};
    ti.src_port = src_port;
    ti.dst_port = dst_port;
    ti.seq_num = seq_num;
    ti.ack_num = ack_num;
    ti.flags.syn = true;
    ti.flags.ack = true;
    ti.window = 65535;
    ti.options = opts;

    IPHeaderInfo ii{};
    ii.ttl = 64;
    ii.protocol = IPPROTO_TCP;
    ii.src_ip.addr = src_ip;
    ii.dst_ip.addr = dst_ip;

    return buildTCPSegment(dst_mac, src_mac, ii, ti, nullptr, 0);
}

std::vector<uint8_t> PacketBuilder::buildACK(
    const MAC& dst_mac, const MAC& src_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num,
    uint16_t window)
{
    TCPHeaderInfo ti{};
    ti.src_port = src_port;
    ti.dst_port = dst_port;
    ti.seq_num = seq_num;
    ti.ack_num = ack_num;
    ti.flags.ack = true;
    ti.window = window;

    IPHeaderInfo ii{};
    ii.ttl = 64;
    ii.protocol = IPPROTO_TCP;
    ii.src_ip.addr = src_ip;
    ii.dst_ip.addr = dst_ip;

    return buildTCPSegment(dst_mac, src_mac, ii, ti, nullptr, 0);
}

std::vector<uint8_t> PacketBuilder::buildPSH_ACK(
    const MAC& dst_mac, const MAC& src_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num,
    const uint8_t* payload, size_t payload_len,
    uint16_t window)
{
    TCPHeaderInfo ti{};
    ti.src_port = src_port;
    ti.dst_port = dst_port;
    ti.seq_num = seq_num;
    ti.ack_num = ack_num;
    ti.flags.psh = true;
    ti.flags.ack = true;
    ti.window = window;

    IPHeaderInfo ii{};
    ii.ttl = 64;
    ii.protocol = IPPROTO_TCP;
    ii.src_ip.addr = src_ip;
    ii.dst_ip.addr = dst_ip;

    return buildTCPSegment(dst_mac, src_mac, ii, ti, payload, payload_len);
}

std::vector<uint8_t> PacketBuilder::buildFIN_ACK(
    const MAC& dst_mac, const MAC& src_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num)
{
    TCPHeaderInfo ti{};
    ti.src_port = src_port;
    ti.dst_port = dst_port;
    ti.seq_num = seq_num;
    ti.ack_num = ack_num;
    ti.flags.fin = true;
    ti.flags.ack = true;
    ti.window = 65535;

    IPHeaderInfo ii{};
    ii.ttl = 64;
    ii.protocol = IPPROTO_TCP;
    ii.src_ip.addr = src_ip;
    ii.dst_ip.addr = dst_ip;

    return buildTCPSegment(dst_mac, src_mac, ii, ti, nullptr, 0);
}

std::vector<uint8_t> PacketBuilder::buildRST(
    const MAC& dst_mac, const MAC& src_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num)
{
    TCPHeaderInfo ti{};
    ti.src_port = src_port;
    ti.dst_port = dst_port;
    ti.seq_num = seq_num;
    ti.ack_num = ack_num;
    ti.flags.rst = true;
    ti.flags.ack = (ack_num != 0);
    ti.window = 0;

    IPHeaderInfo ii{};
    ii.ttl = 64;
    ii.protocol = IPPROTO_TCP;
    ii.src_ip.addr = src_ip;
    ii.dst_ip.addr = dst_ip;

    return buildTCPSegment(dst_mac, src_mac, ii, ti, nullptr, 0);
}

std::vector<uint8_t> PacketBuilder::buildKeepalive(
    const MAC& dst_mac, const MAC& src_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num)
{
    TCPHeaderInfo ti{};
    ti.src_port = src_port;
    ti.dst_port = dst_port;
    ti.seq_num = seq_num - 1;
    ti.ack_num = ack_num;
    ti.flags.ack = true;
    ti.window = 65535;

    IPHeaderInfo ii{};
    ii.ttl = 64;
    ii.protocol = IPPROTO_TCP;
    ii.src_ip.addr = src_ip;
    ii.dst_ip.addr = dst_ip;

    uint8_t byte = 0;
    return buildTCPSegment(dst_mac, src_mac, ii, ti, &byte, 1);
}

std::vector<uint8_t> PacketBuilder::buildDataSegment(
    const MAC& dst_mac, const MAC& src_mac,
    uint32_t src_ip, uint32_t dst_ip,
    uint16_t src_port, uint16_t dst_port,
    uint32_t seq_num, uint32_t ack_num,
    const uint8_t* data, size_t data_len,
    bool push, uint16_t window)
{
    TCPHeaderInfo ti{};
    ti.src_port = src_port;
    ti.dst_port = dst_port;
    ti.seq_num = seq_num;
    ti.ack_num = ack_num;
    ti.flags.psh = push;
    ti.flags.ack = true;
    ti.window = window;

    IPHeaderInfo ii{};
    ii.ttl = 64;
    ii.protocol = IPPROTO_TCP;
    ii.src_ip.addr = src_ip;
    ii.dst_ip.addr = dst_ip;

    return buildTCPSegment(dst_mac, src_mac, ii, ti, data, data_len);
}

// ── ARP (RFC 826) ────────────────────────────────────────────────────

std::vector<uint8_t> PacketBuilder::buildARPRequest(
    const MAC& src_mac, uint32_t sender_ip, uint32_t target_ip)
{
    std::vector<uint8_t> frame(ETH_HDR_LEN + ARP_HDR_LEN, 0);

    // Ethernet header
    MAC bcast = MAC::broadcast();
    std::memcpy(frame.data() + 0, bcast.bytes.data(), 6);
    std::memcpy(frame.data() + 6, src_mac.bytes.data(), 6);
    uint16_t etype = htons(ARP_ETHERTYPE);
    std::memcpy(frame.data() + 12, &etype, 2);

    // ARP body
    uint8_t* arp = frame.data() + ETH_HDR_LEN;
    uint16_t htype = htons(1);              // Ethernet
    uint16_t ptype = htons(0x0800);         // IPv4
    std::memcpy(arp + 0, &htype, 2);
    std::memcpy(arp + 2, &ptype, 2);
    arp[4] = 6;                             // hardware addr len
    arp[5] = 4;                             // protocol addr len
    uint16_t op = htons(1);                 // ARP request
    std::memcpy(arp + 6, &op, 2);
    std::memcpy(arp + 8, src_mac.bytes.data(), 6);   // sender hardware
    uint32_t sip = htonl(sender_ip);
    std::memcpy(arp + 14, &sip, 4);                   // sender protocol
    std::memset(arp + 18, 0, 6);                      // target hardware = 0
    uint32_t tip = htonl(target_ip);
    std::memcpy(arp + 24, &tip, 4);                   // target protocol

    return frame;
}

bool PacketBuilder::parseARPReply(const uint8_t* frame, size_t len,
                                  MAC& out_mac, uint32_t& out_ip) {
    if (!frame || len < ETH_HDR_LEN + ARP_HDR_LEN) return false;

    uint16_t etype;
    std::memcpy(&etype, frame + 12, 2);
    if (ntohs(etype) != ARP_ETHERTYPE) return false;

    const uint8_t* arp = frame + ETH_HDR_LEN;
    if (arp[4] != 6 || arp[5] != 4) return false;

    uint16_t op;
    std::memcpy(&op, arp + 6, 2);
    if (ntohs(op) != 2) return false;       // ARP reply only

    uint8_t mac_bytes[6];
    std::memcpy(mac_bytes, arp + 8, 6);
    out_mac.bytes = {mac_bytes[0], mac_bytes[1], mac_bytes[2],
                     mac_bytes[3], mac_bytes[4], mac_bytes[5]};

    uint32_t ip_net;
    std::memcpy(&ip_net, arp + 14, 4);
    out_ip = ntohl(ip_net);
    return true;
}
