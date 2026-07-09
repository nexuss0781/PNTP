#include "pntp/tcp_engine.h"
#include "pntp/http1_parser.h"
#include <cstring>
#include <cstdlib>
#include <cmath>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <net/if.h>
#include <poll.h>
#include <algorithm>
#include <iostream>

const char* tcpStateToString(TCPState s) {
    switch (s) {
        case TCPState::CLOSED:      return "CLOSED";
        case TCPState::LISTEN:      return "LISTEN";
        case TCPState::SYN_SENT:    return "SYN_SENT";
        case TCPState::SYN_RECEIVED:return "SYN_RECEIVED";
        case TCPState::ESTABLISHED: return "ESTABLISHED";
        case TCPState::FIN_WAIT_1:  return "FIN_WAIT_1";
        case TCPState::FIN_WAIT_2:  return "FIN_WAIT_2";
        case TCPState::CLOSE_WAIT:  return "CLOSE_WAIT";
        case TCPState::CLOSING:     return "CLOSING";
        case TCPState::LAST_ACK:    return "LAST_ACK";
        case TCPState::TIME_WAIT:   return "TIME_WAIT";
    }
    return "UNKNOWN";
}

// ── RTT Estimator (RFC 6298) ─────────────────────────────────────────

void RTTEstimator::update(uint64_t measured_rtt_us) {
    if (!initialized) {
        srtt_us = measured_rtt_us;
        rttvar_us = measured_rtt_us / 2;
        initialized = true;
    } else {
        int64_t delta = static_cast<int64_t>(measured_rtt_us) - static_cast<int64_t>(srtt_us);
        rttvar_us = (3 * rttvar_us + static_cast<uint64_t>(std::abs(delta))) / 4;
        srtt_us = (7 * srtt_us + measured_rtt_us) / 8;
    }
    rto_us = srtt_us + std::max(RTO_MIN_US, K_RTT * rttvar_us);
    if (rto_us < RTO_MIN_US) rto_us = RTO_MIN_US;
    if (rto_us > RTO_MAX_US) rto_us = RTO_MAX_US;
}

void RTTEstimator::backoff() {
    rto_us *= 2;
    if (rto_us > RTO_MAX_US) rto_us = RTO_MAX_US;
}

void RTTEstimator::reset() {
    rto_us = INITIAL_RTO;
}

// ── CUBIC Congestion Control ─────────────────────────────────────────

double CUBICState::cubicFunction(uint64_t t) const {
    double t_d = static_cast<double>(t) / 1000000.0;
    double k_d = static_cast<double>(k) / 1000000.0;
    return 4.0 * (t_d - k_d) * (t_d - k_d) * (t_d - k_d) + w_max;
}

void CUBICState::onCongestionEvent(uint64_t current_tsc) {
    w_max = static_cast<double>(cwnd);
    ssthresh = std::max(cwnd / 2, 2U * 1460);
    cwnd = ssthresh;
    epoch_start = current_tsc;
    k = static_cast<uint64_t>(std::cbrt(w_max * 0.3 / 4.0) * 1000000.0);
    dup_acks = 0;
    recovery = true;
}

void CUBICState::onAck(uint32_t bytes_acked, uint64_t current_tsc) {
    if (recovery) {
        cwnd += bytes_acked;
        if (cwnd >= static_cast<uint32_t>(w_max)) {
            recovery = false;
        }
        return;
    }

    if (cwnd < ssthresh) {
        cwnd += bytes_acked;
    } else {
        uint64_t elapsed = current_tsc - epoch_start;
        double w_cubic_new = cubicFunction(elapsed);
        if (w_cubic_new > static_cast<double>(cwnd) + 1460) {
            cwnd = static_cast<uint32_t>(w_cubic_new);
        } else {
            cwnd += 1460;
        }
    }
    dup_acks = 0;
}

// ── TCPEngine ────────────────────────────────────────────────────────

TCPEngine::TCPEngine() = default;

TCPEngine::~TCPEngine() = default;

bool TCPEngine::initialize(const std::string& interface) {
    if (!raw_sock.init(interface)) {
        return false;
    }
    auto filters = RawSocketHandler::makeBPF_TCPOnly();
    raw_sock.attachBPF(filters);

    int fd = raw_sock.getFd();
    if (fd >= 0) {
        struct sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

        struct ifreq ifr{};
        interface.copy(ifr.ifr_name, IFNAMSIZ - 1);
        int tmp = socket(AF_INET, SOCK_DGRAM, 0);
        if (tmp >= 0) {
            if (ioctl(tmp, SIOCGIFADDR, &ifr) == 0) {
                local_ip = ntohl(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr)->sin_addr.s_addr);
            }
            ::close(tmp);
        }
    }
    return true;
}

void TCPEngine::setLocalMAC(const MAC& mac) {
    local_mac = mac;
}

void TCPEngine::setLocalIP(uint32_t ip) {
    local_ip = ip;
}

uint16_t TCPEngine::allocatePort() {
    return static_cast<uint16_t>(40000 + (ip_id_counter++ % 25000));
}

uint32_t TCPEngine::generateISS() {
    uint32_t tsc_lo = static_cast<uint32_t>(get_rdtsc_serialized());
    uint64_t rand_val = stealth_rand();
    return tsc_lo ^ static_cast<uint32_t>(rand_val) ^ (static_cast<uint32_t>(rand_val >> 32) * 6364136223846793005ULL);
}

bool TCPEngine::resolveHost(const std::string& host, uint32_t& out_ip, MAC& out_mac) {
    auto dns_result = dns_resolver_.resolve(host, pntp::RecordType::A, 5000);
    if (!dns_result.success || dns_result.ipv4_addresses.empty()) {
        return false;
    }

    out_ip = dns_result.ipv4_addresses[0];
    out_mac.bytes = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    return true;
}

TCPConnection* TCPEngine::open(const std::string& host, uint16_t port, uint32_t timeout_ms) {
    (void)timeout_ms;

    uint32_t dst_ip = 0;
    MAC dst_mac;
    if (!resolveHost(host, dst_ip, dst_mac)) {
        return nullptr;
    }

    auto conn = std::make_unique<TCPConnection>();
    conn->src_port = allocatePort();
    conn->dst_port = port;
    conn->src_ip = local_ip;
    conn->dst_ip = dst_ip;
    conn->src_mac = local_mac;
    conn->dst_mac = dst_mac;
    conn->iss = generateISS();
    conn->snd_nxt = conn->iss;
    conn->snd_una = conn->iss;
    conn->opts.local_mss = 1460;
    conn->opts.local_winscale = 7;
    conn->opts.sack_permitted = true;
    conn->opts.ts_enabled = true;
    conn->opts.ts_val = static_cast<uint32_t>(get_rdtsc_serialized());
    conn->connect_start_tsc = get_rdtsc_serialized();
    conn->last_activity_tsc = conn->connect_start_tsc;

    conn->cubic.cwnd = 10 * 1460;
    conn->cubic.ssthresh = 65535;

    uint16_t port_key = conn->src_port;
    TCPConnection* raw_ptr = conn.get();
    connections[port_key] = std::move(conn);

    if (!sendSYN(raw_ptr)) {
        connections.erase(port_key);
        return nullptr;
    }

    transitionTo(raw_ptr, TCPState::SYN_SENT);
    raw_ptr->connect_start_tsc = get_rdtsc_serialized();

    struct pollfd pfd{};
    pfd.fd = raw_sock.getFd();
    pfd.events = POLLIN;

    uint64_t deadline = raw_ptr->connect_start_tsc + static_cast<uint64_t>(timeout_ms) * 3000ULL;
    while (raw_ptr->state == TCPState::SYN_SENT) {
        uint64_t now = get_rdtsc_serialized();
        if (now > deadline) {
            transitionTo(raw_ptr, TCPState::CLOSED);
            sendRST(raw_ptr, raw_ptr->snd_nxt, 0);
            connections.erase(port_key);
            return nullptr;
        }

        int ret = poll(&pfd, 1, 10);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            PacketView pkt = raw_sock.acquirePacket();
            if (pkt) {
                processIncomingPacket(raw_ptr, pkt);
                raw_sock.releasePacket(pkt);
            }
        }
    }

    if (raw_ptr->state != TCPState::ESTABLISHED) {
        TCPConnection* result = raw_ptr;
        connections.erase(port_key);
        return nullptr;
    }

    return raw_ptr;
}

bool TCPEngine::send(TCPConnection* conn, const uint8_t* data, size_t len) {
    if (!conn || conn->state != TCPState::ESTABLISHED) return false;

    size_t offset = 0;
    while (offset < len) {
        uint32_t in_flight = conn->snd_nxt - conn->snd_una;
        uint32_t win = conn->cubic.getWindowSize();
        uint32_t avail = (in_flight < win) ? (win - in_flight) : 0u;
        size_t chunk = std::min(static_cast<size_t>(std::min(avail, static_cast<uint32_t>(conn->opts.local_mss))), len - offset);

        if (chunk == 0) {
            PacketView pkt = raw_sock.acquirePacket();
            if (pkt) {
                processIncomingPacket(conn, pkt);
                raw_sock.releasePacket(pkt);
            }
            continue;
        }

        bool push = (offset + chunk == len);
        auto frame = PacketBuilder::buildDataSegment(
            conn->dst_mac, conn->src_mac,
            conn->src_ip, conn->dst_ip,
            conn->src_port, conn->dst_port,
            conn->snd_nxt, conn->rcv_nxt,
            data + offset, chunk, push, conn->rcv_wnd);

        if (!sendRawPacket(conn, frame)) return false;

        SendSegment seg;
        seg.seq = conn->snd_nxt;
        seg.len = static_cast<uint32_t>(chunk);
        seg.sent_tsc = get_rdtsc_serialized();
        seg.acked = false;
        seg.fast_retransmitted = false;
        seg.data.assign(data + offset, data + offset + chunk);
        conn->send_queue.push_back(seg);

        auto ret_seg = seg;
        conn->retransmit_queue.push_back(ret_seg);

        conn->snd_nxt += chunk;
        offset += chunk;
    }
    return true;
}

ReceiveResult TCPEngine::recv(TCPConnection* conn, uint32_t timeout_ms) {
    ReceiveResult result;
    if (!conn) { result.error = true; return result; }

    result.state = conn->state;

    if (conn->state == TCPState::CLOSED) {
        result.closed = true;
        return result;
    }

    if (conn->state == TCPState::ESTABLISHED && !conn->ooo_queue.empty()) {
        auto& front = conn->ooo_queue.front();
        if (front.seq == conn->rcv_nxt) {
            result.data = std::move(front.data);
            conn->rcv_nxt += static_cast<uint32_t>(result.data.size());
            conn->ooo_queue.erase(conn->ooo_queue.begin());
            result.valid = true;
            result.state = conn->state;
            return result;
        }
    }

    struct pollfd pfd{};
    pfd.fd = raw_sock.getFd();
    pfd.events = POLLIN;

    uint64_t start_tsc = get_rdtsc_serialized();
    uint64_t timeout_cycles = static_cast<uint64_t>(timeout_ms) * 3000ULL;

    while (true) {
        uint64_t now = get_rdtsc_serialized();
        if (now - start_tsc > timeout_cycles) break;

        int ret = poll(&pfd, 1, 10);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            PacketView pkt = raw_sock.acquirePacket();
            if (pkt) {
                bool delivered = processIncomingPacket(conn, pkt);
                raw_sock.releasePacket(pkt);

                if (delivered && !conn->ooo_queue.empty()) {
                    auto& front = conn->ooo_queue.front();
                    if (front.seq == conn->rcv_nxt) {
                        result.data = std::move(front.data);
                        conn->rcv_nxt += static_cast<uint32_t>(result.data.size());
                        conn->ooo_queue.erase(conn->ooo_queue.begin());
                        result.valid = true;
                        break;
                    }
                }

                if (conn->state == TCPState::CLOSE_WAIT) {
                    result.closed = true;
                    break;
                }
            }
        }

        checkRetransmit(conn, get_rdtsc_serialized());
    }

    result.state = conn->state;
    return result;
}

void TCPEngine::close(TCPConnection* conn) {
    if (!conn) return;

    if (conn->state == TCPState::ESTABLISHED) {
        sendFIN(conn);
        transitionTo(conn, TCPState::FIN_WAIT_1);
    } else if (conn->state == TCPState::CLOSE_WAIT) {
        sendFIN(conn);
        transitionTo(conn, TCPState::LAST_ACK);
    }

    struct pollfd pfd{};
    pfd.fd = raw_sock.getFd();
    pfd.events = POLLIN;

    uint64_t start_tsc = get_rdtsc_serialized();
    while (conn->state != TCPState::CLOSED && conn->state != TCPState::TIME_WAIT) {
        uint64_t now = get_rdtsc_serialized();
        if (now - start_tsc > 5000000ULL) break;

        int ret = poll(&pfd, 1, 10);
        if (ret > 0 && (pfd.revents & POLLIN)) {
            PacketView pkt = raw_sock.acquirePacket();
            if (pkt) {
                processIncomingPacket(conn, pkt);
                raw_sock.releasePacket(pkt);
            }
        }
    }

    if (conn->state == TCPState::TIME_WAIT) {
        usleep(TIME_WAIT_MS * 1000);
        transitionTo(conn, TCPState::CLOSED);
    }
}

bool TCPEngine::processIncomingPacket(TCPConnection* conn, const PacketView& pkt) {
    auto* ip = RawSocketHandler::getIPv4Header(pkt);
    if (!ip) return false;
    if (ip->protocol != IPPROTO_TCP) return false;

    auto* tcp = RawSocketHandler::getTCPHeader(pkt);
    if (!tcp) return false;

    uint16_t src_port = ntohs(tcp->source);
    uint16_t dst_port = ntohs(tcp->dest);

    if (src_port != conn->dst_port || dst_port != conn->src_port) return false;

    uint32_t seq_num = ntohl(tcp->seq);
    uint32_t ack_num = ntohl(tcp->ack_seq);
    uint8_t data_offset = tcp->doff;
    size_t tcp_hdr_len = static_cast<size_t>(data_offset) * 4;

    size_t ip_hdr_len = static_cast<size_t>(ip->ihl) * 4;
    size_t total_ip_len = ntohs(ip->tot_len);
    size_t payload_len = 0;
    if (total_ip_len > ip_hdr_len + tcp_hdr_len) {
        payload_len = total_ip_len - ip_hdr_len - tcp_hdr_len;
    }

    bool is_fin = tcp->fin;
    bool is_syn = tcp->syn;
    bool is_rst = tcp->rst;
    bool is_ack = tcp->ack;
    (void)tcp->psh;

    if (is_rst) {
        handleRST(conn);
        return false;
    }

    if (is_syn && is_ack && conn->state == TCPState::SYN_SENT) {
        handleSYNACK(conn, tcp);
        return true;
    }

    if (is_syn && !is_ack) {
        handleSYN(conn, tcp);
        return true;
    }

    if (conn->state == TCPState::SYN_RECEIVED && is_ack) {
        uint32_t expected_ack = conn->iss + 1;
        if (ack_num == expected_ack) {
            conn->snd_una = ack_num;
            conn->snd_wnd = ntohs(tcp->window);
            transitionTo(conn, TCPState::ESTABLISHED);
            conn->rtt.update((get_rdtsc_serialized() - conn->connect_start_tsc) / 3000ULL);
            return true;
        }
    }

    if (is_ack) {
        handleACK(conn, tcp, payload_len);
    }

    if (payload_len > 0 && conn->state == TCPState::ESTABLISHED) {
        const uint8_t* payload = reinterpret_cast<const uint8_t*>(tcp) + tcp_hdr_len;
        uint32_t seg_seq = seq_num;

        if (seg_seq == conn->rcv_nxt) {
            std::vector<uint8_t> data(payload, payload + payload_len);
            conn->ooo_queue.push_back({seg_seq, std::move(data)});
            conn->rcv_nxt += static_cast<uint32_t>(payload_len);

            while (!conn->ooo_queue.empty() && conn->ooo_queue.front().seq == conn->rcv_nxt) {
                auto& front = conn->ooo_queue.front();
                conn->rcv_nxt += static_cast<uint32_t>(front.data.size());
                conn->ooo_queue.erase(conn->ooo_queue.begin());
            }

            auto ack_frame = PacketBuilder::buildACK(
                conn->dst_mac, conn->src_mac,
                conn->src_ip, conn->dst_ip,
                conn->src_port, conn->dst_port,
                conn->snd_nxt, conn->rcv_nxt, conn->rcv_wnd);
            sendRawPacket(conn, ack_frame);
            return true;
        } else if (seg_seq > conn->rcv_nxt) {
            std::vector<uint8_t> data(payload, payload + payload_len);
            bool found = false;
            for (auto& seg : conn->ooo_queue) {
                if (seg.seq == seg_seq) { found = true; break; }
            }
            if (!found) {
                conn->ooo_queue.push_back({seg_seq, std::move(data)});
                std::sort(conn->ooo_queue.begin(), conn->ooo_queue.end(),
                    [](const OutOfOrderSegment& a, const OutOfOrderSegment& b) { return a.seq < b.seq; });
            }

            auto dup_ack = PacketBuilder::buildACK(
                conn->dst_mac, conn->src_mac,
                conn->src_ip, conn->dst_ip,
                conn->src_port, conn->dst_port,
                conn->snd_nxt, conn->rcv_nxt, conn->rcv_wnd);
            sendRawPacket(conn, dup_ack);
            return false;
        }
    }

    if (is_fin) {
        handleFIN(conn, tcp);
        return true;
    }

    return false;
}

void TCPEngine::checkRetransmit(TCPConnection* conn, uint64_t current_tsc) {
    if (!conn) return;
    if (conn->state != TCPState::ESTABLISHED && conn->state != TCPState::FIN_WAIT_1) return;

    // Convert RTO from microseconds to approximate TSC cycles (~3000 cycles/us on modern x86)
    constexpr uint64_t TSC_PER_US = 3000;
    uint64_t rto_cycles = conn->rtt.rto_us * TSC_PER_US;

    auto it = conn->retransmit_queue.begin();
    while (it != conn->retransmit_queue.end()) {
        if (!it->acked && !it->fast_retransmitted) {
            uint64_t elapsed = current_tsc - it->sent_tsc;
            if (elapsed > rto_cycles) {
                conn->cubic.onCongestionEvent(current_tsc);
                conn->rtt.backoff();

                auto frame = PacketBuilder::buildDataSegment(
                    conn->dst_mac, conn->src_mac,
                    conn->src_ip, conn->dst_ip,
                    conn->src_port, conn->dst_port,
                    it->seq, conn->rcv_nxt,
                    it->data.data(), it->data.size(), true, conn->rcv_wnd);
                sendRawPacket(conn, frame);

                it->sent_tsc = current_tsc;
                it->fast_retransmitted = true;
                break;
            }
        }
        ++it;
    }

    processRetransmitQueue(conn);
}

void TCPEngine::processRetransmitQueue(TCPConnection* conn) {
    conn->retransmit_queue.erase(
        std::remove_if(conn->retransmit_queue.begin(), conn->retransmit_queue.end(),
            [](const SendSegment& s) { return s.acked; }),
        conn->retransmit_queue.end());
}

bool TCPEngine::sendRawPacket(const TCPConnection* conn, const std::vector<uint8_t>& packet) {
    return raw_sock.injectPacket(packet.data(), packet.size());
}

bool TCPEngine::sendSYN(TCPConnection* conn) {
    TCPOptions opts;
    opts.mss = conn->opts.local_mss;
    opts.sack_permitted = conn->opts.sack_permitted;
    opts.window_scale = conn->opts.local_winscale;
    opts.has_timestamp = conn->opts.ts_enabled;
    opts.ts_val = static_cast<uint32_t>(get_rdtsc_serialized());

    auto frame = PacketBuilder::buildSYN(
        conn->dst_mac, conn->src_mac,
        conn->src_ip, conn->dst_ip,
        conn->src_port, conn->dst_port,
        conn->iss, opts);

    return sendRawPacket(conn, frame);
}

bool TCPEngine::sendACK(const TCPConnection* conn) {
    auto frame = PacketBuilder::buildACK(
        conn->dst_mac, conn->src_mac,
        conn->src_ip, conn->dst_ip,
        conn->src_port, conn->dst_port,
        conn->snd_nxt, conn->rcv_nxt, conn->rcv_wnd);
    return sendRawPacket(conn, frame);
}

bool TCPEngine::sendData(TCPConnection* conn, const uint8_t* data, size_t len, bool push) {
    auto frame = PacketBuilder::buildDataSegment(
        conn->dst_mac, conn->src_mac,
        conn->src_ip, conn->dst_ip,
        conn->src_port, conn->dst_port,
        conn->snd_nxt, conn->rcv_nxt,
        data, len, push, conn->rcv_wnd);

    if (!sendRawPacket(conn, frame)) return false;

    SendSegment seg;
    seg.seq = conn->snd_nxt;
    seg.len = static_cast<uint32_t>(len);
    seg.sent_tsc = get_rdtsc_serialized();
    seg.acked = false;
    seg.fast_retransmitted = false;
    seg.data.assign(data, data + len);
    conn->send_queue.push_back(seg);
    conn->retransmit_queue.push_back(seg);

    conn->snd_nxt += static_cast<uint32_t>(len);
    return true;
}

bool TCPEngine::sendFIN(TCPConnection* conn) {
    auto frame = PacketBuilder::buildFIN_ACK(
        conn->dst_mac, conn->src_mac,
        conn->src_ip, conn->dst_ip,
        conn->src_port, conn->dst_port,
        conn->snd_nxt, conn->rcv_nxt);
    if (!sendRawPacket(conn, frame)) return false;

    conn->fin_sent = true;
    conn->fin_seq = conn->snd_nxt;
    conn->snd_nxt += 1;
    return true;
}

bool TCPEngine::sendRST(TCPConnection* conn, uint32_t seq, uint32_t ack) {
    auto frame = PacketBuilder::buildRST(
        conn->dst_mac, conn->src_mac,
        conn->src_ip, conn->dst_ip,
        conn->src_port, conn->dst_port,
        seq, ack);
    return sendRawPacket(conn, frame);
}

void TCPEngine::handleSYNACK(TCPConnection* conn, const struct tcphdr* tcp) {
    if (conn->state != TCPState::SYN_SENT) return;

    uint32_t ack_num = ntohl(tcp->ack_seq);
    if (ack_num != conn->iss + 1) {
        sendRST(conn, conn->snd_nxt, ack_num);
        transitionTo(conn, TCPState::CLOSED);
        return;
    }

    conn->irs = ntohl(tcp->seq);
    conn->rcv_nxt = conn->irs + 1;
    conn->snd_una = ack_num;
    conn->snd_wnd = ntohs(tcp->window);

    uint8_t data_offset = tcp->doff;
    size_t tcp_hdr_len = static_cast<size_t>(data_offset) * 4;
    const uint8_t* opts_ptr = reinterpret_cast<const uint8_t*>(tcp) + PacketBuilder::TCP_HDR_LEN;
    size_t opts_len = tcp_hdr_len - PacketBuilder::TCP_HDR_LEN;

    size_t pos = 0;
    while (pos + 1 < opts_len) {
        uint8_t kind = opts_ptr[pos];
        if (kind == 0) break;
        if (kind == 1) { pos++; continue; }

        uint8_t opt_len = opts_ptr[pos + 1];
        if (opt_len < 2 || pos + opt_len > opts_len) break;

        if (kind == 2 && opt_len == 4) {
            conn->opts.remote_mss = (static_cast<uint16_t>(opts_ptr[pos + 2]) << 8) | opts_ptr[pos + 3];
        } else if (kind == 3 && opt_len == 3) {
            conn->opts.remote_winscale = opts_ptr[pos + 2];
            conn->snd_wnd_scale = conn->opts.remote_winscale;
        } else if (kind == 1 && opt_len == 2) {
            conn->opts.sack_permitted = true;
        } else if (kind == 8 && opt_len == 10) {
            conn->opts.ts_enabled = true;
            conn->opts.ts_val = (static_cast<uint32_t>(opts_ptr[pos + 2]) << 24) |
                                (static_cast<uint32_t>(opts_ptr[pos + 3]) << 16) |
                                (static_cast<uint32_t>(opts_ptr[pos + 4]) << 8) |
                                 static_cast<uint32_t>(opts_ptr[pos + 5]);
            conn->opts.ts_ecr = (static_cast<uint32_t>(opts_ptr[pos + 6]) << 24) |
                                (static_cast<uint32_t>(opts_ptr[pos + 7]) << 16) |
                                (static_cast<uint32_t>(opts_ptr[pos + 8]) << 8) |
                                 static_cast<uint32_t>(opts_ptr[pos + 9]);
        }

        pos += opt_len;
    }

    auto ack_frame = PacketBuilder::buildACK(
        conn->dst_mac, conn->src_mac,
        conn->src_ip, conn->dst_ip,
        conn->src_port, conn->dst_port,
        conn->snd_nxt, conn->rcv_nxt, conn->rcv_wnd);
    sendRawPacket(conn, ack_frame);

    conn->snd_una = conn->snd_nxt;
    transitionTo(conn, TCPState::ESTABLISHED);

    uint64_t now = get_rdtsc_serialized();
    uint64_t rtt_cycles = now - conn->connect_start_tsc;
    conn->rtt.update(rtt_cycles / 3000ULL);
}

void TCPEngine::handleACK(TCPConnection* conn, const struct tcphdr* tcp, size_t payload_len) {
    (void)payload_len;
    uint32_t ack_num = ntohl(tcp->ack_seq);

    if (ack_num > conn->snd_una) {
        uint32_t bytes_acked = ack_num - conn->snd_una;
        conn->snd_una = ack_num;
        conn->snd_wnd = ntohs(tcp->window);

        uint64_t now = get_rdtsc_serialized();
        for (auto& seg : conn->send_queue) {
            if (!seg.acked && seg.seq + seg.len <= ack_num) {
                seg.acked = true;
                uint64_t seg_rtt = (now - seg.sent_tsc) / 3000ULL;
                conn->rtt.update(seg_rtt);
            }
        }

        conn->cubic.onAck(bytes_acked, now);

        for (auto& seg : conn->retransmit_queue) {
            if (seg.seq + seg.len <= ack_num) {
                seg.acked = true;
            }
        }

        processRetransmitQueue(conn);
        conn->dup_ack_count = 0;
    } else if (ack_num == conn->snd_una) {
        conn->dup_ack_count++;
        if (conn->dup_ack_count >= FAST_RETRANSMIT_DUP_ACKS && !conn->retransmit_queue.empty()) {
            auto& oldest = conn->retransmit_queue.front();
            if (!oldest.acked) {
                oldest.sent_tsc = get_rdtsc_serialized();
                oldest.fast_retransmitted = true;

                auto frame = PacketBuilder::buildDataSegment(
                    conn->dst_mac, conn->src_mac,
                    conn->src_ip, conn->dst_ip,
                    conn->src_port, conn->dst_port,
                    oldest.seq, conn->rcv_nxt,
                    oldest.data.data(), oldest.data.size(), true, conn->rcv_wnd);
                sendRawPacket(conn, frame);

                conn->cubic.onCongestionEvent(get_rdtsc_serialized());
            }
            conn->dup_ack_count = 0;
        }
    }
}

void TCPEngine::handleFIN(TCPConnection* conn, const struct tcphdr* tcp) {
    uint32_t fin_seq = ntohl(tcp->seq);
    conn->fin_received = true;

    auto ack_frame = PacketBuilder::buildACK(
        conn->dst_mac, conn->src_mac,
        conn->src_ip, conn->dst_ip,
        conn->src_port, conn->dst_port,
        conn->snd_nxt, fin_seq + 1, conn->rcv_wnd);
    sendRawPacket(conn, ack_frame);
    conn->rcv_nxt = fin_seq + 1;

    switch (conn->state) {
        case TCPState::ESTABLISHED:
            transitionTo(conn, TCPState::CLOSE_WAIT);
            break;
        case TCPState::FIN_WAIT_1:
            if (conn->fin_sent) {
                transitionTo(conn, TCPState::CLOSING);
            } else {
                transitionTo(conn, TCPState::FIN_WAIT_2);
            }
            break;
        case TCPState::FIN_WAIT_2:
            transitionTo(conn, TCPState::TIME_WAIT);
            break;
        case TCPState::CLOSING:
            transitionTo(conn, TCPState::TIME_WAIT);
            break;
        default:
            break;
    }
}

void TCPEngine::handleRST(TCPConnection* conn) {
    transitionTo(conn, TCPState::CLOSED);
}

void TCPEngine::handleSYN(TCPConnection* conn, const struct tcphdr* tcp) {
    if (conn->state == TCPState::SYN_SENT) {
        uint32_t seq_num = ntohl(tcp->seq);
        uint32_t ack_num = ntohl(tcp->ack_seq);
        if (ack_num == conn->iss + 1) {
            conn->irs = seq_num;
            conn->rcv_nxt = seq_num + 1;
            conn->snd_una = ack_num;
            transitionTo(conn, TCPState::SYN_RECEIVED);

            auto synack = PacketBuilder::buildSYNACK(
                conn->dst_mac, conn->src_mac,
                conn->src_ip, conn->dst_ip,
                conn->src_port, conn->dst_port,
                conn->iss, conn->rcv_nxt);
            sendRawPacket(conn, synack);
        }
    }
}

void TCPEngine::transitionTo(TCPConnection* conn, TCPState new_state) {
    conn->state = new_state;
    conn->last_activity_tsc = get_rdtsc_serialized();
}

TCPState TCPEngine::getState(const TCPConnection* conn) const {
    return conn ? conn->state : TCPState::CLOSED;
}

std::string TCPEngine::transcendentFetch(const std::string& url) {
    std::string host;
    uint16_t port = 80;
    std::string path = "/";

    std::string cleaned = url;
    if (cleaned.find("http://") == 0) cleaned = cleaned.substr(7);

    size_t slash_pos = cleaned.find('/');
    std::string hostport = (slash_pos != std::string::npos) ? cleaned.substr(0, slash_pos) : cleaned;
    if (slash_pos != std::string::npos) path = cleaned.substr(slash_pos);

    size_t colon_pos = hostport.find(':');
    if (colon_pos != std::string::npos) {
        host = hostport.substr(0, colon_pos);
        port = static_cast<uint16_t>(std::stoi(hostport.substr(colon_pos + 1)));
    } else {
        host = hostport;
    }

    TCPConnection* conn = open(host, port, 5000);
    if (!conn) return "";

    // Build HTTP/1.1 request via serializer
    Http1Request req;
    req.method = H1_GET;
    req.path = path;
    req.version = H1_VER_1_1;
    std::vector<Http1Header> req_headers = {{"Host", host}, {"Connection", "close"}};
    auto request = Http1Parser::serializeRequest(req, req_headers, nullptr, 0);

    if (!send(conn, request.data(), request.size())) {
        close(conn);
        return "";
    }

    std::vector<uint8_t> response_body;
    for (int i = 0; i < 50; ++i) {
        auto result = recv(conn, 500);
        if (result.valid) {
            response_body.insert(response_body.end(), result.data.begin(), result.data.end());
        }
        if (result.closed || conn->state == TCPState::CLOSE_WAIT) break;
    }

    close(conn);

    // Parse response via Http1Parser
    Http1Parser parser;
    parser.feed(response_body.data(), response_body.size());
    if (parser.isComplete() && parser.isResponse() &&
        parser.getResponse().status_code / 100 == 2) {
        auto body = parser.getBody();
        return std::string(body.begin(), body.end());
    }

    // Fallback: return everything if parsing fails
    return std::string(response_body.begin(), response_body.end());
}
