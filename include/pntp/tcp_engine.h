#ifndef PNTP_TCP_ENGINE_H
#define PNTP_TCP_ENGINE_H

#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <map>
#include <memory>
#include <functional>
#include "pntp/raw_socket_handler.h"
#include "pntp/packet_builder.h"
#include "pntp/pntp_core.h"
#include "pntp/dns_resolver.h"

enum class TCPState : uint8_t {
    CLOSED = 0,
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT
};

const char* tcpStateToString(TCPState s);

struct TCPOptionNegotiation {
    uint16_t local_mss = 1460;
    uint16_t remote_mss = 0;
    uint8_t  local_winscale = 7;
    uint8_t  remote_winscale = 0;
    bool     sack_permitted = false;
    bool     ts_enabled = false;
    uint32_t ts_val = 0;
    uint32_t ts_ecr = 0;
};

struct RTTEstimator {
    uint64_t srtt_us = 0;
    uint64_t rttvar_us = 0;
    uint64_t rto_us = 300000;
    bool     initialized = false;

    static constexpr uint64_t RTO_MIN_US   = 200000;
    static constexpr uint64_t RTO_MAX_US   = 120000000;
    static constexpr uint64_t INITIAL_RTO  = 300000;
    static constexpr uint32_t ALPHA_RTT    = 8;
    static constexpr uint32_t BETA_RTT     = 4;
    static constexpr uint32_t K_RTT        = 4;

    void update(uint64_t measured_rtt_us);
    void backoff();
    void reset();
};

struct SendSegment {
    uint32_t seq;
    uint32_t len;
    uint64_t sent_tsc;
    bool     acked;
    bool     fast_retransmitted;
    std::vector<uint8_t> data;
};

struct OutOfOrderSegment {
    uint32_t seq;
    std::vector<uint8_t> data;
};

struct CUBICState {
    double   w_cubic = 0.0;
    double   w_max = 0.0;
    uint64_t k = 0;
    uint64_t epoch_start = 0;
    uint32_t ssthresh = 65535;
    uint32_t cwnd = 1460;
    uint32_t dup_acks = 0;
    bool     recovery = false;

    void     onCongestionEvent(uint64_t current_tsc);
    void     onAck(uint32_t bytes_acked, uint64_t current_tsc);
    double   cubicFunction(uint64_t t) const;
    uint32_t getWindowSize() const { return cwnd; }
};

struct TCPConnection {
    TCPState state = TCPState::CLOSED;
    uint32_t snd_nxt = 0;
    uint32_t snd_una = 0;
    uint32_t rcv_nxt = 0;
    uint16_t snd_wnd = 0;
    uint16_t rcv_wnd = 65535;
    uint16_t snd_wnd_scale = 0;
    uint16_t rcv_wnd_scale = 0;

    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t src_ip = 0;
    uint32_t dst_ip = 0;

    MAC src_mac;
    MAC dst_mac;

    uint32_t iss = 0;
    uint32_t irs = 0;

    TCPOptionNegotiation opts;
    RTTEstimator rtt;
    CUBICState cubic;

    std::vector<SendSegment> send_queue;
    std::vector<SendSegment> retransmit_queue;
    std::vector<OutOfOrderSegment> ooo_queue;

    uint64_t connect_start_tsc = 0;
    uint64_t last_activity_tsc = 0;

    uint32_t dup_ack_count = 0;
    uint32_t last_ack_received = 0;

    bool     fin_sent = false;
    bool     fin_received = false;
    uint32_t fin_seq = 0;

    static constexpr uint32_t DEFAULT_MSS = 1460;
    static constexpr uint32_t MAX_WINDOW = 65535;
    static constexpr int TIME_WAIT_SECONDS = 2;
};

struct ReceiveResult {
    std::vector<uint8_t> data;
    bool     valid = false;
    bool     connected = false;
    bool     closed = false;
    bool     error = false;
    TCPState state = TCPState::CLOSED;
};

class TCPEngine {
public:
    TCPEngine();
    ~TCPEngine();

    bool initialize(const std::string& interface);
    void setLocalMAC(const MAC& mac);
    void setLocalIP(uint32_t ip);

    TCPConnection* open(const std::string& host, uint16_t port,
                        uint32_t timeout_ms = 5000);
    bool send(TCPConnection* conn, const uint8_t* data, size_t len);
    ReceiveResult recv(TCPConnection* conn, uint32_t timeout_ms = 1000);
    void close(TCPConnection* conn);

    bool processIncomingPacket(TCPConnection* conn, const PacketView& pkt);
    void checkRetransmit(TCPConnection* conn, uint64_t current_tsc);

    TCPState getState(const TCPConnection* conn) const;
    std::string transcendentFetch(const std::string& url);

    pntp::DNSResolver* getDNSResolver() { return &dns_resolver_; }
    RawSocketHandler* getRawSocket() { return &raw_sock; }

private:
    RawSocketHandler raw_sock;
    pntp::DNSResolver dns_resolver_;
    MAC local_mac;
    uint32_t local_ip = 0;
    uint16_t ip_id_counter = 0;
    std::map<uint16_t, std::unique_ptr<TCPConnection>> connections;

    uint16_t allocatePort();
    uint32_t generateISS();
    bool resolveHost(const std::string& host, uint32_t& out_ip, MAC& out_mac);

    bool sendRawPacket(const TCPConnection* conn, const std::vector<uint8_t>& packet);
    bool sendSYN(TCPConnection* conn);
    bool sendACK(const TCPConnection* conn);
    bool sendData(TCPConnection* conn, const uint8_t* data, size_t len, bool push);
    bool sendFIN(TCPConnection* conn);
    bool sendRST(TCPConnection* conn, uint32_t seq, uint32_t ack);

    void handleSYNACK(TCPConnection* conn, const struct tcphdr* tcp);
    void handleACK(TCPConnection* conn, const struct tcphdr* tcp, size_t payload_len);
    void handleFIN(TCPConnection* conn, const struct tcphdr* tcp);
    void handleRST(TCPConnection* conn);
    void handleSYN(TCPConnection* conn, const struct tcphdr* tcp);

    void transitionTo(TCPConnection* conn, TCPState new_state);
    void processRetransmitQueue(TCPConnection* conn);

    static constexpr uint32_t TIME_WAIT_MS = 60000;
    static constexpr int MAX_RETRIES = 5;
    static constexpr uint32_t FAST_RETRANSMIT_DUP_ACKS = 3;
};

#endif
