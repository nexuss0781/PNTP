#ifndef PNTP_RAW_SOCKET_HANDLER_H
#define PNTP_RAW_SOCKET_HANDLER_H

#include <string>
#include <cstdint>
#include <cstddef>
#include <atomic>
#include <vector>
#include <linux/filter.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

struct PacketView {
    const uint8_t* data;
    size_t         len;

    PacketView() : data(nullptr), len(0) {}
    PacketView(const uint8_t* d, size_t l) : data(d), len(l) {}

    explicit operator bool() const { return data != nullptr && len > 0; }
};

struct QueueStatsSnapshot {
    uint64_t packets_captured;
    uint64_t packets_dropped_kernel;
    uint64_t packets_dropped_ring;
    uint64_t bytes_captured;
};

struct QueueStats {
    std::atomic<uint64_t> packets_captured{0};
    std::atomic<uint64_t> packets_dropped_kernel{0};
    std::atomic<uint64_t> packets_dropped_ring{0};
    std::atomic<uint64_t> bytes_captured{0};

    QueueStatsSnapshot snapshot() const {
        QueueStatsSnapshot s;
        s.packets_captured       = packets_captured.load(std::memory_order_relaxed);
        s.packets_dropped_kernel = packets_dropped_kernel.load(std::memory_order_relaxed);
        s.packets_dropped_ring   = packets_dropped_ring.load(std::memory_order_relaxed);
        s.bytes_captured         = bytes_captured.load(std::memory_order_relaxed);
        return s;
    }
};

class RawSocketHandler {
public:
    RawSocketHandler();
    ~RawSocketHandler();
    RawSocketHandler(const RawSocketHandler&) = delete;
    RawSocketHandler& operator=(const RawSocketHandler&) = delete;

    bool init(const std::string& interface_name);
    bool setRingParams(uint32_t block_num, uint32_t frame_size);

    int getInterfaceIndex() const { return if_index; }
    const std::string& getInterfaceName() const { return interface; }

    PacketView acquirePacket();
    void releasePacket(const PacketView& pkt);

    bool attachBPF(const std::vector<struct sock_filter>& filter);
    bool setPromiscuous(bool enable);
    bool setFanoutGroup(uint16_t group_id, int type);
    bool setTimeoutMs(uint64_t ms);

    bool injectPacket(const uint8_t* data, size_t len);

    QueueStatsSnapshot getStats() const;
    bool usingRing() const { return !use_heap_mode; }
    bool isInitialized() const { return sock_fd >= 0; }
    int  getFd() const { return sock_fd; }

    static const struct iphdr*  getIPv4Header(const PacketView& pkt);
    static const struct tcphdr* getTCPHeader(const PacketView& pkt);
    static const struct udphdr* getUDPHeader(const PacketView& pkt);
    static PacketView           getPayload(const PacketView& pkt, uint8_t protocol);

    static std::vector<struct sock_filter> makeBPF_TCPOnly();
    static std::vector<struct sock_filter> makeBPF_UDPOnly();
    static std::vector<struct sock_filter> makeBPF_PortOnly(uint16_t port);
    static std::vector<struct sock_filter> makeBPF_All();

private:
    int  sock_fd;
    int  if_index;
    std::string interface;
    static constexpr size_t HEAP_BUF_SIZE = 65536;

    void*    ring_ptr;
    size_t   ring_size;
    uint32_t ring_block_num;
    uint32_t ring_frame_size;
    uint32_t ring_frame_nr;
    uint32_t consumer_idx;

    bool     use_heap_mode;
    uint8_t  heap_buffer[HEAP_BUF_SIZE];
    size_t   heap_packet_len;

    QueueStats stats;
    bool       bpf_attached;

    bool setupRing();
    void teardownRing();
    uint8_t* framePtr(uint32_t idx) const;
};

#endif
