#include "pntp/raw_socket_handler.h"

#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <poll.h>
#include <cerrno>

// ── helpers ─────────────────────────────────────────────────────────────

static uint32_t pageSize() {
    long ps = sysconf(_SC_PAGESIZE);
    return static_cast<uint32_t>(ps > 0 ? ps : 4096);
}

// Compute a block size such that frames_per_block is a power-of-two
// and block_size is page-aligned.  Minimum 16 frames per block.
static uint32_t computeBlockSize(uint32_t frame_size) {
    const uint32_t ps = pageSize();
    uint32_t bs = frame_size * 16;                  // 16 frames minimum
    uint32_t rem = bs % ps;
    if (rem) bs += ps - rem;
    return bs;
}

// ── socket helpers ──────────────────────────────────────────────────────

static int openRawSocket(int if_index) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (fd < 0) return -1;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = if_index;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

// ── construct / destruct ────────────────────────────────────────────────

RawSocketHandler::RawSocketHandler()
    : sock_fd(-1),
      if_index(-1),
      ring_ptr(nullptr),
      ring_size(0),
      ring_block_num(0),
      ring_frame_size(0),
      ring_frame_nr(0),
      consumer_idx(0),
      use_heap_mode(false),
      heap_packet_len(0),
      bpf_attached(false) {}

RawSocketHandler::~RawSocketHandler() {
    if (ring_ptr) teardownRing();
    if (sock_fd >= 0) close(sock_fd);
}

// ── init ────────────────────────────────────────────────────────────────

bool RawSocketHandler::init(const std::string& interface_name) {
    interface = interface_name;

    // resolve interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    int tmp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (tmp_fd < 0) return false;

    interface_name.copy(ifr.ifr_name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(tmp_fd, SIOCGIFINDEX, &ifr) < 0) {
        close(tmp_fd);
        return false;
    }
    if_index = ifr.ifr_ifindex;
    close(tmp_fd);

    // open raw socket + bind
    sock_fd = openRawSocket(if_index);
    if (sock_fd < 0) return false;

    // try PACKET_MMAP ring; fall back to heap on failure
    ring_block_num   = 16;
    ring_frame_size  = 2048;
    if (!setupRing()) {
        use_heap_mode = true;
    }
    return true;
}

bool RawSocketHandler::setRingParams(uint32_t block_num, uint32_t frame_size) {
    if (sock_fd < 0) return false;
    if (ring_ptr) teardownRing();

    ring_block_num  = block_num;
    ring_frame_size = frame_size;

    if (!setupRing()) {
        use_heap_mode = true;
        return false;
    }
    use_heap_mode = false;
    return true;
}

// ── ring setup / teardown ──────────────────────────────────────────────

bool RawSocketHandler::setupRing() {
    uint32_t block_size = computeBlockSize(ring_frame_size);
    uint32_t frames_per_block = block_size / ring_frame_size;

    // TPACKET_V2 for wide compatibility
    int ver = TPACKET_V2;
    if (setsockopt(sock_fd, SOL_PACKET, PACKET_VERSION, &ver, sizeof(ver)) < 0)
        return false;

    struct tpacket_req req;
    memset(&req, 0, sizeof(req));
    req.tp_block_size  = block_size;
    req.tp_block_nr    = ring_block_num;
    req.tp_frame_size  = ring_frame_size;
    req.tp_frame_nr    = ring_block_num * frames_per_block;

    if (setsockopt(sock_fd, SOL_PACKET, PACKET_RX_RING, &req, sizeof(req)) < 0)
        return false;

    ring_frame_nr = req.tp_frame_nr;
    ring_size     = static_cast<size_t>(block_size) * ring_block_num;

    ring_ptr = mmap(nullptr, ring_size,
                    PROT_READ | PROT_WRITE, MAP_SHARED,
                    sock_fd, 0);
    if (ring_ptr == MAP_FAILED) {
        ring_ptr = nullptr;
        ring_size = 0;
        return false;
    }

    consumer_idx = 0;
    use_heap_mode = false;
    return true;
}

void RawSocketHandler::teardownRing() {
    if (ring_ptr && ring_size > 0) {
        munmap(ring_ptr, ring_size);
    }
    ring_ptr   = nullptr;
    ring_size  = 0;
    ring_frame_nr = 0;
}

uint8_t* RawSocketHandler::framePtr(uint32_t idx) const {
    if (!ring_ptr || ring_frame_nr == 0) return nullptr;
    uint32_t frames_per_block = computeBlockSize(ring_frame_size) / ring_frame_size;
    uint32_t block_idx   = idx / frames_per_block;
    uint32_t frame_in_blk = idx % frames_per_block;
    uint32_t block_size  = frames_per_block * ring_frame_size;
    size_t offset = static_cast<size_t>(block_idx) * block_size
                  + static_cast<size_t>(frame_in_blk) * ring_frame_size;
    return static_cast<uint8_t*>(ring_ptr) + offset;
}

// ── packet capture ─────────────────────────────────────────────────────

PacketView RawSocketHandler::acquirePacket() {
    if (sock_fd < 0) return PacketView();

    if (use_heap_mode) {
        struct sockaddr_ll from;
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(sock_fd, heap_buffer, HEAP_BUF_SIZE,
                             MSG_DONTWAIT,
                             (struct sockaddr*)&from, &from_len);
        if (n > 0) {
            heap_packet_len = (static_cast<size_t>(n) < HEAP_BUF_SIZE)
                                ? static_cast<size_t>(n) : HEAP_BUF_SIZE;
            stats.packets_captured.fetch_add(1, std::memory_order_relaxed);
            stats.bytes_captured.fetch_add(heap_packet_len, std::memory_order_relaxed);
            return PacketView(heap_buffer, heap_packet_len);
        }
        return PacketView();
    }

    // PACKET_MMAP ring mode
    struct tpacket2_hdr* hdr =
        reinterpret_cast<struct tpacket2_hdr*>(framePtr(consumer_idx));
    if (!hdr) return PacketView();

    if (hdr->tp_status & TP_STATUS_USER) {
        const uint8_t* data = reinterpret_cast<const uint8_t*>(hdr)
                              + hdr->tp_mac;
        size_t len = hdr->tp_snaplen;
        stats.packets_captured.fetch_add(1, std::memory_order_relaxed);
        stats.bytes_captured.fetch_add(len, std::memory_order_relaxed);

#ifdef TP_STATUS_DROPPED
        if (hdr->tp_status & TP_STATUS_DROPPED)
            stats.packets_dropped_kernel.fetch_add(1, std::memory_order_relaxed);
#endif

        return PacketView(data, len);
    }
    return PacketView();
}

void RawSocketHandler::releasePacket(const PacketView& pkt) {
    if (!pkt || sock_fd < 0) return;
    if (use_heap_mode) return;

    struct tpacket2_hdr* hdr =
        reinterpret_cast<struct tpacket2_hdr*>(framePtr(consumer_idx));
    if (!hdr) return;

    // Ensure all reads on packet data complete before we hand the frame back.
    __sync_synchronize();
    hdr->tp_status = TP_STATUS_KERNEL;
    consumer_idx = (consumer_idx + 1) % ring_frame_nr;
}

// ── BPF ─────────────────────────────────────────────────────────────────

bool RawSocketHandler::attachBPF(const std::vector<struct sock_filter>& filter) {
    if (sock_fd < 0) return false;

    struct sock_fprog fp;
    memset(&fp, 0, sizeof(fp));
    fp.len    = static_cast<unsigned short>(filter.size());
    fp.filter = const_cast<struct sock_filter*>(filter.data());

    if (setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &fp, sizeof(fp)) < 0)
        return false;

    bpf_attached = true;
    return true;
}

// ── socket options ─────────────────────────────────────────────────────

bool RawSocketHandler::setPromiscuous(bool enable) {
    if (sock_fd < 0) return false;

    struct packet_mreq mr;
    memset(&mr, 0, sizeof(mr));
    mr.mr_ifindex = if_index;
    mr.mr_type    = PACKET_MR_PROMISC;
    mr.mr_alen    = 0;

    int opt = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;
    return setsockopt(sock_fd, SOL_PACKET, opt, &mr, sizeof(mr)) == 0;
}

bool RawSocketHandler::setFanoutGroup(uint16_t group_id, int type) {
    if (sock_fd < 0) return false;
    uint32_t fanout_arg = (static_cast<uint32_t>(type) & 0xFFFF)
                        | (static_cast<uint32_t>(group_id) << 16);
    return setsockopt(sock_fd, SOL_PACKET, PACKET_FANOUT,
                      &fanout_arg, sizeof(fanout_arg)) == 0;
}

bool RawSocketHandler::setTimeoutMs(uint64_t ms) {
    if (sock_fd < 0) return false;
    struct timeval tv;
    tv.tv_sec  = static_cast<time_t>(ms / 1000);
    tv.tv_usec = static_cast<suseconds_t>((ms % 1000) * 1000);
    return setsockopt(sock_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0;
}

// ── injection ──────────────────────────────────────────────────────────

bool RawSocketHandler::injectPacket(const uint8_t* data, size_t len) {
    if (sock_fd < 0 || !data || len == 0) return false;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = if_index;
    sll.sll_protocol = htons(ETH_P_ALL);

    ssize_t sent = sendto(sock_fd, data, len, 0,
                          (struct sockaddr*)&sll, sizeof(sll));
    return sent == static_cast<ssize_t>(len);
}

// ── stats ──────────────────────────────────────────────────────────────

QueueStatsSnapshot RawSocketHandler::getStats() const {
    // poll kernel drop counter if available
    if (sock_fd >= 0) {
        struct tpacket_stats kstats;
        socklen_t slen = sizeof(kstats);
        if (getsockopt(sock_fd, SOL_PACKET, PACKET_STATISTICS,
                       &kstats, &slen) == 0) {
            const_cast<QueueStats&>(stats)
                .packets_dropped_kernel.store(kstats.tp_drops,
                                              std::memory_order_relaxed);
        }
    }
    return stats.snapshot();
}

// ── header parsing ─────────────────────────────────────────────────────

const struct iphdr* RawSocketHandler::getIPv4Header(const PacketView& pkt) {
    if (!pkt || pkt.len < 34) return nullptr;  // 14 eth + 20 ip

    // Ethernet header is 14 bytes; IP header starts at offset 14.
    const uint8_t* ip_start = pkt.data + 14;
    // Quick sanity check: version/ihl first byte should have 0x45 for IPv4
    if ((ip_start[0] & 0xF0) != 0x40) return nullptr;

    return reinterpret_cast<const struct iphdr*>(ip_start);
}

const struct tcphdr* RawSocketHandler::getTCPHeader(const PacketView& pkt) {
    auto* ip = getIPv4Header(pkt);
    if (!ip) return nullptr;
    if (ip->protocol != IPPROTO_TCP) return nullptr;

    uint8_t ip_ihl = ip->ihl;       // header length in 32-bit words
    size_t ip_hdr_len = static_cast<size_t>(ip_ihl) * 4;
    size_t tcp_off = 14 + ip_hdr_len;

    if (pkt.len < tcp_off + 20) return nullptr;
    return reinterpret_cast<const struct tcphdr*>(pkt.data + tcp_off);
}

const struct udphdr* RawSocketHandler::getUDPHeader(const PacketView& pkt) {
    auto* ip = getIPv4Header(pkt);
    if (!ip) return nullptr;
    if (ip->protocol != IPPROTO_UDP) return nullptr;

    uint8_t ip_ihl = ip->ihl;
    size_t ip_hdr_len = static_cast<size_t>(ip_ihl) * 4;
    size_t udp_off = 14 + ip_hdr_len;

    if (pkt.len < udp_off + 8) return nullptr;
    return reinterpret_cast<const struct udphdr*>(pkt.data + udp_off);
}

PacketView RawSocketHandler::getPayload(const PacketView& pkt, uint8_t protocol) {
    if (protocol == IPPROTO_TCP) {
        auto* tcp = getTCPHeader(pkt);
        if (!tcp) return PacketView();
        uint8_t doff = tcp->doff;
        size_t tcp_hdr_len = static_cast<size_t>(doff) * 4;
        auto* ip = getIPv4Header(pkt);
        size_t ip_hdr_len = static_cast<size_t>(ip->ihl) * 4;
        size_t total_start = 14 + ip_hdr_len + tcp_hdr_len;
        size_t ip_total = ntohs(ip->tot_len);
        size_t total_len = 14 + ip_total;   // from ethernet start
        if (pkt.len < total_len) total_len = pkt.len;
        if (total_start >= total_len) return PacketView();
        return PacketView(pkt.data + total_start, total_len - total_start);
    }

    if (protocol == IPPROTO_UDP) {
        auto* udp = getUDPHeader(pkt);
        if (!udp) return PacketView();
        auto* ip = getIPv4Header(pkt);
        size_t ip_hdr_len = static_cast<size_t>(ip->ihl) * 4;
        size_t udp_start = 14 + ip_hdr_len + 8;  // 8 = sizeof udp header
        size_t udp_len = ntohs(udp->len);
        size_t total_start = 14 + ip_hdr_len;
        size_t total_len  = total_start + udp_len;
        if (pkt.len < total_len) total_len = pkt.len;
        size_t payload_len = (total_len > udp_start) ? total_len - udp_start : 0;
        if (payload_len == 0) return PacketView();
        return PacketView(pkt.data + udp_start, payload_len);
    }

    return PacketView();
}

// ── BPF factory helpers ────────────────────────────────────────────────

std::vector<struct sock_filter> RawSocketHandler::makeBPF_All() {
    struct sock_filter code[] = {
        { BPF_RET | BPF_K, 0, 0, 0x00040000 } // accept all, up to 262144 bytes
    };
    return std::vector<struct sock_filter>(code, code + 1);
}

std::vector<struct sock_filter> RawSocketHandler::makeBPF_TCPOnly() {
    // Capture only TCP over IPv4
    struct sock_filter code[] = {
        { BPF_LD | BPF_H | BPF_ABS, 0, 0, 0x000c },             // ldh [12] — EtherType
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0x0800 },            // jeq ETH_P_IP
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x0806 },            // jeq ETH_P_ARP
        { BPF_RET | BPF_K, 0, 0, 0x00000000 },                  // ret 0 (reject ARP)
        { BPF_LD | BPF_B | BPF_ABS, 0, 0, 23 },                 // ldb [23] — IP protocol
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, IPPROTO_TCP },       // jeq TCP
        { BPF_RET | BPF_K, 0, 0, 0x00000000 },                  // ret 0 (reject non-TCP)
        { BPF_RET | BPF_K, 0, 0, 0x00040000 },                  // accept TCP
    };
    return std::vector<struct sock_filter>(code, code + 8);
}

std::vector<struct sock_filter> RawSocketHandler::makeBPF_UDPOnly() {
    struct sock_filter code[] = {
        { BPF_LD | BPF_H | BPF_ABS, 0, 0, 0x000c },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0x0800 },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x0806 },
        { BPF_RET | BPF_K, 0, 0, 0x00000000 },
        { BPF_LD | BPF_B | BPF_ABS, 0, 0, 23 },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, IPPROTO_UDP },
        { BPF_RET | BPF_K, 0, 0, 0x00000000 },
        { BPF_RET | BPF_K, 0, 0, 0x00040000 },
    };
    return std::vector<struct sock_filter>(code, code + 8);
}

std::vector<struct sock_filter> RawSocketHandler::makeBPF_PortOnly(uint16_t port) {
    // Check TCP or UDP dst port == port, IPv4 only
    // TCP dst port offset: 14 (eth) + 20 (IP) + 2 (TCP src) = 36
    // UDP dst port offset: 14 (eth) + 20 (IP) + 2 (UDP src) = 36
    uint32_t port_be = port;  // BPF_K is host-order; ldh converts from net
    struct sock_filter code[] = {
        { BPF_LD | BPF_H | BPF_ABS, 0, 0, 0x000c },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 3, 0x0800 },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, 0x0806 },
        { BPF_RET | BPF_K, 0, 0, 0x00000000 },
        { BPF_LD | BPF_B | BPF_ABS, 0, 0, 23 },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, IPPROTO_TCP },
        { BPF_JMP | BPF_JEQ | BPF_K, 0, 1, IPPROTO_UDP },
        { BPF_LD | BPF_H | BPF_ABS, 0, 0, 36 },                 // ldh [36] — dst port
        { BPF_JMP | BPF_JEQ | BPF_K, 1, 0, port_be },           // jeq port
        { BPF_RET | BPF_K, 0, 0, 0x00000000 },
        { BPF_RET | BPF_K, 0, 0, 0x00040000 },
    };
    return std::vector<struct sock_filter>(code, code + 11);
}
