#include "pntp/raw_socket_handler.h"
#include "pntp/pntp_core.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>

static std::atomic<bool> running{true};

int main() {
    init_entropy_pool();

    RawSocketHandler handler;
    std::string iface = "eth0";

    std::cout << "=== PNTP Raw Socket Test ===\n";

    if (!handler.init(iface)) {
        // Try loopback
        iface = "lo";
        std::cout << "[INFO] eth0 unavailable, trying lo...\n";
        if (!handler.init(iface)) {
            std::cerr << "FAIL: Cannot init on any interface\n";
            return 1;
        }
    }

    std::cout << "[OK] Initialized on " << iface
              << " (mode: " << (handler.usingRing() ? "PACKET_MMAP" : "heap") << ")\n";

    // Optional BPF filter — capture only TCP
    auto tcp_filter = RawSocketHandler::makeBPF_TCPOnly();
    if (handler.attachBPF(tcp_filter))
        std::cout << "[OK] BPF filter attached (TCP only)\n";
    else
        std::cout << "[WARN] BPF attach failed (non-fatal)\n";

    if (handler.setPromiscuous(true))
        std::cout << "[OK] Promiscuous mode enabled\n";

    if (!handler.setTimeoutMs(2000))
        std::cout << "[WARN] Cannot set timeout\n";

    auto start = std::chrono::steady_clock::now();
    uint64_t count = 0;
    uint64_t bytes = 0;

    std::cout << "\nCapturing packets for 5 seconds...\n";

    while (running) {
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (elapsed > std::chrono::seconds(5)) break;

        auto pkt = handler.acquirePacket();
        if (pkt) {
            ++count;
            bytes += pkt.len;

            // Parse headers
            auto* ip  = RawSocketHandler::getIPv4Header(pkt);
            auto* tcp = RawSocketHandler::getTCPHeader(pkt);
            if (ip && tcp) {
                char src[16], dst[16];
                inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
                inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));
                std::cout << "TCP " << src << ":" << ntohs(tcp->source)
                          << " -> " << dst << ":" << ntohs(tcp->dest)
                          << "  (" << pkt.len << "B)\n";
            } else {
                std::cout << "Packet " << count << ": " << pkt.len << "B\n";
            }
            handler.releasePacket(pkt);
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    }

    auto end = std::chrono::steady_clock::now();
    double secs = std::chrono::duration<double>(end - start).count();

    auto st = handler.getStats();
    std::cout << "\n=== Results ===\n"
              << "Packets:    " << count << "\n"
              << "Bytes:      " << bytes << "\n"
              << "Duration:   " << secs << " s\n"
              << "Rate:       " << (count / secs) << " pkt/s\n"
              << "Stats:      " << st.packets_captured << " captured, "
              << st.packets_dropped_kernel << " dropped\n";

    handler.setPromiscuous(false);
    std::cout << "\nDone.\n";
    return 0;
}
