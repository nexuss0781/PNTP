#include "pntp/raw_socket_handler.h"
#include <iostream>
#include <iomanip>
#include <thread>
#include <chrono>

int main() {
    RawSocketHandler handler;
    std::string interface_name = "eth0"; // Determined from 'ip a'

    if (!handler.init(interface_name)) {
        std::cerr << "Failed to initialize RawSocketHandler on " << interface_name << std::endl;
        return 1;
    }

    std::cout << "Attempting to capture packets for 5 seconds...\n";
    auto start_time = std::chrono::high_resolution_clock::now();
    int packets_captured = 0;

    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - start_time).count() < 5) {
        std::vector<unsigned char> packet = handler.capturePacket();
        if (!packet.empty()) {
            packets_captured++;
            std::cout << "Captured packet of size: " << packet.size() << " bytes\n";
            // Optionally print a snippet of the packet
            // std::cout << "Hex dump (first 16 bytes): ";
            // for (size_t i = 0; i < std::min((size_t)16, packet.size()); ++i) {
            //     std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)packet[i] << " ";
            // }
            // std::cout << std::dec << std::endl;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Small delay to avoid busy-waiting
    }

    std::cout << "\nFinished capturing. Total packets captured: " << packets_captured << std::endl;

    // Example of injecting a dummy packet (requires root and careful handling)
    // std::vector<unsigned char> dummy_packet = { /* ... raw ethernet frame data ... */ };
    // if (!dummy_packet.empty()) {
    //     std::cout << "Attempting to inject a dummy packet...\n";
    //     if (handler.injectPacket(dummy_packet)) {
    //         std::cout << "Dummy packet injected successfully.\n";
    //     } else {
    //         std::cerr << "Failed to inject dummy packet.\n";
    //     }
    // }

    return 0;
}
