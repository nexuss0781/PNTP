#include "pntp/raw_socket_handler.h"

#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

RawSocketHandler::RawSocketHandler() : sock_fd(-1) {}

RawSocketHandler::~RawSocketHandler() {
    if (sock_fd != -1) {
        close(sock_fd);
    }
}

bool RawSocketHandler::init(const std::string& interface_name) {
    interface = interface_name;

    // Create a raw socket
    // AF_PACKET for link-layer packets, SOCK_RAW for raw packets, htons(ETH_P_ALL) for all protocols
    sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_fd == -1) {
        std::cerr << "Error creating raw socket: " << strerror(errno) << std::endl;
        return false;
    }

    // Bind the socket to the specified interface
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1) {
        std::cerr << "Error getting interface index for " << interface << ": " << strerror(errno) << std::endl;
        close(sock_fd);
        sock_fd = -1;
        return false;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    if (bind(sock_fd, (struct sockaddr*)&sll, sizeof(sll)) == -1) {
        std::cerr << "Error binding raw socket to interface " << interface << ": " << strerror(errno) << std::endl;
        close(sock_fd);
        sock_fd = -1;
        return false;
    }

    std::cout << "Raw socket initialized on interface: " << interface << std::endl;
    return true;
}

std::vector<unsigned char> RawSocketHandler::capturePacket() {
    std::vector<unsigned char> buffer(65536); // Max Ethernet frame size
    ssize_t num_bytes = recvfrom(sock_fd, buffer.data(), buffer.size(), 0, NULL, NULL);

    if (num_bytes == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // No packet available, non-blocking socket
            return {};
        }
        std::cerr << "Error capturing packet: " << strerror(errno) << std::endl;
        return {};
    }

    buffer.resize((size_t)num_bytes);
    return buffer;
}

bool RawSocketHandler::injectPacket(const std::vector<unsigned char>& packet_data) {
    if (sock_fd == -1) {
        std::cerr << "Error: Raw socket not initialized for injection.\n";
        return false;
    }

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface.c_str(), IFNAMSIZ - 1);

    if (ioctl(sock_fd, SIOCGIFINDEX, &ifr) == -1) {
        std::cerr << "Error getting interface index for " << interface << ": " << strerror(errno) << std::endl;
        return false;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL); // Not strictly necessary for sending, but good practice

    ssize_t sent_bytes = sendto(sock_fd, packet_data.data(), packet_data.size(), 0, (struct sockaddr*)&sll, sizeof(sll));

    if (sent_bytes == -1) {
        std::cerr << "Error injecting packet: " << strerror(errno) << std::endl;
        return false;
    }
    if (sent_bytes != (ssize_t)packet_data.size()) {
        std::cerr << "Warning: Incomplete packet injection. Sent " << sent_bytes << " of " << packet_data.size() << " bytes.\n";
    }

    return true;
}
