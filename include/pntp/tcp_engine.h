#ifndef TCP_ENGINE_H
#define TCP_ENGINE_H

#include <string>
#include <vector>
#include <netinet/ip.h>
#include <netinet/tcp.h>

class StealthNetworkEngine {
public:
    StealthNetworkEngine();
    ~StealthNetworkEngine();

    bool initialize(const std::string& interface);
    std::string transcendentFetch(const std::string& url);

private:
    int raw_sock;
    std::string iface;
    char stealth_id[16];

    struct PseudoHeader {
        uint32_t source_address;
        uint32_t dest_address;
        uint8_t placeholder;
        uint8_t protocol;
        uint16_t tcp_length;
    };

    unsigned short calculateChecksum(unsigned short *ptr, int nbytes);
    void buildTcpPacket(char* buffer, const std::string& dest_ip, int dest_port, const std::string& payload);
};

#endif // TCP_ENGINE_H
