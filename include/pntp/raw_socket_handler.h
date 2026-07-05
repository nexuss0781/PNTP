#ifndef RAW_SOCKET_HANDLER_H
#define RAW_SOCKET_HANDLER_H

#include <string>
#include <vector>

class RawSocketHandler {
public:
    RawSocketHandler();
    ~RawSocketHandler();

    bool init(const std::string& interface_name);
    std::vector<unsigned char> capturePacket();
    bool injectPacket(const std::vector<unsigned char>& packet_data);

private:
    int sock_fd;
    std::string interface;
};

#endif // RAW_SOCKET_HANDLER_H
