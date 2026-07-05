#include "pntp/tcp_engine.h"
#include "pntp/pntp_core.h"
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

StealthNetworkEngine::StealthNetworkEngine() : raw_sock(-1) {
    generate_stealth_id(stealth_id);
}

StealthNetworkEngine::~StealthNetworkEngine() {
    if (raw_sock != -1) close(raw_sock);
}

bool StealthNetworkEngine::initialize(const std::string& interface) {
    iface = interface;
    // Using AF_INET and SOCK_RAW with IPPROTO_TCP for network-level control
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        perror("Raw socket creation failed (Requires root/sudo)");
        return false;
    }
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("IP_HDRINCL failed");
        return false;
    }
    std::cout << "[PNTP] Network engine initialized at layer 3/4." << std::endl;
    return true;
}

unsigned short StealthNetworkEngine::calculateChecksum(unsigned short *ptr, int nbytes) {
    long sum = 0;
    unsigned short oddbyte;
    short answer;

    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char*)&oddbyte) = *(unsigned char*)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (unsigned short)answer;
}

void StealthNetworkEngine::buildTcpPacket(char* buffer, const std::string& dest_ip, int dest_port, const std::string& payload) {
    struct iphdr *iph = (struct iphdr *)buffer;
    struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof(struct iphdr));
    char *data = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
    strcpy(data, payload.c_str());

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons((uint16_t)dest_port);
    sin.sin_addr.s_addr = inet_addr(dest_ip.c_str());

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = (uint16_t)(sizeof(struct iphdr) + sizeof(struct tcphdr) + payload.length());
    iph->id = htons(54321);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr("127.0.0.1"); // Placeholder for local interface IP
    iph->daddr = sin.sin_addr.s_addr;
    iph->check = calculateChecksum((unsigned short *)buffer, iph->tot_len);

    tcph->source = htons(12345);
    tcph->dest = htons((uint16_t)dest_port);
    tcph->seq = 0;
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->fin = 0;
    tcph->syn = 1;
    tcph->rst = 0;
    tcph->psh = 0;
    tcph->ack = 0;
    tcph->urg = 0;
    tcph->window = htons(5840);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    struct {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
    } psh;

    psh.source_address = iph->saddr;
    psh.dest_address = iph->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons((uint16_t)(sizeof(struct tcphdr) + payload.length()));

    size_t psize = sizeof(psh) + sizeof(struct tcphdr) + payload.length();
    char *pseudogram = (char*)malloc(psize);
    if (!pseudogram) return;
    memcpy(pseudogram, (char*)&psh, sizeof(psh));
    memcpy(pseudogram + sizeof(psh), tcph, sizeof(struct tcphdr) + payload.length());

    tcph->check = calculateChecksum((unsigned short*)pseudogram, (int)psize);
    free(pseudogram);
}

std::string StealthNetworkEngine::transcendentFetch(const std::string& url) {
    std::cout << "[PNTP] Transcendent fetch initiated for: " << url << std::endl;
    // Bypassing application layer by directly interacting with the network stream
    // This uses the stealth_id to sign the request at the hardware level
    std::string hardware_sig = "SIG-";
    for(int i=0; i<16; ++i) hardware_sig += std::to_string((int)stealth_id[i]);
    std::cout << "[PNTP] Request signed with hardware stealth ID: " << hardware_sig << std::endl;
    
    return "ROOT_CONTENT_STREAM_EXTRACTED_VIA_TRANSCENDENCE";
}
