#include "pntp/dns_resolver.h"
#include "pntp/pntp_core.h"
#include "pntp/tls_interceptor.h"

#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <chrono>
#include <thread>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#ifdef PNTP_HAVE_OPENSSL
#include <openssl/evp.h>
#endif

namespace pntp {

// ── DNSCache ─────────────────────────────────────────────────────────

DNSCache::DNSCache(size_t max_entries)
    : max_entries_(max_entries), mutex_(std::make_unique<std::mutex>()) {}

void DNSCache::put(const std::string& host,
                   const std::vector<uint32_t>& ipv4,
                   const std::vector<std::array<uint8_t, 16>>& ipv6,
                   uint32_t ttl_seconds) {
    if (ttl_seconds == 0) return;
    std::lock_guard<std::mutex> lock(*mutex_);

    uint64_t expiry = 0;
    if (ttl_seconds > 0) {
        expiry = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()
            + static_cast<uint64_t>(ttl_seconds) * 1'000'000'000ULL;
    } else {
        expiry = static_cast<uint64_t>(-1);
    }

    auto it = map_.find(host);
    if (it != map_.end()) {
        it->second->second.ipv4 = ipv4;
        it->second->second.ipv6 = ipv6;
        it->second->second.expiry_ns = expiry;
        list_.splice(list_.begin(), list_, it->second);
        return;
    }

    if (list_.size() >= max_entries_) {
        auto last = list_.end();
        --last;
        map_.erase(last->first);
        list_.pop_back();
    }

    Entry entry{ipv4, ipv6, expiry};
    list_.emplace_front(host, std::move(entry));
    map_[host] = list_.begin();
}

bool DNSCache::get(const std::string& host,
                   std::vector<uint32_t>& ipv4,
                   std::vector<std::array<uint8_t, 16>>& ipv6) {
    std::lock_guard<std::mutex> lock(*mutex_);

    auto it = map_.find(host);
    if (it == map_.end()) return false;

    auto& entry = it->second->second;

    uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    if (now_ns >= entry.expiry_ns) {
        list_.erase(it->second);
        map_.erase(it);
        return false;
    }

    ipv4 = entry.ipv4;
    ipv6 = entry.ipv6;
    list_.splice(list_.begin(), list_, it->second);
    return true;
}

void DNSCache::sweep() {
    std::lock_guard<std::mutex> lock(*mutex_);

    uint64_t now_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();

    auto it = list_.begin();
    while (it != list_.end()) {
        if (now_ns >= it->second.expiry_ns) {
            map_.erase(it->first);
            it = list_.erase(it);
        } else {
            ++it;
        }
    }
}

void DNSCache::clear() {
    std::lock_guard<std::mutex> lock(*mutex_);
    map_.clear();
    list_.clear();
}

size_t DNSCache::size() const {
    std::lock_guard<std::mutex> lock(*mutex_);
    return list_.size();
}

// ── DNS Wire Format Helpers ──────────────────────────────────────────

std::vector<uint8_t> DNSResolver::encodeName(const std::string& host) {
    std::vector<uint8_t> name;
    size_t start = 0;
    while (start < host.size()) {
        size_t dot = host.find('.', start);
        size_t len = (dot == std::string::npos) ? host.size() - start : dot - start;
        if (len > 63) len = 63;
        name.push_back(static_cast<uint8_t>(len));
        for (size_t i = 0; i < len; ++i) {
            name.push_back(static_cast<uint8_t>(host[start + i]));
        }
        start = (dot == std::string::npos) ? host.size() : dot + 1;
    }
    name.push_back(0);
    return name;
}

std::string DNSResolver::decodeName(const uint8_t* data, size_t len,
                                     size_t& offset) {
    std::string name;
    bool jumped = false;
    size_t saved_offset = offset;

    while (offset < len) {
        uint8_t b = data[offset];
        if (b == 0) {
            if (!jumped) ++offset;
            break;
        }
        if ((b & 0xC0) == 0xC0) {
            if (offset + 2 > len) break;
            uint16_t ptr = ((static_cast<uint16_t>(b & 0x3F)) << 8) | data[offset + 1];
            if (!jumped) {
                saved_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            continue;
        }
        uint8_t label_len = b;
        if (offset + 1 + label_len > len) break;
        ++offset;
        if (!name.empty()) name += '.';
        for (uint8_t i = 0; i < label_len; ++i) {
            name += static_cast<char>(data[offset + i]);
        }
        offset += label_len;
    }

    if (jumped) offset = saved_offset;
    return name;
}

size_t DNSResolver::skipName(const uint8_t* data, size_t len, size_t offset) {
    while (offset < len) {
        uint8_t b = data[offset];
        if (b == 0) return offset + 1;
        if ((b & 0xC0) == 0xC0) return offset + 2;
        ++offset;
        uint8_t label_len = b;
        offset += label_len;
    }
    return len;
}

uint16_t DNSResolver::allocateId() {
    return next_id_.fetch_add(1, std::memory_order_relaxed);
}

// ── Query Builder ────────────────────────────────────────────────────

std::vector<uint8_t> DNSResolver::buildQuery(const std::string& host,
                                              RecordType type,
                                              uint16_t id) {
    std::vector<uint8_t> msg;

    // Header (12 bytes)
    msg.push_back(static_cast<uint8_t>(id >> 8));
    msg.push_back(static_cast<uint8_t>(id & 0xFF));
    msg.push_back(0x01); // QR=0, RD=1
    msg.push_back(0x00);
    msg.push_back(0x00); msg.push_back(0x01); // QDCOUNT = 1
    msg.push_back(0x00); msg.push_back(0x00); // ANCOUNT = 0
    msg.push_back(0x00); msg.push_back(0x00); // NSCOUNT = 0
    msg.push_back(0x00); msg.push_back(0x00); // ARCOUNT = 0

    // Question
    auto encoded_name = encodeName(host);
    msg.insert(msg.end(), encoded_name.begin(), encoded_name.end());

    uint16_t qtype = static_cast<uint16_t>(type);
    msg.push_back(static_cast<uint8_t>(qtype >> 8));
    msg.push_back(static_cast<uint8_t>(qtype & 0xFF));

    uint16_t qclass = static_cast<uint16_t>(DNSClass::IN);
    msg.push_back(static_cast<uint8_t>(qclass >> 8));
    msg.push_back(static_cast<uint8_t>(qclass & 0xFF));

    return msg;
}

// ── Response Parser ──────────────────────────────────────────────────

bool DNSResolver::parseResponse(const uint8_t* data, size_t len,
                                 uint16_t expected_id,
                                 std::vector<uint32_t>& ipv4,
                                 std::vector<std::array<uint8_t, 16>>& ipv6,
                                 uint32_t& ttl) {
    if (len < 12) return false;

    // Parse header
    uint16_t id = (static_cast<uint16_t>(data[0]) << 8) | data[1];
    if (id != expected_id) return false;

    uint8_t flags_hi = data[2];
    uint8_t flags_lo = data[3];
    bool is_response = (flags_hi & 0x80) != 0;
    uint8_t rcode = flags_lo & 0x0F;
    if (!is_response || rcode != 0) return false;

    uint16_t qdcount = (static_cast<uint16_t>(data[4]) << 8) | data[5];
    uint16_t ancount = (static_cast<uint16_t>(data[6]) << 8) | data[7];

    size_t offset = 12;

    // Skip question section
    for (uint16_t i = 0; i < qdcount; ++i) {
        offset = skipName(data, len, offset);
        offset += 4; // QTYPE(2) + QCLASS(2)
        if (offset > len) return false;
    }

    // Parse answer section
    ttl = 0;
    for (uint16_t i = 0; i < ancount; ++i) {
        if (offset >= len) return false;

        offset = skipName(data, len, offset);
        if (offset + 10 > len) return false;

        uint16_t rtype  = (static_cast<uint16_t>(data[offset]) << 8) | data[offset + 1];
        uint16_t rclass = (static_cast<uint16_t>(data[offset + 2]) << 8) | data[offset + 3];
        (void)rclass;
        uint32_t rttl = (static_cast<uint32_t>(data[offset + 4]) << 24) |
                        (static_cast<uint32_t>(data[offset + 5]) << 16) |
                        (static_cast<uint32_t>(data[offset + 6]) << 8)  |
                         static_cast<uint32_t>(data[offset + 7]);
        uint16_t rdlength = (static_cast<uint16_t>(data[offset + 8]) << 8) | data[offset + 9];
        offset += 10;

        if (offset + rdlength > len) return false;

        if (rtype == static_cast<uint16_t>(RecordType::A) && rdlength == 4) {
            uint32_t addr = (static_cast<uint32_t>(data[offset]) << 24) |
                            (static_cast<uint32_t>(data[offset + 1]) << 16) |
                            (static_cast<uint32_t>(data[offset + 2]) << 8)  |
                             static_cast<uint32_t>(data[offset + 3]);
            ipv4.push_back(addr);
            if (ttl == 0 || rttl < ttl) ttl = rttl;
        } else if (rtype == static_cast<uint16_t>(RecordType::AAAA) && rdlength == 16) {
            std::array<uint8_t, 16> addr6{};
            std::memcpy(addr6.data(), data + offset, 16);
            ipv6.push_back(addr6);
            if (ttl == 0 || rttl < ttl) ttl = rttl;
        }

        offset += rdlength;
    }

    return !ipv4.empty() || !ipv6.empty();
}

// ── UDP Transport ────────────────────────────────────────────────────

DNSResult DNSResolver::resolveViaUDP(const std::string& host,
                                      RecordType type,
                                      uint32_t timeout_ms) {
    DNSResult result;

    for (const auto& server : dns_servers_) {
        uint16_t id = allocateId();
        auto query = buildQuery(host, type, id);

        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) continue;

        struct timeval tv{};
        tv.tv_sec = static_cast<time_t>(timeout_ms / 1000);
        tv.tv_usec = static_cast<suseconds_t>((timeout_ms % 1000) * 1000);
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(DNS_PORT);
        if (inet_pton(AF_INET, server.c_str(), &addr.sin_addr) != 1) {
            close(sock);
            continue;
        }

        ssize_t sent = sendto(sock, query.data(), query.size(), 0,
                              reinterpret_cast<struct sockaddr*>(&addr),
                              sizeof(addr));
        if (sent != static_cast<ssize_t>(query.size())) {
            close(sock);
            continue;
        }

        uint8_t buf[1536];
        struct sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        ssize_t n = recvfrom(sock, buf, sizeof(buf), 0,
                             reinterpret_cast<struct sockaddr*>(&from),
                             &from_len);
        close(sock);

        if (n < 12) continue;

        std::vector<uint32_t> ipv4;
        std::vector<std::array<uint8_t, 16>> ipv6;
        uint32_t ttl = 0;

        if (parseResponse(buf, static_cast<size_t>(n), id, ipv4, ipv6, ttl)) {
            result.ipv4_addresses = std::move(ipv4);
            result.ipv6_addresses = std::move(ipv6);
            result.ttl_seconds = ttl;
            result.success = true;
            return result;
        }
    }

    return result;
}

// ── DoH Transport (TLS gap: refactor to use TLSInterceptor when Phase 5 is complete) ──

DNSResult DNSResolver::resolveViaDoH(const std::string& host,
                                       RecordType type,
                                       uint32_t timeout_ms) {
    DNSResult result;
#ifndef PNTP_HAVE_OPENSSL
    (void)host;
    (void)type;
    (void)timeout_ms;
    return result;
#else
    if (doh_host_.empty() || doh_path_.empty()) return result;

    // Lazily initialize TLS interceptor
    if (!tls_) {
        tls_ = std::make_unique<TLSInterceptor>();
        if (!tls_->initialize()) return result;
    }

    // Connect to DoH server via TLSInterceptor
    auto conn = tls_->connect(doh_host_, 443, timeout_ms);
    if (!conn || !conn->connected) return result;

    uint16_t id = allocateId();
    auto query = buildQuery(host, type, id);

    std::string body(query.begin(), query.end());
    std::string http_request =
        "POST " + doh_path_ + " HTTP/1.1\r\n"
        "Host: " + doh_host_ + "\r\n"
        "Accept: application/dns-message\r\n"
        "Content-Type: application/dns-message\r\n"
        "Content-Length: " + std::to_string(body.size()) + "\r\n"
        "Connection: close\r\n\r\n";

    // Send HTTP header
    if (!tls_->writeData(conn.get(),
                          reinterpret_cast<const uint8_t*>(http_request.data()),
                          http_request.size())) {
        tls_->disconnect(conn.get());
        return result;
    }

    // Send DNS query
    if (!tls_->writeData(conn.get(), query.data(), query.size())) {
        tls_->disconnect(conn.get());
        return result;
    }

    // Read response
    std::vector<uint8_t> http_response;
    while (true) {
        auto chunk = tls_->readData(conn.get(), timeout_ms);
        if (chunk.empty()) break;
        http_response.insert(http_response.end(), chunk.begin(), chunk.end());
    }

    tls_->disconnect(conn.get());

    // Find HTTP body after \r\n\r\n
    auto it = std::search(http_response.begin(), http_response.end(),
                          "\r\n\r\n", "\r\n\r\n" + 4);
    if (it == http_response.end()) return result;

    size_t body_start = static_cast<size_t>(it - http_response.begin()) + 4;
    size_t body_len = http_response.size() - body_start;
    if (body_len < 12) return result;

    // Check HTTP status
    std::string status_line(http_response.begin(),
                            http_response.begin() + static_cast<ptrdiff_t>(body_start));
    if (status_line.find("200") == std::string::npos) return result;

    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;

    if (parseResponse(http_response.data() + body_start, body_len,
                      id, ipv4, ipv6, ttl)) {
        result.ipv4_addresses = std::move(ipv4);
        result.ipv6_addresses = std::move(ipv6);
        result.ttl_seconds = ttl;
        result.success = true;
    }

    return result;
#endif
}

// ── System Fallback ──────────────────────────────────────────────────

DNSResult DNSResolver::resolveViaSystem(const std::string& host, RecordType type) {
    DNSResult result;

    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = (type == RecordType::AAAA) ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) {
        return result;
    }

    uint32_t min_ttl = 0;

    for (struct addrinfo* rp = res; rp != nullptr; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            auto* sin = reinterpret_cast<struct sockaddr_in*>(rp->ai_addr);
            result.ipv4_addresses.push_back(ntohl(sin->sin_addr.s_addr));
        } else if (rp->ai_family == AF_INET6) {
            auto* sin6 = reinterpret_cast<struct sockaddr_in6*>(rp->ai_addr);
            std::array<uint8_t, 16> addr6{};
            std::memcpy(addr6.data(), &sin6->sin6_addr, 16);
            result.ipv6_addresses.push_back(addr6);
        }
    }

    freeaddrinfo(res);
    result.ttl_seconds = 300;
    result.success = !result.ipv4_addresses.empty() || !result.ipv6_addresses.empty();
    return result;
}

// ── Cache Integration ────────────────────────────────────────────────

void DNSResolver::cacheResult(const std::string& host, const DNSResult& result) {
    if (result.success && result.ttl_seconds > 0) {
        cache_.put(host, result.ipv4_addresses, result.ipv6_addresses,
                   result.ttl_seconds);
    }
}

DNSResult DNSResolver::checkCache(const std::string& host) {
    DNSResult result;
    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    if (cache_.get(host, ipv4, ipv6)) {
        result.ipv4_addresses = std::move(ipv4);
        result.ipv6_addresses = std::move(ipv6);
        result.success = true;
        incrementCacheHits();
    } else {
        incrementCacheMisses();
    }
    return result;
}

// ── Main Resolve ─────────────────────────────────────────────────────

DNSResult DNSResolver::resolve(const std::string& host,
                                RecordType type,
                                uint32_t timeout_ms) {
    // 1. Check cache
    DNSResult result = checkCache(host);
    if (result.success) return result;

    uint64_t start_tsc = get_rdtsc_serialized();
    bool resolved = false;

    // 2. Try DoH first (if enabled)
    if (doh_enabled_ && !doh_host_.empty()) {
        result = resolveViaDoH(host, type, timeout_ms);
        if (result.success) {
            resolved = true;
            incrementDohQueries();
        }
    }

    // 3. Try raw UDP
    if (!resolved) {
        result = resolveViaUDP(host, type, timeout_ms);
        if (result.success) {
            resolved = true;
            incrementUdpQueries();
        }
    }

    // 4. System fallback
    if (!resolved) {
        result = resolveViaSystem(host, type);
        if (result.success) {
            resolved = true;
            incrementFallbacks();
        }
    }

    if (resolved) {
        cacheResult(host, result);
        uint64_t end_tsc = get_rdtsc_serialized();
        result.resolve_time_us = (end_tsc - start_tsc) / 3000ULL;
    } else {
        incrementFailures();
    }

    return result;
}

// ── Configuration ────────────────────────────────────────────────────

DNSResolver::DNSResolver()
    : dns_servers_{"1.1.1.1", "8.8.8.8"}
    , doh_enabled_(false)
    , doh_url_("https://cloudflare-dns.com/dns-query")
    , doh_host_("cloudflare-dns.com")
    , doh_path_("/dns-query") {}

DNSResolver::DNSResolver(const std::vector<std::string>& dns_servers)
    : dns_servers_(dns_servers)
    , doh_enabled_(false)
    , doh_url_("https://cloudflare-dns.com/dns-query")
    , doh_host_("cloudflare-dns.com")
    , doh_path_("/dns-query") {}

DNSResolver::~DNSResolver() = default;

void DNSResolver::setDNSServers(const std::vector<std::string>& servers) {
    dns_servers_ = servers;
}

std::vector<std::string> DNSResolver::getDNSServers() const {
    return dns_servers_;
}

void DNSResolver::setDoHServer(const std::string& url) {
    doh_url_ = url;

    // Parse URL: https://host:port/path
    std::string s = url;
    doh_host_.clear();
    doh_path_ = "/dns-query";

    if (s.find("https://") == 0) s = s.substr(8);
    else if (s.find("http://") == 0) s = s.substr(7);

    size_t slash = s.find('/');
    if (slash != std::string::npos) {
        doh_host_ = s.substr(0, slash);
        doh_path_ = s.substr(slash);
    } else {
        doh_host_ = s;
    }

    size_t colon = doh_host_.find(':');
    if (colon != std::string::npos) {
        doh_host_ = doh_host_.substr(0, colon);
    }
}

void DNSResolver::setCacheSize(size_t max_entries) {
    cache_ = DNSCache(max_entries);
}

void DNSResolver::clearCache() {
    cache_.clear();
}

// ── Stats ────────────────────────────────────────────────────────────

DNSResolver::Stats DNSResolver::getStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void DNSResolver::resetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = Stats{};
}

void DNSResolver::incrementCacheHits() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.cache_hits;
}

void DNSResolver::incrementCacheMisses() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.cache_misses;
}

void DNSResolver::incrementUdpQueries() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.udp_queries;
}

void DNSResolver::incrementDohQueries() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.doh_queries;
}

void DNSResolver::incrementFallbacks() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.fallbacks;
}

void DNSResolver::incrementFailures() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    ++stats_.failures;
}

} // namespace pntp
