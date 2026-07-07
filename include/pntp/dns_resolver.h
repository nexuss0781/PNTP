#ifndef PNTP_DNS_RESOLVER_H
#define PNTP_DNS_RESOLVER_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <array>
#include <list>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <atomic>

namespace pntp {

enum class RecordType : uint16_t {
    A    = 1,
    AAAA = 28
};

enum class DNSClass : uint16_t {
    IN = 1
};

struct DNSResult {
    std::vector<uint32_t> ipv4_addresses;
    std::vector<std::array<uint8_t, 16>> ipv6_addresses;
    uint32_t ttl_seconds = 0;
    uint64_t resolve_time_us = 0;
    bool     success = false;
};

class DNSCache {
public:
    explicit DNSCache(size_t max_entries = 1024);

    void put(const std::string& host,
             const std::vector<uint32_t>& ipv4,
             const std::vector<std::array<uint8_t, 16>>& ipv6,
             uint32_t ttl_seconds);

    bool get(const std::string& host,
             std::vector<uint32_t>& ipv4,
             std::vector<std::array<uint8_t, 16>>& ipv6);

    void sweep();
    void clear();
    size_t size() const;
    size_t capacity() const { return max_entries_; }

private:
    struct Entry {
        std::vector<uint32_t> ipv4;
        std::vector<std::array<uint8_t, 16>> ipv6;
        uint64_t expiry_ns;
    };

    size_t max_entries_;
    std::unordered_map<std::string,
        std::list<std::pair<std::string, Entry>>::iterator> map_;
    std::list<std::pair<std::string, Entry>> list_;
    mutable std::unique_ptr<std::mutex> mutex_;
};

class DNSResolver {
public:
    static constexpr uint16_t DNS_PORT = 53;

    DNSResolver();
    explicit DNSResolver(const std::vector<std::string>& dns_servers);
    ~DNSResolver();

    struct Stats {
        uint64_t cache_hits   = 0;
        uint64_t cache_misses = 0;
        uint64_t udp_queries  = 0;
        uint64_t doh_queries  = 0;
        uint64_t fallbacks    = 0;
        uint64_t failures     = 0;
    };

    DNSResult resolve(const std::string& host,
                      RecordType type = RecordType::A,
                      uint32_t timeout_ms = 5000);

    // Wire-format utilities (exposed for testing and direct use)
    static std::vector<uint8_t> buildQuery(const std::string& host,
                                            RecordType type, uint16_t id);

    static bool parseResponse(const uint8_t* data, size_t len,
                               uint16_t expected_id,
                               std::vector<uint32_t>& ipv4,
                               std::vector<std::array<uint8_t, 16>>& ipv6,
                               uint32_t& ttl);

    static std::vector<uint8_t> encodeName(const std::string& host);
    static std::string decodeName(const uint8_t* data, size_t len,
                                   size_t& offset);
    static size_t skipName(const uint8_t* data, size_t len, size_t offset);

    void setDNSServers(const std::vector<std::string>& servers);
    std::vector<std::string> getDNSServers() const;

    void setDoHEnabled(bool enabled) { doh_enabled_ = enabled; }
    bool isDoHEnabled() const { return doh_enabled_; }
    void setDoHServer(const std::string& url);
    std::string getDoHServer() const { return doh_url_; }

    void setCacheSize(size_t max_entries);
    void clearCache();
    size_t cacheSize() const { return cache_.size(); }

    Stats getStats() const;
    void  resetStats();

private:
    DNSResult resolveViaUDP(const std::string& host,
                            RecordType type, uint32_t timeout_ms);
    DNSResult resolveViaDoH(const std::string& host,
                            RecordType type, uint32_t timeout_ms);
    DNSResult resolveViaSystem(const std::string& host, RecordType type);

    uint16_t allocateId();

    void cacheResult(const std::string& host, const DNSResult& result);
    DNSResult checkCache(const std::string& host);
    void incrementCacheHits();
    void incrementCacheMisses();
    void incrementUdpQueries();
    void incrementDohQueries();
    void incrementFallbacks();
    void incrementFailures();

    std::vector<std::string> dns_servers_;
    std::string doh_url_;
    std::string doh_host_;
    std::string doh_path_;
    bool doh_enabled_ = false;
    DNSCache cache_;
    mutable std::mutex stats_mutex_;
    Stats stats_;
    std::atomic<uint16_t> next_id_{1};
};

} // namespace pntp

#endif
