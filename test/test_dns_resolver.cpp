#include <gtest/gtest.h>
#include <thread>
#include <chrono>
#include <arpa/inet.h>

#include "pntp/dns_resolver.h"

using namespace pntp;

// ── DNS Wire Format Tests ────────────────────────────────────────────

class DNSWireFormatTest : public ::testing::Test {};

TEST_F(DNSWireFormatTest, EncodeName_Simple) {
    auto encoded = DNSResolver::encodeName("example.com");
    // 07example03com00
    ASSERT_EQ(encoded.size(), 14);
    EXPECT_EQ(encoded[0],  7);
    EXPECT_EQ(encoded[1], 'e'); EXPECT_EQ(encoded[2], 'x');
    EXPECT_EQ(encoded[3], 'a'); EXPECT_EQ(encoded[4], 'm');
    EXPECT_EQ(encoded[5], 'p'); EXPECT_EQ(encoded[6], 'l');
    EXPECT_EQ(encoded[7], 'e');
    EXPECT_EQ(encoded[8],  3);
    EXPECT_EQ(encoded[9], 'c'); EXPECT_EQ(encoded[10], 'o');
    EXPECT_EQ(encoded[11], 'm');
    EXPECT_EQ(encoded[12], 0);
}

TEST_F(DNSWireFormatTest, EncodeName_MultiLevel) {
    auto encoded = DNSResolver::encodeName("sub.domain.example.com");
    EXPECT_GT(encoded.size(), 0);
    EXPECT_EQ(encoded.back(), 0);
    EXPECT_EQ(encoded[0], 3);
    EXPECT_EQ(encoded[1], 's'); EXPECT_EQ(encoded[2], 'u'); EXPECT_EQ(encoded[3], 'b');
}

TEST_F(DNSWireFormatTest, EncodeName_SingleLabel) {
    auto encoded = DNSResolver::encodeName("localhost");
    ASSERT_EQ(encoded.size(), 10);
    EXPECT_EQ(encoded[0], 9);
    EXPECT_EQ(encoded[9], 0);
}

TEST_F(DNSWireFormatTest, DecodeName_Simple) {
    uint8_t data[] = {7, 'e','x','a','m','p','l','e', 3, 'c','o','m', 0, 0,0};
    size_t offset = 0;
    std::string name = DNSResolver::decodeName(data, sizeof(data), offset);
    EXPECT_EQ(name, "example.com");
    EXPECT_EQ(offset, 13);
}

TEST_F(DNSWireFormatTest, DecodeName_Pointer) {
    uint8_t data[] = {
        3, 'c','o','m', 0,
        7, 'e','x','a','m','p','l','e', 0xC0, 0x00
    };
    size_t offset = 7;
    std::string name = DNSResolver::decodeName(data, sizeof(data), offset);
    EXPECT_EQ(name, "example.com");
    EXPECT_EQ(offset, 9);
}

TEST_F(DNSWireFormatTest, EncodeDecode_RoundTrip) {
    std::string hosts[] = {
        "example.com",
        "www.google.com",
        "a.b.c.d.e.example.org",
        "localhost",
        "single"
    };
    for (const auto& host : hosts) {
        auto encoded = DNSResolver::encodeName(host);
        size_t offset = 0;
        std::string decoded = DNSResolver::decodeName(encoded.data(), encoded.size(), offset);
        EXPECT_EQ(decoded, host) << "Round-trip failed for: " << host;
    }
}

// ── DNS Query Builder Tests ──────────────────────────────────────────

class DNSQueryBuilderTest : public ::testing::Test {};

TEST_F(DNSQueryBuilderTest, BuildQuery_ValidHeader) {
    auto query = DNSResolver::buildQuery("example.com", RecordType::A, 0x1234);
    ASSERT_GE(query.size(), 12);

    // Verify header
    EXPECT_EQ(query[0], 0x12);
    EXPECT_EQ(query[1], 0x34);
    EXPECT_EQ(query[2], 0x01); // RD=1
    EXPECT_EQ(query[3], 0x00);
    EXPECT_EQ(query[4], 0x00); EXPECT_EQ(query[5], 0x01); // QDCOUNT=1
    EXPECT_EQ(query[6], 0x00); EXPECT_EQ(query[7], 0x00); // ANCOUNT=0
}

TEST_F(DNSQueryBuilderTest, BuildQuery_QuestionSection) {
    auto query = DNSResolver::buildQuery("example.com", RecordType::A, 1);
    ASSERT_GE(query.size(), 18);

    // Question name: 07example03com00
    EXPECT_EQ(query[12], 7);
    EXPECT_EQ(query[20], 3);
    EXPECT_EQ(query[24], 0); // end of name

    // QTYPE (A = 1)
    EXPECT_EQ(query[25], 0x00);
    EXPECT_EQ(query[26], 0x01);

    // QCLASS (IN = 1)
    EXPECT_EQ(query[27], 0x00);
    EXPECT_EQ(query[28], 0x01);
}

TEST_F(DNSQueryBuilderTest, BuildQuery_AAAAType) {
    auto query = DNSResolver::buildQuery("example.com", RecordType::AAAA, 1);
    ASSERT_GE(query.size(), 29);
    EXPECT_EQ(query[25], 0x00);
    EXPECT_EQ(query[26], 0x1C); // AAAA = 28
}

TEST_F(DNSQueryBuilderTest, BuildQuery_DifferentIDs) {
    auto q1 = DNSResolver::buildQuery("test.com", RecordType::A, 0xAAAA);
    auto q2 = DNSResolver::buildQuery("test.com", RecordType::A, 0xBBBB);
    EXPECT_EQ(q1.size(), q2.size());
    EXPECT_EQ(q1[0], 0xAA); EXPECT_EQ(q1[1], 0xAA);
    EXPECT_EQ(q2[0], 0xBB); EXPECT_EQ(q2[1], 0xBB);
}

// ── DNS Response Parser Tests ────────────────────────────────────────

class DNSResponseParserTest : public ::testing::Test {
protected:
    // Constructed DNS response for example.com A record query (ID=0x1234)
    // Response: 93.184.216.34, TTL=302
    std::vector<uint8_t> makeAResponse() {
        std::vector<uint8_t> resp;
        // Header: ID=0x1234, QR=1, RD=1, RA=1, RCODE=0
        resp.push_back(0x12); resp.push_back(0x34);
        resp.push_back(0x81); resp.push_back(0x80);
        resp.push_back(0x00); resp.push_back(0x01); // QDCOUNT=1
        resp.push_back(0x00); resp.push_back(0x01); // ANCOUNT=1
        resp.push_back(0x00); resp.push_back(0x00); // NSCOUNT=0
        resp.push_back(0x00); resp.push_back(0x00); // ARCOUNT=0
        // Question: 07example03com00 QTYPE=A QCLASS=IN
        uint8_t q[] = {7,'e','x','a','m','p','l','e', 3,'c','o','m', 0, 0,1, 0,1};
        resp.insert(resp.end(), q, q + sizeof(q));
        // Answer: pointer 0xC00C TYPE=A CLASS=IN TTL=302 RDLENGTH=4 RDATA=93.184.216.34
        resp.push_back(0xC0); resp.push_back(0x0C);
        resp.push_back(0x00); resp.push_back(0x01); // TYPE=A
        resp.push_back(0x00); resp.push_back(0x01); // CLASS=IN
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x01); resp.push_back(0x2E); // TTL=302
        resp.push_back(0x00); resp.push_back(0x04); // RDLENGTH=4
        resp.push_back(0x5D); resp.push_back(0xB8);
        resp.push_back(0xD8); resp.push_back(0x22); // 93.184.216.34
        return resp;
    }

    // Constructed DNS response for example.com AAAA record
    // IPv6: 2606:2800:220:1:248:1893:25c8:1946
    std::vector<uint8_t> makeAAAAAResponse() {
        std::vector<uint8_t> resp;
        resp.push_back(0x56); resp.push_back(0x78); // ID=0x5678
        resp.push_back(0x81); resp.push_back(0x80);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(0x00);
        // Question: 07example03com00 QTYPE=AAAA QCLASS=IN
        uint8_t q[] = {7,'e','x','a','m','p','l','e', 3,'c','o','m', 0, 0,0x1C, 0,1};
        resp.insert(resp.end(), q, q + sizeof(q));
        // Answer: pointer 0xC00C TYPE=AAAA CLASS=IN TTL=300 RDLENGTH=16
        resp.push_back(0xC0); resp.push_back(0x0C);
        resp.push_back(0x00); resp.push_back(0x1C); // TYPE=AAAA
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x01); resp.push_back(0x2C); // TTL=300
        resp.push_back(0x00); resp.push_back(0x10); // RDLENGTH=16
        // 2606:2800:220:1:248:1893:25c8:1946
        uint8_t ipv6[] = {0x26,0x06,0x28,0x00,0x02,0x20,0x00,0x01,
                          0x02,0x48,0x18,0x93,0x25,0xC8,0x19,0x46};
        resp.insert(resp.end(), ipv6, ipv6 + 16);
        return resp;
    }

    // NXDOMAIN response
    std::vector<uint8_t> makeNXDOMAINResponse() {
        std::vector<uint8_t> resp;
        resp.push_back(0x12); resp.push_back(0x35);
        resp.push_back(0x81); resp.push_back(0x83); // RCODE=3 (NXDOMAIN)
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x00);
        uint8_t q[] = {3,'x','y','z', 0, 0,1, 0,1};
        resp.insert(resp.end(), q, q + sizeof(q));
        // Authority SOA (minimal)
        uint8_t soa[] = {0xC0,0x0C, 0x00,0x06, 0x00,0x01,
                         0x00,0x00,0x0E,0x10, 0x00,0x14};
        resp.insert(resp.end(), soa, soa + sizeof(soa));
        uint8_t soa_data[] = {0xC0,0x0C, 0xC0,0x0C,
                              0x00,0x00,0x0E,0x10,
                              0x00,0x00,0x0E,0x10,
                              0x00,0x00,0x0E,0x10,
                              0x00,0x00,0x0E,0x10};
        resp.insert(resp.end(), soa_data, soa_data + sizeof(soa_data));
        return resp;
    }

    // Multiple A records response
    std::vector<uint8_t> makeMultiAResponse() {
        std::vector<uint8_t> resp;
        resp.push_back(0xAB); resp.push_back(0xCD);
        resp.push_back(0x81); resp.push_back(0x80);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x03); // ANCOUNT=3
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(0x00);
        uint8_t q[] = {4,'t','e','s','t', 0, 0,1, 0,1};
        resp.insert(resp.end(), q, q + sizeof(q));
        // 3 A records
        uint32_t addrs[] = {0xC0000001, 0xC0000002, 0xC0000003};
        uint32_t base_offset = static_cast<uint32_t>(resp.size() + 2);
        for (int i = 0; i < 3; ++i) {
            resp.push_back(0xC0); resp.push_back(static_cast<uint8_t>(base_offset & 0xFF));
            resp.push_back(0x00); resp.push_back(0x01);
            resp.push_back(0x00); resp.push_back(0x01);
            uint32_t ttl = htonl(300 + static_cast<uint32_t>(i));
            uint8_t* ttl_bytes = reinterpret_cast<uint8_t*>(&ttl);
            for (int b = 0; b < 4; ++b) resp.push_back(ttl_bytes[b]);
            resp.push_back(0x00); resp.push_back(0x04);
            uint32_t addr = htonl(addrs[i]);
            uint8_t* addr_bytes = reinterpret_cast<uint8_t*>(&addr);
            for (int b = 0; b < 4; ++b) resp.push_back(addr_bytes[b]);
        }
        return resp;
    }
};

TEST_F(DNSResponseParserTest, ParseARecord) {
    auto resp = makeAResponse();
    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;

    EXPECT_TRUE(DNSResolver::parseResponse(resp.data(), resp.size(),
                                            0x1234, ipv4, ipv6, ttl));
    ASSERT_EQ(ipv4.size(), 1);
    EXPECT_EQ(ipv4[0], 0x5DB8D822); // 93.184.216.34 in host order
    EXPECT_GE(ttl, 1);
}

TEST_F(DNSResponseParserTest, ParseAAAARecord) {
    auto resp = makeAAAAAResponse();
    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;

    EXPECT_TRUE(DNSResolver::parseResponse(resp.data(), resp.size(),
                                            0x5678, ipv4, ipv6, ttl));
    ASSERT_EQ(ipv6.size(), 1);
    EXPECT_EQ(ipv6[0][0], 0x26);
    EXPECT_EQ(ipv6[0][1], 0x06);
    EXPECT_EQ(ttl, 300);
}

TEST_F(DNSResponseParserTest, ParseNXDOMAIN) {
    auto resp = makeNXDOMAINResponse();
    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;

    EXPECT_FALSE(DNSResolver::parseResponse(resp.data(), resp.size(),
                                             0x1235, ipv4, ipv6, ttl));
    EXPECT_TRUE(ipv4.empty());
}

TEST_F(DNSResponseParserTest, ParseWrongTransactionID) {
    auto resp = makeAResponse();
    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;

    EXPECT_FALSE(DNSResolver::parseResponse(resp.data(), resp.size(),
                                             0xDEAD, ipv4, ipv6, ttl));
}

TEST_F(DNSResponseParserTest, ParseEmptyResponse) {
    std::vector<uint8_t> empty;
    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;

    EXPECT_FALSE(DNSResolver::parseResponse(empty.data(), empty.size(),
                                             1, ipv4, ipv6, ttl));
}

TEST_F(DNSResponseParserTest, ParseTruncatedResponse) {
    std::vector<uint8_t> truncated = {0x12, 0x34, 0x81, 0x80};
    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;

    EXPECT_FALSE(DNSResolver::parseResponse(truncated.data(), truncated.size(),
                                             0x1234, ipv4, ipv6, ttl));
}

TEST_F(DNSResponseParserTest, ParseMultipleARecords) {
    auto resp = makeMultiAResponse();
    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;

    EXPECT_TRUE(DNSResolver::parseResponse(resp.data(), resp.size(),
                                            0xABCD, ipv4, ipv6, ttl));
    ASSERT_EQ(ipv4.size(), 3);
}

// ── DNSCache Tests ───────────────────────────────────────────────────

class DNSCacheTest : public ::testing::Test {
protected:
    void SetUp() override {
        cache = std::make_unique<DNSCache>(5);
    }

    std::unique_ptr<DNSCache> cache;
};

TEST_F(DNSCacheTest, PutAndGet) {
    std::vector<uint32_t> ipv4 = {0x5DB8D822};
    std::vector<std::array<uint8_t, 16>> ipv6;
    cache->put("example.com", ipv4, ipv6, 300);

    std::vector<uint32_t> out_ipv4;
    std::vector<std::array<uint8_t, 16>> out_ipv6;
    EXPECT_TRUE(cache->get("example.com", out_ipv4, out_ipv6));
    ASSERT_EQ(out_ipv4.size(), 1);
    EXPECT_EQ(out_ipv4[0], 0x5DB8D822);
}

TEST_F(DNSCacheTest, GetMissing) {
    std::vector<uint32_t> out_ipv4;
    std::vector<std::array<uint8_t, 16>> out_ipv6;
    EXPECT_FALSE(cache->get("nonexistent.example", out_ipv4, out_ipv6));
}

TEST_F(DNSCacheTest, TTLExpiry) {
    std::vector<uint32_t> ipv4 = {0x01020304};
    std::vector<std::array<uint8_t, 16>> ipv6;
    cache->put("ttl-test.example", ipv4, ipv6, 1);

    std::vector<uint32_t> out_ipv4;
    std::vector<std::array<uint8_t, 16>> out_ipv6;
    EXPECT_TRUE(cache->get("ttl-test.example", out_ipv4, out_ipv6));

    // Sleep past TTL
    std::this_thread::sleep_for(std::chrono::seconds(2));
    cache->sweep();
    EXPECT_FALSE(cache->get("ttl-test.example", out_ipv4, out_ipv6));
}

TEST_F(DNSCacheTest, TTLZeroNeverCached) {
    std::vector<uint32_t> ipv4 = {0x01020304};
    std::vector<std::array<uint8_t, 16>> ipv6;
    cache->put("no-cache.example", ipv4, ipv6, 0);

    std::vector<uint32_t> out_ipv4;
    std::vector<std::array<uint8_t, 16>> out_ipv6;
    EXPECT_FALSE(cache->get("no-cache.example", out_ipv4, out_ipv6));
}

TEST_F(DNSCacheTest, LRUEviction) {
    for (int i = 0; i < 10; ++i) {
        std::vector<uint32_t> ipv4 = {static_cast<uint32_t>(i)};
        std::vector<std::array<uint8_t, 16>> ipv6;
        cache->put("host" + std::to_string(i), ipv4, ipv6, 300);
    }
    EXPECT_EQ(cache->size(), 5);

    std::vector<uint32_t> out_ipv4;
    std::vector<std::array<uint8_t, 16>> out_ipv6;
    EXPECT_FALSE(cache->get("host0", out_ipv4, out_ipv6));
    EXPECT_TRUE(cache->get("host9", out_ipv4, out_ipv6));
}

TEST_F(DNSCacheTest, LRUAccessPromotion) {
    for (int i = 0; i < 5; ++i) {
        std::vector<uint32_t> ipv4 = {static_cast<uint32_t>(i)};
        std::vector<std::array<uint8_t, 16>> ipv6;
        cache->put("host" + std::to_string(i), ipv4, ipv6, 300);
    }

    // Access host0 to promote it
    std::vector<uint32_t> out_ipv4;
    std::vector<std::array<uint8_t, 16>> out_ipv6;
    EXPECT_TRUE(cache->get("host0", out_ipv4, out_ipv6));

    // Add more to trigger eviction
    for (int i = 5; i < 8; ++i) {
        std::vector<uint32_t> ipv4 = {static_cast<uint32_t>(i)};
        std::vector<std::array<uint8_t, 16>> ipv6;
        cache->put("host" + std::to_string(i), ipv4, ipv6, 300);
    }

    // host1 should be evicted (least recently used)
    EXPECT_FALSE(cache->get("host1", out_ipv4, out_ipv6));
    // host0 should still exist (promoted)
    EXPECT_TRUE(cache->get("host0", out_ipv4, out_ipv6));
}

TEST_F(DNSCacheTest, Clear) {
    std::vector<uint32_t> ipv4 = {0x5DB8D822};
    std::vector<std::array<uint8_t, 16>> ipv6;
    cache->put("example.com", ipv4, ipv6, 300);
    cache->clear();
    EXPECT_EQ(cache->size(), 0);
}

TEST_F(DNSCacheTest, UpdateExisting) {
    std::vector<uint32_t> ipv4_a = {0x01020304};
    std::vector<uint32_t> ipv4_b = {0x05060708};
    std::vector<std::array<uint8_t, 16>> ipv6;

    cache->put("host", ipv4_a, ipv6, 300);
    cache->put("host", ipv4_b, ipv6, 300);

    std::vector<uint32_t> out_ipv4;
    std::vector<std::array<uint8_t, 16>> out_ipv6;
    EXPECT_TRUE(cache->get("host", out_ipv4, out_ipv6));
    ASSERT_EQ(out_ipv4.size(), 1);
    EXPECT_EQ(out_ipv4[0], 0x05060708);
}

// ── DNS Resolver Integration Tests ───────────────────────────────────

class DNSResolverIntegrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        resolver = std::make_unique<DNSResolver>();
    }

    std::unique_ptr<DNSResolver> resolver;
};

TEST_F(DNSResolverIntegrationTest, ResolveExampleComViaUDP) {
    // This test requires network access and a DNS server
    auto result = resolver->resolve("example.com", RecordType::A, 3000);
    if (!result.success) {
        GTEST_SKIP() << "Network/DNS not available, skipping integration test";
    }
    EXPECT_FALSE(result.ipv4_addresses.empty());
    bool found = false;
    for (uint32_t addr : result.ipv4_addresses) {
        if (addr == 0x5DB8D822) { found = true; break; } // 93.184.216.34
    }
    EXPECT_TRUE(found) << "Expected 93.184.216.34 for example.com";
    EXPECT_GT(result.ttl_seconds, 0);
}

TEST_F(DNSResolverIntegrationTest, ResolveViaCache) {
    auto first = resolver->resolve("example.com", RecordType::A, 3000);
    if (!first.success) {
        GTEST_SKIP() << "Network/DNS not available, skipping cache test";
    }

    auto stats = resolver->getStats();
    EXPECT_GE(stats.cache_hits + stats.cache_misses, 1);

    auto second = resolver->resolve("example.com", RecordType::A, 3000);
    EXPECT_TRUE(second.success);
}

TEST_F(DNSResolverIntegrationTest, ResolveInvalidHost) {
    auto result = resolver->resolve("this-domain-does-not-exist-12345.test",
                                     RecordType::A, 2000);
    EXPECT_FALSE(result.success);
}

TEST_F(DNSResolverIntegrationTest, ResolveMultipleServers) {
    resolver->setDNSServers({"8.8.8.8", "1.1.1.1"});
    auto result = resolver->resolve("google.com", RecordType::A, 3000);
    if (!result.success) {
        GTEST_SKIP() << "Network/DNS not available";
    }
    EXPECT_FALSE(result.ipv4_addresses.empty());
}

TEST_F(DNSResolverIntegrationTest, AAAAQuery) {
    auto result = resolver->resolve("example.com", RecordType::AAAA, 3000);
    if (!result.success) {
        GTEST_SKIP() << "Network/DNS not available or AAAA not supported";
    }
    EXPECT_FALSE(result.ipv6_addresses.empty());
}

TEST_F(DNSResolverIntegrationTest, CachePerformance) {
    auto result = resolver->resolve("example.com", RecordType::A, 3000);
    if (!result.success) {
        GTEST_SKIP() << "Network/DNS not available";
    }

    // Second resolve should be from cache (near-zero time)
    auto cached = resolver->resolve("example.com", RecordType::A, 3000);
    EXPECT_TRUE(cached.success);
    EXPECT_LT(cached.resolve_time_us, result.resolve_time_us);
}

TEST_F(DNSResolverIntegrationTest, ResolveOrderUDPFallback) {
    // Set an invalid DoH server, should fall through to UDP
    resolver->setDoHEnabled(true);
    resolver->setDoHServer("https://invalid-doh-server.example/dns-query");

    auto result = resolver->resolve("example.com", RecordType::A, 3000);
    if (!result.success) {
        GTEST_SKIP() << "Network/DNS not available";
    }
    EXPECT_TRUE(result.success);

    auto stats = resolver->getStats();
    EXPECT_GE(stats.udp_queries, 1);
}

TEST_F(DNSResolverIntegrationTest, ClearCacheBetweenResolves) {
    auto result = resolver->resolve("example.com", RecordType::A, 3000);
    if (!result.success) {
        GTEST_SKIP() << "Network/DNS not available";
    }

    resolver->clearCache();
    auto stats_before = resolver->getStats();
    EXPECT_EQ(stats_before.cache_hits, 0);

    // Should miss cache and query again
    auto again = resolver->resolve("example.com", RecordType::A, 3000);
    EXPECT_TRUE(again.success);
}

// ── Resolver Configuration Tests ─────────────────────────────────────

class DNSResolverConfigTest : public ::testing::Test {
protected:
    DNSResolver resolver;
};

TEST_F(DNSResolverConfigTest, DefaultServers) {
    auto servers = resolver.getDNSServers();
    ASSERT_GE(servers.size(), 2);
    EXPECT_EQ(servers[0], "1.1.1.1");
    EXPECT_EQ(servers[1], "8.8.8.8");
}

TEST_F(DNSResolverConfigTest, CustomServers) {
    resolver.setDNSServers({"9.9.9.9", "208.67.222.222"});
    auto servers = resolver.getDNSServers();
    ASSERT_EQ(servers.size(), 2);
    EXPECT_EQ(servers[0], "9.9.9.9");
    EXPECT_EQ(servers[1], "208.67.222.222");
}

TEST_F(DNSResolverConfigTest, DoHServerParsing) {
    resolver.setDoHServer("https://dns.google/dns-query");
    EXPECT_EQ(resolver.getDoHServer(), "https://dns.google/dns-query");
}

TEST_F(DNSResolverConfigTest, DoHEnableDisable) {
    EXPECT_FALSE(resolver.isDoHEnabled());
    resolver.setDoHEnabled(true);
    EXPECT_TRUE(resolver.isDoHEnabled());
    resolver.setDoHEnabled(false);
    EXPECT_FALSE(resolver.isDoHEnabled());
}

TEST_F(DNSResolverConfigTest, StatsInitialState) {
    auto stats = resolver.getStats();
    EXPECT_EQ(stats.cache_hits, 0);
    EXPECT_EQ(stats.cache_misses, 0);
    EXPECT_EQ(stats.udp_queries, 0);
    EXPECT_EQ(stats.doh_queries, 0);
    EXPECT_EQ(stats.fallbacks, 0);
    EXPECT_EQ(stats.failures, 0);
}

TEST_F(DNSResolverConfigTest, ResetStats) {
    resolver.resolve("this-does-not-exist.example", RecordType::A, 1000);

    resolver.resetStats();
    auto stats = resolver.getStats();
    EXPECT_EQ(stats.cache_misses, 0);
}

TEST_F(DNSResolverConfigTest, CacheSizeConfig) {
    resolver.setCacheSize(100);
    EXPECT_EQ(resolver.cacheSize(), 0);

    // Resolve and verify cache doesn't grow unbounded
    resolver.resolve("example.com", RecordType::A, 1000);
    EXPECT_LE(resolver.cacheSize(), 100);
}

// ── Goal Validation Tests ────────────────────────────────────────────

class DNSGoalValidationTest : public ::testing::Test {
    // Phase 4 goal: Bypass system resolver with raw DNS + DoH capability.
    // These tests validate that the DNS resolver meets its design goals.
};

TEST_F(DNSGoalValidationTest, Goal_RawWireFormat_NoGetaddrinfo) {
    // Goal: Build and parse DNS wire format without using system resolver
    DNSResolver resolver;
    auto query = DNSResolver::buildQuery("test.example", RecordType::A, 1);
    EXPECT_GT(query.size(), 12);
    EXPECT_EQ(query[12], 4); // label "test"
    EXPECT_EQ(query[13], 't');
}

TEST_F(DNSGoalValidationTest, Goal_NameCompressionHandling) {
    // Goal: Correctly handle DNS name compression pointers
    uint8_t data[] = {
        3, 'c','o','m', 0,
        4, 't','e','s','t', 0xC0, 0x00
    };
    size_t offset = 5;
    std::string name = DNSResolver::decodeName(data, sizeof(data), offset);
    EXPECT_EQ(name, "test.com");
    EXPECT_EQ(offset, 7);
}

TEST_F(DNSGoalValidationTest, Goal_CacheBypassesResolution) {
    // Goal: Cache should return results without network query
    DNSResolver resolver;
    // Put directly into cache (via private cache — we test through resolve)
    resolver.resolve("example.com", RecordType::A, 3000);

    // Cache miss tracking
    auto stats_before = resolver.getStats();
    uint64_t misses_before = stats_before.cache_misses;

    resolver.resolve("example.com", RecordType::A, 3000);

    auto stats_after = resolver.getStats();
    EXPECT_EQ(stats_after.cache_misses, misses_before);
}

TEST_F(DNSGoalValidationTest, Goal_MultipleARecords) {
    // Goal: Support multiple A records in response
    auto resp = std::vector<uint8_t>();
    // Build manual response with 2 A records
    resp.push_back(0x00); resp.push_back(0x01); // ID
    resp.push_back(0x81); resp.push_back(0x80); // flags
    resp.push_back(0x00); resp.push_back(0x01); // QDCOUNT
    resp.push_back(0x00); resp.push_back(0x02); // ANCOUNT=2
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x00);
    uint8_t q[] = {4,'m','u','l','t', 0, 0,1, 0,1};
    resp.insert(resp.end(), q, q + sizeof(q));
    // Two A records pointing to same name
    for (int i = 0; i < 2; ++i) {
        resp.push_back(0xC0); resp.push_back(0x0C);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x01); resp.push_back(0x2C); // TTL=300
        resp.push_back(0x00); resp.push_back(0x04);
        resp.push_back(0xC0); resp.push_back(0x00);
        resp.push_back(0x00); resp.push_back(static_cast<uint8_t>(i + 1));
    }

    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;
    EXPECT_TRUE(DNSResolver::parseResponse(resp.data(), resp.size(),
                                            1, ipv4, ipv6, ttl));
    EXPECT_EQ(ipv4.size(), 2);
}

TEST_F(DNSGoalValidationTest, Goal_CacheLRUPreventsUnboundedGrowth) {
    // Goal: LRU eviction must bound cache size
    DNSCache cache(3);

    for (int i = 0; i < 10; ++i) {
        std::vector<uint32_t> ipv4 = {static_cast<uint32_t>(i)};
        std::vector<std::array<uint8_t, 16>> ipv6;
        cache.put("host" + std::to_string(i), ipv4, ipv6, 300);
    }

    EXPECT_EQ(cache.size(), 3);
}

TEST_F(DNSGoalValidationTest, Goal_ConfigurableServers) {
    // Goal: DNS servers must be configurable
    DNSResolver resolver({"9.9.9.9", "149.112.112.112"});
    auto servers = resolver.getDNSServers();
    EXPECT_EQ(servers[0], "9.9.9.9");
    EXPECT_EQ(servers[1], "149.112.112.112");
}

TEST_F(DNSGoalValidationTest, Goal_TTLTracking) {
    // Goal: DNS results must preserve TTL information from response
    auto resp = std::vector<uint8_t>();
    resp.push_back(0x12); resp.push_back(0x34);
    resp.push_back(0x81); resp.push_back(0x80);
    resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x00);
    uint8_t q[] = {7,'e','x','a','m','p','l','e', 3,'c','o','m', 0, 0,1, 0,1};
    resp.insert(resp.end(), q, q + sizeof(q));
    resp.push_back(0xC0); resp.push_back(0x0C);
    resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x0E); resp.push_back(0x10); // TTL=3600
    resp.push_back(0x00); resp.push_back(0x04);
    resp.push_back(0x5D); resp.push_back(0xB8);
    resp.push_back(0xD8); resp.push_back(0x22);

    std::vector<uint32_t> ipv4;
    std::vector<std::array<uint8_t, 16>> ipv6;
    uint32_t ttl = 0;
    EXPECT_TRUE(DNSResolver::parseResponse(resp.data(), resp.size(),
                                            0x1234, ipv4, ipv6, ttl));
    EXPECT_EQ(ttl, 3600);
}
