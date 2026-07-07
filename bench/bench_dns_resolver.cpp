#include <benchmark/benchmark.h>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include "pntp/dns_resolver.h"

using namespace pntp;

// ── DNS Wire Format Benchmarks ──────────────────────────────────────

static void BM_EncodeName(benchmark::State& state) {
    std::string host = "www.example.com";
    for (auto _ : state) {
        auto encoded = DNSResolver::encodeName(host);
        benchmark::DoNotOptimize(encoded.data());
    }
}
BENCHMARK(BM_EncodeName);

static void BM_DecodeName(benchmark::State& state) {
    auto encoded = DNSResolver::encodeName("deep.subdomain.example.org");
    for (auto _ : state) {
        size_t offset = 0;
        auto name = DNSResolver::decodeName(encoded.data(), encoded.size(), offset);
        benchmark::DoNotOptimize(name.data());
    }
}
BENCHMARK(BM_DecodeName);

static void BM_BuildQuery(benchmark::State& state) {
    for (auto _ : state) {
        auto query = DNSResolver::buildQuery("example.com", RecordType::A, 1);
        benchmark::DoNotOptimize(query.data());
    }
}
BENCHMARK(BM_BuildQuery);

// ── DNS Response Parse Benchmarks ───────────────────────────────────

static std::vector<uint8_t> MakeTestResponse(size_t num_answers) {
    std::vector<uint8_t> resp;
    resp.push_back(0x12); resp.push_back(0x34);
    resp.push_back(0x81); resp.push_back(0x80);
    resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(0x00); resp.push_back(static_cast<uint8_t>(num_answers));
    resp.push_back(0x00); resp.push_back(0x00);
    resp.push_back(0x00); resp.push_back(0x00);
    uint8_t q[] = {7,'e','x','a','m','p','l','e', 3,'c','o','m', 0, 0,1, 0,1};
    resp.insert(resp.end(), q, q + sizeof(q));
    for (size_t i = 0; i < num_answers; ++i) {
        resp.push_back(0xC0); resp.push_back(0x0C);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x01);
        resp.push_back(0x00); resp.push_back(0x00);
        resp.push_back(0x01); resp.push_back(0x2C);
        resp.push_back(0x00); resp.push_back(0x04);
        resp.push_back(0x5D); resp.push_back(0xB8);
        resp.push_back(0xD8); resp.push_back(0x22);
    }
    return resp;
}

static void BM_ParseResponse_Single(benchmark::State& state) {
    auto resp = MakeTestResponse(1);
    for (auto _ : state) {
        std::vector<uint32_t> ipv4;
        std::vector<std::array<uint8_t, 16>> ipv6;
        uint32_t ttl = 0;
        bool ok = DNSResolver::parseResponse(resp.data(), resp.size(),
                                              0x1234, ipv4, ipv6, ttl);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_ParseResponse_Single);

static void BM_ParseResponse_Multi(benchmark::State& state) {
    auto resp = MakeTestResponse(10);
    for (auto _ : state) {
        std::vector<uint32_t> ipv4;
        std::vector<std::array<uint8_t, 16>> ipv6;
        uint32_t ttl = 0;
        bool ok = DNSResolver::parseResponse(resp.data(), resp.size(),
                                              0x1234, ipv4, ipv6, ttl);
        benchmark::DoNotOptimize(ok);
    }
}
BENCHMARK(BM_ParseResponse_Multi);

// ── DNSCache Benchmarks ─────────────────────────────────────────────

static void BM_CachePut(benchmark::State& state) {
    DNSCache cache(10000);
    std::vector<uint32_t> ipv4 = {0x5DB8D822};
    std::vector<std::array<uint8_t, 16>> ipv6;
    int i = 0;
    for (auto _ : state) {
        cache.put("host" + std::to_string(i++), ipv4, ipv6, 300);
    }
}
BENCHMARK(BM_CachePut);

static void BM_CacheGet_Hit(benchmark::State& state) {
    DNSCache cache(10000);
    std::vector<uint32_t> ipv4 = {0x5DB8D822};
    std::vector<std::array<uint8_t, 16>> ipv6;
    cache.put("example.com", ipv4, ipv6, 300);

    for (auto _ : state) {
        std::vector<uint32_t> out4;
        std::vector<std::array<uint8_t, 16>> out6;
        bool hit = cache.get("example.com", out4, out6);
        benchmark::DoNotOptimize(hit);
    }
}
BENCHMARK(BM_CacheGet_Hit);

static void BM_CacheGet_Miss(benchmark::State& state) {
    DNSCache cache(10000);
    for (auto _ : state) {
        std::vector<uint32_t> out4;
        std::vector<std::array<uint8_t, 16>> out6;
        bool hit = cache.get("nonexistent.example", out4, out6);
        benchmark::DoNotOptimize(hit);
    }
}
BENCHMARK(BM_CacheGet_Miss);

static void BM_CacheSweep(benchmark::State& state) {
    DNSCache cache(100000);
    std::vector<uint32_t> ipv4 = {0x5DB8D822};
    std::vector<std::array<uint8_t, 16>> ipv6;
    for (int i = 0; i < 100000; ++i) {
        cache.put("host" + std::to_string(i), ipv4, ipv6, 1);
    }
    std::this_thread::sleep_for(std::chrono::seconds(2));
    for (auto _ : state) {
        cache.sweep();
    }
}
BENCHMARK(BM_CacheSweep);

// ── End-to-End Resolve Benchmark ─────────────────────────────────────

static void BM_Resolve_Cold(benchmark::State& state) {
    DNSResolver resolver;
    for (auto _ : state) {
        auto result = resolver.resolve("example.com", RecordType::A, 2000);
        benchmark::DoNotOptimize(result.success);
        if (result.success) break; // one cold resolve
    }
    state.SetLabel("cold (first resolve)");
}
BENCHMARK(BM_Resolve_Cold)->Iterations(1);

static void BM_Resolve_Hot(benchmark::State& state) {
    DNSResolver resolver;
    resolver.resolve("example.com", RecordType::A, 2000); // warm cache
    for (auto _ : state) {
        auto result = resolver.resolve("example.com", RecordType::A, 2000);
        benchmark::DoNotOptimize(result.success);
    }
    state.SetLabel("hot (cached)");
}
BENCHMARK(BM_Resolve_Hot);

BENCHMARK_MAIN();
