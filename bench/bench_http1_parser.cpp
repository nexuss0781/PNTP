#include <benchmark/benchmark.h>
#include "pntp/http1_parser.h"

#include <random>
#include <sstream>
#include <string>
#include <vector>

// ══════════════════════════════════════════════════════════════════════
// Bench: Parse Request Line
// ══════════════════════════════════════════════════════════════════════

static void BM_ParseRequestLine(benchmark::State& state) {
    std::string req = "GET /index.html HTTP/1.1\r\n\r\n";
    for (auto _ : state) {
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
        benchmark::DoNotOptimize(parser.isComplete());
    }
}
BENCHMARK(BM_ParseRequestLine);

// ══════════════════════════════════════════════════════════════════════
// Bench: Parse Response Line
// ══════════════════════════════════════════════════════════════════════

static void BM_ParseResponseLine(benchmark::State& state) {
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    for (auto _ : state) {
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
        benchmark::DoNotOptimize(parser.isComplete());
    }
}
BENCHMARK(BM_ParseResponseLine);

// ══════════════════════════════════════════════════════════════════════
// Bench: Parse 10 Headers
// ══════════════════════════════════════════════════════════════════════

static void BM_ParseHeaders_10(benchmark::State& state) {
    std::string req = "GET / HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "User-Agent: Mozilla/5.0\r\n"
                      "Accept: text/html,application/json\r\n"
                      "Accept-Language: en-US,en;q=0.5\r\n"
                      "Accept-Encoding: gzip, deflate\r\n"
                      "Connection: keep-alive\r\n"
                      "Cache-Control: no-cache\r\n"
                      "X-Custom-1: value1\r\n"
                      "X-Custom-2: value2\r\n"
                      "X-Custom-3: value3\r\n\r\n";
    for (auto _ : state) {
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
        benchmark::DoNotOptimize(parser.isComplete());
    }
}
BENCHMARK(BM_ParseHeaders_10);

// ══════════════════════════════════════════════════════════════════════
// Bench: Parse 50 Headers
// ══════════════════════════════════════════════════════════════════════

static void BM_ParseHeaders_50(benchmark::State& state) {
    std::ostringstream oss;
    oss << "GET / HTTP/1.1\r\nHost: example.com\r\n";
    for (int i = 0; i < 50; ++i) {
        oss << "X-Header-" << i << ": " << "some_value_for_this_header_" << i << "\r\n";
    }
    oss << "\r\n";
    std::string req = oss.str();

    for (auto _ : state) {
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
        benchmark::DoNotOptimize(parser.isComplete());
    }
}
BENCHMARK(BM_ParseHeaders_50);

// ══════════════════════════════════════════════════════════════════════
// Bench: Parse Chunked Body (1MB)
// ══════════════════════════════════════════════════════════════════════

static void BM_ParseChunkedBody_1MB(benchmark::State& state) {
    // Build a chunked response with ~1MB body in 8KB chunks
    std::string chunk_data(8192, 'A');
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    constexpr int num_chunks = 128;
    for (int i = 0; i < num_chunks; ++i) {
        oss << "2000\r\n";
        oss.write(chunk_data.data(), 8192);
        oss << "\r\n";
    }
    oss << "0\r\n\r\n";
    std::string resp = oss.str();

    for (auto _ : state) {
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
        benchmark::DoNotOptimize(parser.isComplete());
    }
}
BENCHMARK(BM_ParseChunkedBody_1MB);

// ══════════════════════════════════════════════════════════════════════
// Bench: Serialize Request
// ══════════════════════════════════════════════════════════════════════

static void BM_SerializeRequest(benchmark::State& state) {
    Http1Request req;
    req.method = H1_GET;
    req.path = "/api/data";
    req.query = "page=1&limit=10";
    req.version = H1_VER_1_1;

    std::vector<Http1Header> headers = {
        {"Host", "api.example.com"},
        {"Authorization", "Bearer token123"},
        {"Accept", "application/json"},
        {"User-Agent", "PNTP/4.0"}
    };

    for (auto _ : state) {
        auto wire = Http1Parser::serializeRequest(req, headers, nullptr, 0);
        benchmark::DoNotOptimize(wire.size());
    }
}
BENCHMARK(BM_SerializeRequest);

// ══════════════════════════════════════════════════════════════════════
// Bench: Serialize Response
// ══════════════════════════════════════════════════════════════════════

static void BM_SerializeResponse(benchmark::State& state) {
    Http1Response resp;
    resp.status_code = 200;
    resp.reason = "OK";
    resp.version = H1_VER_1_1;

    std::vector<Http1Header> headers = {
        {"Content-Type", "text/html; charset=utf-8"},
        {"Server", "PNTP/4.0"},
        {"Cache-Control", "no-cache"}
    };

    std::string body = "<html><body>Hello, World!</body></html>";

    for (auto _ : state) {
        auto wire = Http1Parser::serializeResponse(
            resp, headers,
            reinterpret_cast<const uint8_t*>(body.data()), body.size());
        benchmark::DoNotOptimize(wire.size());
    }
}
BENCHMARK(BM_SerializeResponse);

// ══════════════════════════════════════════════════════════════════════
// Bench: Full Round Trip (Parse then Serialize)
// ══════════════════════════════════════════════════════════════════════

static void BM_FullRoundTrip(benchmark::State& state) {
    std::string req = "POST /api/data HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Content-Type: application/json\r\n"
                      "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9\r\n"
                      "Content-Length: 23\r\n"
                      "\r\n"
                      "{\"key\": \"value\", \"n\": 1}";

    for (auto _ : state) {
        // Parse
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
        benchmark::DoNotOptimize(parser.isComplete());

        // Serialize response
        if (parser.isComplete()) {
            Http1Response resp;
            resp.status_code = 200;
            resp.reason = "OK";
            std::string response_body = "ok";
            auto wire = Http1Parser::serializeResponse(
                resp, {{"Content-Type", "text/plain"}},
                reinterpret_cast<const uint8_t*>(response_body.data()),
                response_body.size());
            benchmark::DoNotOptimize(wire.size());
        }
    }
}
BENCHMARK(BM_FullRoundTrip);

// ══════════════════════════════════════════════════════════════════════
// Bench: Content-Length Body Throughput
// ══════════════════════════════════════════════════════════════════════

static void BM_ContentLengthBodyThroughput(benchmark::State& state) {
    size_t body_size = static_cast<size_t>(state.range(0));
    std::string body(body_size, 'X');
    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\nContent-Length: " << body_size << "\r\n\r\n";
    oss << body;
    std::string resp = oss.str();

    for (auto _ : state) {
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
        benchmark::DoNotOptimize(parser.isComplete());
    }
}
BENCHMARK(BM_ContentLengthBodyThroughput)
    ->RangeMultiplier(10)
    ->Range(100, 100000);

// ══════════════════════════════════════════════════════════════════════
// Bench: Chunk Overhead
// ══════════════════════════════════════════════════════════════════════

static void BM_SerializeChunk(benchmark::State& state) {
    std::string data(state.range(0), 'A');
    for (auto _ : state) {
        auto chunk = Http1Parser::serializeChunk(
            reinterpret_cast<const uint8_t*>(data.data()), data.size());
        benchmark::DoNotOptimize(chunk.size());
    }
}
BENCHMARK(BM_SerializeChunk)->RangeMultiplier(10)->Range(10, 10000);

// BENCHMARK_MAIN removed - defined in bench_pntp_core.cpp
