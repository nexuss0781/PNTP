#include "pntp/http2_parser.h"
#include <benchmark/benchmark.h>
#include <cstring>
#include <random>

// ── Helper: Build a wire frame ───────────────────────────────────────

static std::vector<uint8_t> makeFrame(uint8_t type, uint8_t flags,
    uint32_t stream_id, const std::vector<uint8_t>& payload)
{
    auto hdr = Http2Parser::makeFrameHeader(
        static_cast<uint32_t>(payload.size()), type, flags, stream_id);
    hdr.insert(hdr.end(), payload.begin(), payload.end());
    return hdr;
}

// ── HPACK Benchmarks ─────────────────────────────────────────────────

static void BM_HpackEncode_SimpleRequest(benchmark::State& state) {
    HpackEncoder encoder;
    bool error = false;
    std::vector<HpackHeaderField> headers = {
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"},
        {":authority", "example.com"},
        {"accept", "*/*"},
        {"user-agent", "PNTP/4.0"}
    };

    for (auto _ : state) {
        error = false;
        auto result = encoder.encode(headers, error);
        benchmark::DoNotOptimize(result);
        if (error) state.SkipWithError("Encode failed");
    }
}
BENCHMARK(BM_HpackEncode_SimpleRequest);

static void BM_HpackEncode_Response(benchmark::State& state) {
    HpackEncoder encoder;
    bool error = false;
    std::vector<HpackHeaderField> headers = {
        {":status", "200"},
        {"content-type", "text/html; charset=utf-8"},
        {"content-length", "12345"},
        {"server", "nginx/1.24.0"},
        {"date", "Mon, 01 Jan 2024 00:00:00 GMT"},
        {"cache-control", "public, max-age=3600"},
        {"x-frame-options", "DENY"}
    };

    for (auto _ : state) {
        error = false;
        auto result = encoder.encode(headers, error);
        benchmark::DoNotOptimize(result);
        if (error) state.SkipWithError("Encode failed");
    }
}
BENCHMARK(BM_HpackEncode_Response);

static void BM_HpackDecode_SimpleRequest(benchmark::State& state) {
    HpackEncoder encoder;
    HpackDecoder decoder;
    bool error = false;

    auto encoded = encoder.encode({
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"},
        {":authority", "example.com"},
        {"accept", "*/*"},
        {"user-agent", "PNTP/4.0"}
    }, error);
    if (error) state.SkipWithError("Encode failed");

    for (auto _ : state) {
        error = false;
        auto result = decoder.decode(encoded.data(), encoded.size(), error);
        benchmark::DoNotOptimize(result);
        if (error) state.SkipWithError("Decode failed");
    }
}
BENCHMARK(BM_HpackDecode_SimpleRequest);

static void BM_HpackDecode_Response(benchmark::State& state) {
    HpackEncoder encoder;
    HpackDecoder decoder;
    bool error = false;

    auto encoded = encoder.encode({
        {":status", "200"},
        {"content-type", "text/html; charset=utf-8"},
        {"content-length", "12345"},
        {"server", "nginx/1.24.0"},
        {"date", "Mon, 01 Jan 2024 00:00:00 GMT"},
        {"cache-control", "public, max-age=3600"}
    }, error);
    if (error) state.SkipWithError("Encode failed");

    for (auto _ : state) {
        error = false;
        auto result = decoder.decode(encoded.data(), encoded.size(), error);
        benchmark::DoNotOptimize(result);
        if (error) state.SkipWithError("Decode failed");
    }
}
BENCHMARK(BM_HpackDecode_Response);

static void BM_HpackEncode_ManyHeaders(benchmark::State& state) {
    HpackEncoder encoder;
    bool error = false;
    std::vector<HpackHeaderField> headers;
    for (int i = 0; i < 15; ++i) {
        headers.push_back({"x-header-" + std::to_string(i),
                           "value-" + std::to_string(i)});
    }

    for (auto _ : state) {
        error = false;
        auto result = encoder.encode(headers, error);
        benchmark::DoNotOptimize(result);
        if (error) state.SkipWithError("Encode failed");
    }
}
BENCHMARK(BM_HpackEncode_ManyHeaders);

static void BM_HpackRoundTrip_10Headers(benchmark::State& state) {
    HpackEncoder encoder;
    HpackDecoder decoder;
    bool error = false;

    std::vector<HpackHeaderField> original;
    for (int i = 0; i < 10; ++i) {
        original.push_back({"x-header-" + std::to_string(i),
                            "value-" + std::to_string(i)});
    }

    for (auto _ : state) {
        error = false;
        auto encoded = encoder.encode(original, error);
        if (error) { state.SkipWithError("Encode"); break; }
        auto decoded = decoder.decode(encoded.data(), encoded.size(), error);
        if (error) { state.SkipWithError("Decode"); break; }
        benchmark::DoNotOptimize(decoded);
    }
}
BENCHMARK(BM_HpackRoundTrip_10Headers);

// ── Frame Parsing Benchmarks ─────────────────────────────────────────

static void BM_FrameParse_Settings(benchmark::State& state) {
    Http2Parser parser;
    parser.sendPreface();

    std::vector<uint8_t> payload;
    auto addSetting = [&](uint16_t id, uint32_t val) {
        payload.push_back(static_cast<uint8_t>(id >> 8));
        payload.push_back(static_cast<uint8_t>(id & 0xFF));
        payload.push_back(static_cast<uint8_t>(val >> 24));
        payload.push_back(static_cast<uint8_t>(val >> 16));
        payload.push_back(static_cast<uint8_t>(val >> 8));
        payload.push_back(static_cast<uint8_t>(val));
    };
    addSetting(0x01, 4096);
    addSetting(0x03, 100);
    addSetting(0x04, 65535);
    addSetting(0x05, 16384);

    auto frame = makeFrame(0x04, 0x00, 0, payload);

    for (auto _ : state) {
        // Reset parser state (simplified — just re-create)
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(frame.data(), frame.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_FrameParse_Settings);

static void BM_FrameParse_Goaway(benchmark::State& state) {
    Http2Parser parser;
    parser.sendPreface();

    auto frame = parser.serializeGoaway(1, Http2Error::NO_ERROR);

    for (auto _ : state) {
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(frame.data(), frame.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_FrameParse_Goaway);

static void BM_FrameParse_RstStream(benchmark::State& state) {
    Http2Parser parser;
    parser.sendPreface();

    auto frame = parser.serializeRstStream(1, Http2Error::CANCEL);

    for (auto _ : state) {
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(frame.data(), frame.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_FrameParse_RstStream);

static void BM_FrameParse_Ping(benchmark::State& state) {
    uint8_t data[8] = {};
    auto frame = Http2Parser::makeFrameHeader(8, 0x06, 0x00, 0);
    frame.insert(frame.end(), data, data + 8);

    for (auto _ : state) {
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(frame.data(), frame.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_FrameParse_Ping);

static void BM_FrameParse_WindowUpdate(benchmark::State& state) {
    std::vector<uint8_t> payload(4, 0);
    payload[2] = 0x10;  // increment = 4096
    auto frame = makeFrame(0x08, 0x00, 0, payload);

    for (auto _ : state) {
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(frame.data(), frame.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_FrameParse_WindowUpdate);

static void BM_FrameParse_Priority(benchmark::State& state) {
    std::vector<uint8_t> payload(5, 0);
    payload[4] = 32;
    auto frame = makeFrame(0x02, 0x00, 3, payload);

    for (auto _ : state) {
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(frame.data(), frame.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_FrameParse_Priority);

static void BM_FrameParse_Data(benchmark::State& state) {
    std::vector<uint8_t> payload(100, 'A');
    auto frame = makeFrame(0x00, 0x00, 1, payload);

    for (auto _ : state) {
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(frame.data(), frame.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_FrameParse_Data);

static void BM_FrameSerialize_Headers(benchmark::State& state) {
    Http2Parser parser;

    std::vector<HpackHeaderField> headers = {
        {":method", "GET"},
        {":path", "/"},
        {":scheme", "https"}
    };

    for (auto _ : state) {
        auto frame = parser.serializeHeaders(1, headers, false);
        benchmark::DoNotOptimize(frame);
    }
}
BENCHMARK(BM_FrameSerialize_Headers);

// ── Throughput Benchmarks ────────────────────────────────────────────

static void BM_Feed_100DataFrames(benchmark::State& state) {
    // Build 100 DATA frames to feed at once
    std::vector<uint8_t> batch;
    for (int i = 0; i < 100; ++i) {
        std::vector<uint8_t> payload(100, static_cast<uint8_t>(i));
        bool end = (i == 99);
        auto frame = makeFrame(0x00, end ? 0x01 : 0x00, 1, payload);
        batch.insert(batch.end(), frame.begin(), frame.end());
    }

    for (auto _ : state) {
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(batch.data(), batch.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_Feed_100DataFrames);

static void BM_Feed_MixedFrames(benchmark::State& state) {
    // Mix of SETTINGS, PING, WINDOW_UPDATE, PRIORITY, HEADERS, DATA
    std::vector<uint8_t> batch;

    // SETTINGS
    std::vector<uint8_t> s_payload(24, 0);
    batch.push_back(0x00); batch.push_back(0x00); batch.push_back(24);
    batch.push_back(0x04); batch.push_back(0x00);
    batch.push_back(0x00); batch.push_back(0x00); batch.push_back(0x00); batch.push_back(0x00);
    batch.insert(batch.end(), s_payload.begin(), s_payload.end());

    // PING
    uint8_t ping_data[8] = {};
    auto ping = Http2Parser::makeFrameHeader(8, 0x06, 0x00, 0);
    ping.insert(ping.end(), ping_data, ping_data + 8);
    batch.insert(batch.end(), ping.begin(), ping.end());

    // WINDOW_UPDATE
    std::vector<uint8_t> wu_payload(4, 0);
    wu_payload[2] = 0x10;
    auto wu = makeFrame(0x08, 0x00, 0, wu_payload);
    batch.insert(batch.end(), wu.begin(), wu.end());

    // PRIORITY
    std::vector<uint8_t> prio_payload(5, 0);
    prio_payload[4] = 32;
    auto prio = makeFrame(0x02, 0x00, 3, prio_payload);
    batch.insert(batch.end(), prio.begin(), prio.end());

    for (auto _ : state) {
        Http2Parser p;
        p.sendPreface();
        auto consumed = p.feed(batch.data(), batch.size());
        benchmark::DoNotOptimize(consumed);
    }
}
BENCHMARK(BM_Feed_MixedFrames);

// BENCHMARK_MAIN removed - defined in bench_pntp_core.cpp
