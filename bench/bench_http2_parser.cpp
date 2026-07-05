#include "pntp/http2_parser.h"
#include <benchmark/benchmark.h>

static void BM_Http2ParseSingleFrame(benchmark::State& state) {
    Http2Parser parser;
    Http2Frame frame;
    frame.length = 4;
    frame.type = 1;
    frame.flags = 0x04;
    frame.stream_id = 1;
    frame.payload = {0x00, 0x01, 0x02, 0x03};
    auto wire = parser.serializeFrames({frame});

    for (auto _ : state) {
        auto parsed = parser.parseData(wire);
        benchmark::DoNotOptimize(parsed);
    }
}
BENCHMARK(BM_Http2ParseSingleFrame);

static void BM_Http2SerializeFrame(benchmark::State& state) {
    Http2Parser parser;
    Http2Frame frame;
    frame.length = 256;
    frame.type = 0;
    frame.flags = 1;
    frame.stream_id = 5;
    frame.payload.resize(256);

    for (auto _ : state) {
        auto wire = parser.serializeFrames({frame});
        benchmark::DoNotOptimize(wire);
    }
}
BENCHMARK(BM_Http2SerializeFrame);

BENCHMARK_MAIN();
