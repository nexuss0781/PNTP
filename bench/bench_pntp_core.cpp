#include "pntp/pntp_core.h"
#include <benchmark/benchmark.h>

static void BM_GetRDTSC(benchmark::State& state) {
    for (auto _ : state) {
        auto tsc = get_rdtsc();
        benchmark::DoNotOptimize(tsc);
    }
}
BENCHMARK(BM_GetRDTSC);

static void BM_GenerateStealthId(benchmark::State& state) {
    char sid[16];
    for (auto _ : state) {
        generate_stealth_id(sid);
        benchmark::DoNotOptimize(sid);
    }
}
BENCHMARK(BM_GenerateStealthId);

BENCHMARK_MAIN();
