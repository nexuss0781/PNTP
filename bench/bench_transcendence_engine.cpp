#include "pntp/transcendence_engine.h"
#include "pntp/cookie_jar.h"
#include "pntp/url_manipulator.h"

#include <benchmark/benchmark.h>

#include <string>
#include <vector>

using ::BackendTranscendence;
using ::CookieJar;
using ::Headers;
using ::ParsedURL;
using ::UrlManipulator;

// ── HTTP/1.1 request serialization ──────────────────────────────────

static void BM_BuildHttp1Request(benchmark::State& state) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com/path/to?q=1");
    FetchConfig cfg;
    cfg.headers.set("Accept-Encoding", "gzip, deflate");
    for (auto _ : state) {
        auto req = bt.buildHttp1Request(u, cfg, true);
        benchmark::DoNotOptimize(req.size());
    }
}
BENCHMARK(BM_BuildHttp1Request);

static void BM_BuildHttp2Headers(benchmark::State& state) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com/path/to?q=1");
    FetchConfig cfg;
    cfg.headers.set("Accept-Encoding", "gzip, deflate");
    for (auto _ : state) {
        auto hh = bt.buildHttp2Headers(u, cfg);
        benchmark::DoNotOptimize(hh.size());
    }
}
BENCHMARK(BM_BuildHttp2Headers);

// ── Headers container ────────────────────────────────────────────────

static void BM_HeadersInsertLookup(benchmark::State& state) {
    for (auto _ : state) {
        Headers h;
        h.set("Host", "example.com");
        h.set("User-Agent", "PNTP-Transcendent-Browser/4.0");
        benchmark::DoNotOptimize(h.get("HOST"));
        benchmark::DoNotOptimize(h.has("user-agent"));
    }
}
BENCHMARK(BM_HeadersInsertLookup);

// ── Rewrite rules ────────────────────────────────────────────────────

static void BM_ApplyRewriteRules(benchmark::State& state) {
    std::vector<URLRewriteRule> rules = {
        {"example.com", "cdn.example.net"},
        {"http://", "https://"},
        {"/download/", "/mirror/"},
    };
    std::string url = "http://example.com/download/v1/file.bin";
    for (auto _ : state) {
        auto out = BackendTranscendence::applyRewriteRules(url, rules);
        benchmark::DoNotOptimize(out.size());
    }
}
BENCHMARK(BM_ApplyRewriteRules);

// ── Redirect resolution ──────────────────────────────────────────────

static void BM_ResolveRedirect(benchmark::State& state) {
    for (auto _ : state) {
        auto out = UrlManipulator::resolveRedirect(
            "https://a.example/x/y?q=1", "/new/page");
        benchmark::DoNotOptimize(out.size());
    }
}
BENCHMARK(BM_ResolveRedirect);

// ── Cookie jar ───────────────────────────────────────────────────────

static void BM_CookieJarRoundTrip(benchmark::State& state) {
    CookieJar jar;
    jar.setFromHeaders("https://example.com/account", {"session=abc; Path=/"});
    for (auto _ : state) {
        benchmark::DoNotOptimize(
            jar.cookieHeaderFor("https://example.com/account/detail"));
    }
}
BENCHMARK(BM_CookieJarRoundTrip);
// ── parallelFetch vs sequential ───────────────────────────────────────

static void BM_ParallelVsSequential(benchmark::State& state) {
    BackendTranscendence bt;
    FetchConfig cfg;
    cfg.cache_policy = CachePolicy::NONE;
    // We cannot make real network calls here; the benchmark measures
    // API dispatch/structure cost when no multiplex is possible.
    // Using https on different hosts triggers per-request fallback path.
    std::vector<std::string> urls;
    const int n = 4;
    for (int i = 0; i < n; ++i) {
        urls.push_back("https://example" + std::to_string(i) + ".com/test");
    }
    for (auto _ : state) {
        auto res = bt.parallelFetch(urls, cfg);
        benchmark::DoNotOptimize(res.size());
    }
}
BENCHMARK(BM_ParallelVsSequential);
