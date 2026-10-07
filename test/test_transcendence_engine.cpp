#include "pntp/transcendence_engine.h"

#include "pntp/cookie_jar.h"
#include "pntp/url_manipulator.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

using BackendTranscendence = ::BackendTranscendence;
using Buffer = ::Buffer;
using FetchConfig = ::FetchConfig;
using FetchResult = ::FetchResult;
using Headers = ::Headers;
using ParsedURL = ::ParsedURL;
using URLRewriteRule = ::URLRewriteRule;

// ── Headers ─────────────────────────────────────────────────────────

TEST(TranscendenceHeaders, SetOverwritesExisting) {
    Headers h;
    h.set("Host", "a.example");
    h.set("host", "b.example");
    ASSERT_EQ(h.items.size(), 1u);
    EXPECT_EQ(h.get("HOST"), "b.example");
}

TEST(TranscendenceHeaders, AddPreservesDuplicates) {
    Headers h;
    h.add("Set-Cookie", "a=1");
    h.add("Set-Cookie", "b=2");
    ASSERT_EQ(h.items.size(), 2u);
    EXPECT_EQ(h.getAll("set-cookie").size(), 2u);
}

TEST(TranscendenceHeaders, HasAndGetAreCaseInsensitive) {
    Headers h;
    h.set("Content-Type", "text/html");
    EXPECT_TRUE(h.has("content-type"));
    EXPECT_TRUE(h.has("CONTENT-TYPE"));
    EXPECT_EQ(h.get("Content-TYPE"), "text/html");
    EXPECT_FALSE(h.has("Content-Length"));
    EXPECT_EQ(h.get("Missing"), "");
}

TEST(TranscendenceHeaders, RemoveDropsAllMatching) {
    Headers h;
    h.add("X-Forwarded-For", "1.1.1.1");
    h.add("x-forwarded-for", "2.2.2.2");
    EXPECT_TRUE(h.remove("X-FORWARDED-FOR"));
    EXPECT_FALSE(h.has("x-forwarded_for"));
    EXPECT_EQ(h.items.size(), 0u);
    EXPECT_FALSE(h.remove("absent"));
}

TEST(TranscendenceHeaders, ToMapLastWins) {
    Headers h;
    h.add("X-A", "1");
    h.add("X-A", "2");
    h.add("X-B", "3");
    auto m = h.toMap();
    EXPECT_EQ(m.size(), 2u);
    EXPECT_EQ(m["X-A"], "2");
    EXPECT_EQ(m["X-B"], "3");
}

// ── Struct defaults ─────────────────────────────────────────────────

TEST(TranscendenceDefaults, FetchConfig) {
    FetchConfig c;
    EXPECT_EQ(c.method, "GET");
    EXPECT_EQ(c.timeout_ms, 10000u);
    EXPECT_TRUE(c.follow_redirects);
    EXPECT_EQ(c.max_redirects, 5u);
    EXPECT_EQ(c.cache_policy, CachePolicy::NONE);
    EXPECT_TRUE(c.stealth_profile.layers.empty());
}

TEST(TranscendenceDefaults, FetchTiming) {
    ::FetchTiming t;
    EXPECT_EQ(t.dns_us, 0u);
    EXPECT_EQ(t.connect_us, 0u);
    EXPECT_EQ(t.tls_us, 0u);
    EXPECT_EQ(t.ttfb_us, 0u);
    EXPECT_EQ(t.total_us, 0u);
    EXPECT_EQ(t.tsc_cycles, 0u);
}

TEST(TranscendenceDefaults, FetchResult) {
    FetchResult r;
    EXPECT_TRUE(r.response_body.empty());
    EXPECT_TRUE(r.response_headers.items.empty());
    EXPECT_EQ(r.status_code, 0);
    EXPECT_EQ(r.protocol, "");
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.error, "");
    EXPECT_EQ(r.packet_count, 0u);
    EXPECT_EQ(r.retransmit_count, 0u);
    EXPECT_TRUE(r.extractions.empty());
    EXPECT_EQ(r.bodyString(), "");
}

TEST(TranscendenceDefaults, Session) {
    BackendTranscendence::Session s;
    EXPECT_EQ(s.host, "");
    EXPECT_EQ(s.port, 0u);
    EXPECT_FALSE(s.tls);
    EXPECT_EQ(s.alpn, "");
    EXPECT_EQ(s.tcp, nullptr);
    EXPECT_EQ(s.tls_conn, nullptr);
    EXPECT_EQ(s.h2, nullptr);
    EXPECT_FALSE(s.h2_started);
    EXPECT_TRUE(s.cookies.empty());
    EXPECT_EQ(s.created_at, 0u);
    EXPECT_TRUE(s.h2_streams.empty());
}

TEST(TranscendenceDefaults, H2StreamState) {
    BackendTranscendence::Session::H2StreamState st;
    EXPECT_EQ(st.status, 0);
    EXPECT_TRUE(st.headers.items.empty());
    EXPECT_TRUE(st.body.empty());
    EXPECT_FALSE(st.headers_seen);
    EXPECT_FALSE(st.ended);
    EXPECT_FALSE(st.failed);
    EXPECT_FALSE(st.has_first_byte);
}

TEST(TranscendenceDefaults, StealthAndRewrite) {
    ::StealthProfile sp;
    EXPECT_EQ(sp.name, "default");
    EXPECT_TRUE(sp.layers.empty());

    URLRewriteRule r;
    EXPECT_EQ(r.match, "");
    EXPECT_EQ(r.replace, "");

    TranscendencePlan plan;
    EXPECT_TRUE(plan.extraction_plans.empty());
    EXPECT_TRUE(plan.stealth_profiles.empty());
    EXPECT_TRUE(plan.rewrite_rules.empty());
}

// ── HTTP/1.1 request serialization ──────────────────────────────────

namespace {

std::string firstLine(const Buffer& b) {
    for (size_t i = 0; i + 1 < b.size(); ++i) {
        if (b[i] == '\r' && b[i + 1] == '\n') {
            return std::string(b.begin(), b.begin() + static_cast<std::ptrdiff_t>(i));
        }
    }
    return std::string(b.begin(), b.end());
}

std::string asString(const Buffer& b) {
    return std::string(b.begin(), b.end());
}

bool hasHeader(const Buffer& b, const std::string& name,
               const std::string& value) {
    std::string needle = name + ": " + value;
    return asString(b).find(needle) != std::string::npos;
}

} // namespace

TEST(TranscendenceSerialize, GetRequestLine) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com/path/to?q=1");
    ASSERT_TRUE(u.valid);
    auto req = bt.buildHttp1Request(u, FetchConfig{}, true);
    EXPECT_EQ(firstLine(req), "GET /path/to?q=1 HTTP/1.1");
    EXPECT_EQ(asString(req).back(), '\n');
}

TEST(TranscendenceSerialize, DefaultHeaders) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com/");
    auto req = bt.buildHttp1Request(u, FetchConfig{}, true);
    std::string s = asString(req);
    EXPECT_EQ(s.find("Host: example.com\r\n") != std::string::npos, true);
    EXPECT_EQ(s.find("User-Agent: PNTP-Transcendent-Browser/4.0\r\n") !=
                  std::string::npos,
              true);
    EXPECT_EQ(s.find("Accept: */*\r\n") != std::string::npos, true);
    EXPECT_EQ(s.find("Connection: keep-alive\r\n") != std::string::npos, true);
}

TEST(TranscendenceSerialize, ConnectionCloseWhenNotKeepingAlive) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com/");
    auto req = bt.buildHttp1Request(u, FetchConfig{}, false);
    EXPECT_EQ(asString(req).find("Connection: close\r\n") != std::string::npos,
              true);
}

TEST(TranscendenceSerialize, FullUrlPathDefaultSlash) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com");
    ASSERT_TRUE(u.valid);
    EXPECT_EQ(u.path, "");
    auto req = bt.buildHttp1Request(u, FetchConfig{}, true);
    EXPECT_EQ(firstLine(req), "GET / HTTP/1.1");
}

TEST(TranscendenceSerialize, CustomMethodAndBody) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com/api");
    FetchConfig c;
    c.method = "POST";
    c.body = "hello";
    auto req = bt.buildHttp1Request(u, c, true);
    EXPECT_EQ(firstLine(req), "POST /api HTTP/1.1");
    EXPECT_TRUE(hasHeader(req, "Content-Length", "5"));
    EXPECT_EQ(asString(req).find("hello") != std::string::npos, true);
}

TEST(TranscendenceSerialize, CustomHeadersKeepOrder) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com/");
    FetchConfig c;
    c.headers.add("X-Custom-A", "1");
    c.headers.add("X-Custom-B", "2");
    auto req = bt.buildHttp1Request(u, c, true);
    std::string s = asString(req);
    EXPECT_EQ(s.find("X-Custom-A: 1") != std::string::npos, true);
    EXPECT_EQ(s.find("X-Custom-B: 2") != std::string::npos, true);
    EXPECT_EQ(s.find("X-Custom-A") < s.find("X-Custom-B"), true);
}

TEST(TranscendenceSerialize, AuthProviderInjectAuthHeader) {
    BackendTranscendence bt;
    bt.setAuthProvider("BASIC", "user:pass");
    ParsedURL u = ParsedURL::parse("https://example.com/");
    auto req = bt.buildHttp1Request(u, FetchConfig{}, true);
    EXPECT_TRUE(hasHeader(req, "Authorization", "Basic dXNlcjpwYXNz"));
}

TEST(TranscendenceSerialize, BearerTokenInjected) {
    BackendTranscendence bt;
    bt.setAuthenticationToken("s3cr3t");
    ParsedURL u = ParsedURL::parse("https://example.com/");
    auto req = bt.buildHttp1Request(u, FetchConfig{}, true);
    EXPECT_TRUE(hasHeader(req, "Authorization", "Bearer s3cr3t"));
}

TEST(TranscendenceSerialize, JarCookiesInjected) {
    BackendTranscendence bt;
    bt.cookieJar().setFromHeaders("https://example.com/",
                                  {"sid=abc123; Path=/", "theme=dark; Path=/"});
    ParsedURL u = ParsedURL::parse("https://example.com/");
    auto req = bt.buildHttp1Request(u, FetchConfig{}, true);
    EXPECT_TRUE(hasHeader(req, "Cookie", "sid=abc123; theme=dark"));
}

TEST(TranscendenceSerialize, Https2HeadersNoHostHack) {
    BackendTranscendence bt;
    ParsedURL u = ParsedURL::parse("https://example.com/x?y=2");
    auto hh = bt.buildHttp2Headers(u, FetchConfig{});
    bool saw_method = false, saw_path = false, saw_scheme = false,
         saw_authority = false;
    for (const auto& f : hh) {
        if (f.name == ":method") saw_method = true;
        if (f.name == ":path" && f.value == "/x?y=2") saw_path = true;
        if (f.name == ":scheme" && f.value == "https") saw_scheme = true;
        if (f.name == ":authority" && f.value == "example.com")
            saw_authority = true;
        EXPECT_NE(f.name, ":host") << "illegal pseudo-header must not appear";
    }
    EXPECT_TRUE(saw_method);
    EXPECT_TRUE(saw_path);
    EXPECT_TRUE(saw_scheme);
    EXPECT_TRUE(saw_authority);
}

// ── Rewrite rules ───────────────────────────────────────────────────

TEST(TranscendenceRewrite, LiteralReplaceAllOccurrences) {
    std::vector<URLRewriteRule> rules = {{"/download/", "/mirror/"}};
    EXPECT_EQ(BackendTranscendence::applyRewriteRules(
                  "https://a.example/download/v1/file.bin", rules),
              "https://a.example/mirror/v1/file.bin");
}

TEST(TranscendenceRewrite, OrderedRulesChain) {
    std::vector<URLRewriteRule> rules = {
        {"example.com", "cdn.example.net"},
        {"http://", "https://"},
    };
    EXPECT_EQ(BackendTranscendence::applyRewriteRules(
                  "http://example.com/x", rules),
              "https://cdn.example.net/x");
}

TEST(TranscendenceRewrite, EmptyMatchSkippedAndNoRulesIdentity) {
    std::vector<URLRewriteRule> bad = {{"", "https://x"}};
    std::string url = "https://example.com/";
    EXPECT_EQ(BackendTranscendence::applyRewriteRules(url, {}), url);
    EXPECT_EQ(BackendTranscendence::applyRewriteRules(url, bad), url);
}

// ── Redirect resolution ─────────────────────────────────────────────

TEST(TranscendenceRedirect, AbsoluteAndRelative) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("https://a.example/x/y",
                                              "https://b.example/z"),
              "https://b.example/z");
    EXPECT_EQ(UrlManipulator::resolveRedirect("https://a.example/x/y",
                                              "/new/page"),
              "https://a.example/new/page");
    EXPECT_EQ(UrlManipulator::resolveRedirect("https://a.example/x/y?q=1",
                                              "sibling"),
              "https://a.example/x/sibling");
}

TEST(TranscendenceRedirect, ProtocolRelative) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("https://a.example/",
                                              "//b.example/z"),
              "https://b.example/z");
}

// ── Cookie jar round-trip ───────────────────────────────────────────

TEST(TranscendenceCookies, RoundTripAndScoping) {
    CookieJar jar;
    size_t n = jar.setFromHeaders(
        "https://example.com/account",
        {"session=abc; Path=/", "prefs=dark; Path=/account",
         "tracker=1; Domain=example.com; Path=/"});
    EXPECT_EQ(n, 3u);

    EXPECT_EQ(jar.cookieHeaderFor("https://example.com/account/detail"),
              "prefs=dark; session=abc; tracker=1");
    EXPECT_EQ(jar.cookieHeaderFor("https://example.com/other"),
              "session=abc; tracker=1");
    EXPECT_EQ(jar.cookieHeaderFor("https://sub.example.com/"), "tracker=1");
}

TEST(TranscendenceCookies, SecureCookieNotSentOverHttp) {
    CookieJar jar;
    jar.setFromHeaders("https://example.com/",
                       {"token=xyz; Path=/; Secure"});
    EXPECT_EQ(jar.cookieHeaderFor("https://example.com/"), "token=xyz");
    EXPECT_EQ(jar.cookieHeaderFor("http://example.com/"), "");
}

TEST(TranscendenceCookies, ExpiredCookieExcluded) {
    CookieJar jar;
    jar.setFromHeaders("https://example.com/",
                       {"gone=1; Path=/; Max-Age=0"});
    EXPECT_EQ(jar.cookieHeaderFor("https://example.com/"), "");
    EXPECT_EQ(jar.size(), 1u);  // stored but expired
}

// ── Plan-driven extraction (offline harness) ────────────────────────

TEST(TranscendencePlan, ExtractionPlanRunsOnBody) {
    DataExtractor extractor;
    ::ExtractionPlan ep;
    ep.rules.push_back(
        {::ExtractionRule::CSS_SELECTOR, "h1", "title", "", false});
    ep.rules.push_back(
        {::ExtractionRule::CSS_SELECTOR, ".item", "item", "", true});

    std::string html =
        "<html><body><h1>Hello</h1><span class=\"item\">A</span>"
        "<span class=\"item\">B</span></body></html>";
    auto res = extractor.extract(ep, html, "text/html");
    EXPECT_TRUE(res.success);
    EXPECT_EQ(res.fields["title"].size(), 1u);
    EXPECT_EQ(res.fields["title"][0], "Hello");
    EXPECT_EQ(res.fields["item"].size(), 2u);
}
TEST(TranscendenceLive, UdacityPageTitleComparison_Gated) {
    const char* env_net = getenv("PNTP_ENABLE_NETWORK_TESTS");
    if (!env_net || env_net[0] == '0') {
        GTEST_SKIP() << "PNTP_ENABLE_NETWORK_TESTS not set";
    }
    BackendTranscendence bt;
    FetchConfig cfg;
    cfg.timeout_ms = 5000;
    cfg.max_redirects = 10;
    cfg.cache_policy = CachePolicy::NONE;
    auto res = bt.transcendFetch("https://www.udacity.com/", cfg);
    if (!res.ok) {
        GTEST_SKIP() << "Live fetch failed: " << res.error;
    }
    EXPECT_EQ(res.protocol.find("HTTP"), 0u);
    EXPECT_GT(res.status_code, 0);
    EXPECT_TRUE(res.response_body.size() > 0);
    ::ExtractionPlan ep;
    ep.rules.push_back({::ExtractionRule::CSS_SELECTOR, "title", "title", "", false});
    DataExtractor ex;
    auto er = ex.extract(ep, std::string(res.response_body.begin(), res.response_body.end()), "text/html");
    if (er.success && !er.fields["title"].empty()) {
        std::string title = er.fields["title"][0];
        while (!title.empty() && (title.back() == '\n' || title.back() == '\r' || title.back() == ' ' || title.back() == '\t')) title.pop_back();
        EXPECT_FALSE(title.empty());
    }
}
