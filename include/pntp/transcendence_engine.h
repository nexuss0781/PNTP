#ifndef TRANSCENDENCE_ENGINE_H
#define TRANSCENDENCE_ENGINE_H

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "pntp/data_extractor.h"
#include "pntp/stealth_ensemble.h"
#include "pntp/http2_parser.h"
#include "pntp/tls_interceptor.h"

class TCPEngine;
struct TCPConnection;
class Http2Parser;
class CookieJar;
class UrlManipulator;
class DataExtractor;
struct ParsedURL;


// ── Buffer / header types ────────────────────────────────────────────

using Buffer = std::vector<uint8_t>;

// Ordered header collection preserving insertion order and duplicates
// (RFC 7230 field order matters for some servers and for tests).
struct Headers {
    std::vector<std::pair<std::string, std::string>> items;

    void set(const std::string& name, const std::string& value);
    void add(const std::string& name, const std::string& value);
    bool has(const std::string& name) const;
    std::string get(const std::string& name) const;
    std::vector<std::string> getAll(const std::string& name) const;
    bool remove(const std::string& name);
    std::map<std::string, std::string> toMap() const;
};

// ── Fetch configuration ──────────────────────────────────────────────

enum class CachePolicy : uint8_t {
    NONE = 0,
    REUSE_IF_FRESH
};

struct StealthProfile {
    std::string name = "default";
    std::vector<std::string> layers;
};

struct URLRewriteRule {
    std::string match;
    std::string replace;
};

struct FetchTiming {
    uint64_t dns_us = 0;
    uint64_t connect_us = 0;
    uint64_t tls_us = 0;
    uint64_t ttfb_us = 0;
    uint64_t total_us = 0;
    uint64_t tsc_cycles = 0;
};

struct FetchConfig {
    Headers headers;
    std::string method = "GET";
    std::string body;
    uint32_t timeout_ms = 10000;
    bool follow_redirects = true;
    uint32_t max_redirects = 5;
    CachePolicy cache_policy = CachePolicy::NONE;
    StealthProfile stealth_profile;
};

// ── Fetch result ─────────────────────────────────────────────────────

struct FetchResult {
    Buffer response_body;
    Headers response_headers;
    uint16_t status_code = 0;
    std::string protocol;   // "HTTP/1.1" or "HTTP/2"
    FetchTiming timing;
    uint32_t packet_count = 0;
    uint32_t retransmit_count = 0;
    bool ok = false;
    std::string error;
    // Filled by transcendWithPlan(), one entry per extraction plan.
    std::vector<ExtractionResult> extractions;

    std::string bodyString() const {
        return std::string(response_body.begin(), response_body.end());
    }
};

// ── Transcendence plan ───────────────────────────────────────────────

struct TranscendencePlan {
    std::vector<ExtractionPlan> extraction_plans;
    std::vector<StealthProfile> stealth_profiles;
    std::vector<URLRewriteRule> rewrite_rules;
};

// ── Backend Transcendence ────────────────────────────────────────────
//
// Native HTTP client built from the raw socket up: TCPEngine (raw TCP)
// -> TLSInterceptor (TLS 1.3) -> Http1Parser / Http2Parser. No libcurl,
// no system resolver, no regular expressions.
class BackendTranscendence {
public:
    BackendTranscendence();
    ~BackendTranscendence();

    BackendTranscendence(const BackendTranscendence&) = delete;
    BackendTranscendence& operator=(const BackendTranscendence&) = delete;

    // ── Fetch ───────────────────────────────────────────────────────
    // Follows redirects (config.follow_redirects / config.max_redirects),
    // carrying cookies through the shared CookieJar.
    FetchResult transcendFetch(const std::string& url,
                               const FetchConfig& config = FetchConfig{});

    // HTTP/2 multiplexed fetch: URLs sharing a host are sent over one
    // TLS session as concurrent streams. Redirects are not followed
    // here (use transcendFetch). Non-https URLs and hosts that do not
    // negotiate h2 fall back to sequential transcendFetch.
    std::vector<FetchResult> parallelFetch(
        const std::vector<std::string>& urls,
        const FetchConfig& config = FetchConfig{});

    // ── Session persistence ─────────────────────────────────────────
    // A Session owns one raw TCP connection plus (for https) one TLS
    // connection and one HTTP/2 connection state. Sessions created
    // here stay registered until destroySession() (or destruction of
    // the BackendTranscendence).
    struct Session {
        std::string host;
        uint16_t port = 0;
        bool tls = false;
        std::string alpn;              // negotiated protocol ("" if none)
        TCPConnection* tcp = nullptr;
        TLSInterceptor::TLSConnection* tls_conn = nullptr;
        Http2Parser* h2 = nullptr;
        bool h2_started = false;
        std::map<std::string, std::string> cookies;
        uint64_t created_at = 0;

        // In-flight HTTP/2 stream state, keyed by stream id. Written by
        // the Http2Parser callbacks installed in startH2().
        struct H2StreamState {
            uint16_t status = 0;
            Headers headers;
            Buffer body;
            bool headers_seen = false;
            bool ended = false;
            bool failed = false;
            bool has_first_byte = false;
            std::chrono::steady_clock::time_point first_byte_at;
        };
        std::map<uint32_t, H2StreamState> h2_streams;
        std::chrono::steady_clock::time_point h2_t0;
    };

    Session* createSession(const std::string& host);
    void destroySession(Session* session);

    // ── Plan-driven pipeline ────────────────────────────────────────
    // Applies rewrite_rules to the URL, pushes stealth_profiles into
    // the ensemble, fetches with session reuse, then runs every
    // extraction plan over the response body (results in
    // FetchResult::extractions).
    FetchResult transcendWithPlan(const std::string& url,
                                  const TranscendencePlan& plan);

    // ── Stealth ensemble integration ────────────────────────────────
    void setEnsembleProfile(const StealthProfile& profile);
    StealthProfile getEnsembleProfile() const { return profile_; }

    // ── Auth injection (delegates to the internal UrlManipulator) ───
    void setAuthProvider(const std::string& type,
                         const std::string& credentials);
    void setAuthenticationToken(const std::string& token);

    // ── Request introspection (exposed for preview/testing) ──────────
    // Serializes the exact HTTP/1.1 request bytes (headers, cookies and
    // auth already applied) without touching the network.
    std::vector<uint8_t> buildHttp1Request(const ParsedURL& url,
                                           const FetchConfig& config,
                                           bool keep_alive);
    std::vector<HpackHeaderField> buildHttp2Headers(const ParsedURL& url,
                                                    const FetchConfig& config);
    // Applies an ordered literal replace of every rewrite rule.
    static std::string applyRewriteRules(
        const std::string& url, const std::vector<URLRewriteRule>& rules);

    CookieJar& cookieJar() { return *cookie_jar_; }
    const CookieJar& cookieJar() const { return *cookie_jar_; }

    // Optional external wiring (non-owning). When no engine is supplied
    // the backend lazily creates and initializes one.
    void setTCPEngine(TCPEngine* engine) { engine_ = engine; }
    void setInterface(const std::string& iface) { interface_ = iface; }

private:
    TCPEngine* ensureEngine();
    UrlManipulator& manipulator();

    // Shared request/response plumbing.
    Headers applyHeaderPolicy(const ParsedURL& url, const Headers& in);

    // Opens TCP (+TLS for https) and returns a fully-formed but
    // unregistered session. Timing fields are filled into `sink`.
    std::unique_ptr<Session> dialSession(const ParsedURL& url,
                                         const FetchConfig& config,
                                         FetchResult& sink);

    // One request/response exchange over an established session; does
    // not close the connection. `peer_close` reports that the server
    // asked to close (Connection: close / EOF semantics).
    FetchResult exchange(Session* s, const ParsedURL& url,
                         const FetchConfig& config, bool keep_alive,
                         bool* peer_close);
    FetchResult exchangeHttp1(Session* s, const ParsedURL& url,
                              const FetchConfig& config, bool keep_alive,
                              bool* peer_close);
    FetchResult exchangeHttp2(Session* s, const ParsedURL& url,
                              const FetchConfig& config);

    // HTTP/2 connection setup (preface, SETTINGS, callbacks) — once
    // per session. Returns false when the preface cannot be written.
    bool startH2(Session* s);
    // Reads and feeds frames until every sid is done or `timeout_ms`
    // elapses. Returns true when all streams completed.
    bool pumpH2(Session* s, const std::vector<uint32_t>& sids,
                uint32_t timeout_ms);

    Session* findReusable(const std::string& host, uint16_t port);
    static std::string sessionKey(const std::string& host, uint16_t port);
    void closeSessionResources(Session* s);

    void applyStealth(const StealthProfile& profile);

    FetchResult fetchOnce(const std::string& url, const FetchConfig& config);

    std::map<std::string, std::unique_ptr<Session>> sessions_;

    std::unique_ptr<TCPEngine> owned_engine_;
    TCPEngine* engine_ = nullptr;
    std::string interface_ = "eth0";

    std::unique_ptr<TLSInterceptor> tls_;
    std::unique_ptr<CookieJar> cookie_jar_;
    std::unique_ptr<StealthEnsemble> ensemble_;
    std::unique_ptr<UrlManipulator> manipulator_;
    std::unique_ptr<DataExtractor> extractor_;

    StealthProfile profile_;

    static constexpr size_t MAX_BODY_BYTES = 32u * 1024u * 1024u;
    static constexpr uint32_t STREAM_READ_TIMEOUT_MS = 2000;
};

#endif // TRANSCENDENCE_ENGINE_H
