#include "pntp/transcendence_engine.h"

#include "pntp/byte_stream.h"
#include "pntp/cookie_jar.h"
#include "pntp/dns_resolver.h"
#include "pntp/http1_parser.h"
#include "pntp/http2_parser.h"
#include "pntp/pntp_core.h"
#include "pntp/raw_socket_handler.h"
#include "pntp/tcp_engine.h"
#include "pntp/tls_interceptor.h"
#include "pntp/url_manipulator.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>

// ── Helpers ───────────────────────────────────────────────────────────

namespace {

using Clock = std::chrono::steady_clock;

std::string toLower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

uint64_t usSince(Clock::time_point t0) {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(
            Clock::now() - t0).count());
}

uint64_t usBetween(Clock::time_point a, Clock::time_point b) {
    if (b <= a) return 0;
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(b - a).count());
}

uint16_t parseStatusValue(const std::string& v) {
    unsigned long n = std::strtoul(v.c_str(), nullptr, 10);
    if (n > 999) return 0;
    return static_cast<uint16_t>(n);
}

uint64_t nowEpochSeconds() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

bool isRedirectStatus(uint16_t s) {
    return s >= 300 && s < 400;
}

Http1Method http1MethodFromString(const std::string& m) {
    std::string s = toLower(m);
    if (s == "get") return H1_GET;
    if (s == "post") return H1_POST;
    if (s == "put") return H1_PUT;
    if (s == "delete") return H1_DELETE;
    if (s == "head") return H1_HEAD;
    if (s == "options") return H1_OPTIONS;
    if (s == "patch") return H1_PATCH;
    if (s == "connect") return H1_CONNECT;
    if (s == "trace") return H1_TRACE;
    return H1_UNKNOWN_METHOD;
}

} // namespace

void Headers::set(const std::string& name, const std::string& value) {
    remove(name);
    add(name, value);
}

void Headers::add(const std::string& name, const std::string& value) {
    items.emplace_back(name, value);
}

bool Headers::has(const std::string& name) const {
    std::string n = toLower(name);
    for (const auto& [k, v] : items) {
        (void)v;
        if (toLower(k) == n) return true;
    }
    return false;
}

std::string Headers::get(const std::string& name) const {
    std::string n = toLower(name);
    for (const auto& [k, v] : items) {
        if (toLower(k) == n) return v;
    }
    return {};
}

std::vector<std::string> Headers::getAll(const std::string& name) const {
    std::vector<std::string> out;
    std::string n = toLower(name);
    for (const auto& [k, v] : items) {
        if (toLower(k) == n) out.push_back(v);
    }
    return out;
}

bool Headers::remove(const std::string& name) {
    std::string n = toLower(name);
    bool removed = false;
    for (size_t i = 0; i < items.size();) {
        if (toLower(items[i].first) == n) {
            items.erase(items.begin() + static_cast<std::ptrdiff_t>(i));
            removed = true;
        } else {
            ++i;
        }
    }
    return removed;
}

std::map<std::string, std::string> Headers::toMap() const {
    std::map<std::string, std::string> m;
    for (const auto& [k, v] : items) {
        m[k] = v;
    }
    return m;
}

// ── BackendTranscendence ──────────────────────────────────────────────

BackendTranscendence::BackendTranscendence() {
    tls_ = std::make_unique<TLSInterceptor>();
    cookie_jar_ = std::make_unique<CookieJar>();
    ensemble_ = std::make_unique<StealthEnsemble>();
    manipulator_ = std::make_unique<UrlManipulator>();
    extractor_ = std::make_unique<DataExtractor>();
}

BackendTranscendence::~BackendTranscendence() {
    for (auto& kv : sessions_) {
        closeSessionResources(kv.second.get());
    }
    sessions_.clear();
}

TCPEngine* BackendTranscendence::ensureEngine() {
    if (engine_) return engine_;
    owned_engine_ = std::make_unique<TCPEngine>();
    if (!owned_engine_->initialize(interface_)) {
        owned_engine_.reset();
        return nullptr;
    }
    engine_ = owned_engine_.get();
    return engine_;
}

UrlManipulator& BackendTranscendence::manipulator() {
    return *manipulator_;
}

void BackendTranscendence::setAuthProvider(const std::string& type,
                                           const std::string& credentials) {
    UrlManipulator::AuthProvider p;
    p.type = type;
    p.credentials = credentials;
    manipulator_->setAuthProvider(p);
}

void BackendTranscendence::setAuthenticationToken(const std::string& token) {
    manipulator_->setAuthenticationToken(token);
}

// ── Request building ──────────────────────────────────────────────────

Headers BackendTranscendence::applyHeaderPolicy(const ParsedURL& url,
                                                const Headers& in) {
    // Feed the caller's headers through the UrlManipulator, which
    // applies the configured auth provider / bearer token. Original
    // insertion order is preserved; manipulator additions are appended.
    std::map<std::string, std::string> base;
    for (const auto& [k, v] : in.items) {
        base[k] = v;
    }
    auto modified = manipulator_->modifyRequestHeaders(url.serialize(), base);

    Headers out;
    for (const auto& [k, v] : in.items) {
        auto it = modified.find(k);
        if (it != modified.end()) {
            out.add(k, it->second);
            modified.erase(it);
        } else {
            out.add(k, v);
        }
    }
    for (const auto& [k, v] : modified) {
        out.add(k, v);
    }
    return out;
}

std::vector<uint8_t> BackendTranscendence::buildHttp1Request(
    const ParsedURL& url, const FetchConfig& config, bool keep_alive) {
    Http1Request req;
    req.method = http1MethodFromString(config.method);
    req.method_str = config.method.empty() ? std::string("GET") : config.method;
    req.path = url.path.empty() ? std::string("/") : url.path;
    if (!url.query.empty()) {
        req.path += "?" + url.query;
    }
    req.version = H1_VER_1_1;

    Headers h = applyHeaderPolicy(url, config.headers);
    if (!h.has("Host")) h.set("Host", url.host);
    if (!h.has("User-Agent")) h.set("User-Agent", "PNTP-Transcendent-Browser/4.0");
    if (!h.has("Accept")) h.set("Accept", "*/*");
    if (!h.has("Connection")) {
        h.set("Connection", keep_alive ? "keep-alive" : "close");
    }

    std::string cookie_hdr = cookie_jar_->cookieHeaderFor(url.serialize());
    if (!cookie_hdr.empty()) {
        if (h.has("Cookie")) {
            h.set("Cookie", h.get("Cookie") + "; " + cookie_hdr);
        } else {
            h.set("Cookie", cookie_hdr);
        }
    }

    const uint8_t* body = nullptr;
    size_t body_len = 0;
    if (!config.body.empty()) {
        h.set("Content-Length", std::to_string(config.body.size()));
        body = reinterpret_cast<const uint8_t*>(config.body.data());
        body_len = config.body.size();
    }

    std::vector<Http1Header> hh;
    hh.reserve(h.items.size());
    for (const auto& [k, v] : h.items) hh.push_back({k, v});
    return Http1Parser::serializeRequest(req, hh, body, body_len);
}

std::vector<HpackHeaderField> BackendTranscendence::buildHttp2Headers(
    const ParsedURL& url, const FetchConfig& config) {
    std::vector<HpackHeaderField> hh;
    hh.push_back({":method",
                  config.method.empty() ? std::string("GET") : config.method});
    std::string path = url.path.empty() ? std::string("/") : url.path;
    if (!url.query.empty()) path += "?" + url.query;
    hh.push_back({":path", path});
    hh.push_back({":scheme",
                  url.scheme.empty() ? std::string("https") : url.scheme});
    hh.push_back({":authority", url.host});

    Headers h = applyHeaderPolicy(url, config.headers);

    std::string cookie_hdr = cookie_jar_->cookieHeaderFor(url.serialize());
    if (!cookie_hdr.empty()) {
        if (h.has("Cookie")) {
            h.set("Cookie", h.get("Cookie") + "; " + cookie_hdr);
        } else {
            h.set("Cookie", cookie_hdr);
        }
    }
    if (!config.body.empty() && !h.has("Content-Length")) {
        h.set("Content-Length", std::to_string(config.body.size()));
    }

    // HPACK requires lowercase field names (RFC 9113 §8.2.1).
    for (const auto& [k, v] : h.items) {
        hh.push_back({toLower(k), v});
    }
    return hh;
}

// ── Session plumbing ──────────────────────────────────────────────────

std::string BackendTranscendence::sessionKey(const std::string& host,
                                             uint16_t port) {
    return host + ":" + std::to_string(port);
}

void BackendTranscendence::closeSessionResources(Session* s) {
    if (!s) return;
    if (s->tls_conn) {
        tls_->disconnect(s->tls_conn);
        delete s->tls_conn;
        s->tls_conn = nullptr;
    }
    if (s->tcp && engine_) {
        engine_->close(s->tcp);
        s->tcp = nullptr;
    }
    if (s->h2) {
        delete s->h2;
        s->h2 = nullptr;
    }
    s->h2_started = false;
    s->h2_streams.clear();
}

BackendTranscendence::Session*
BackendTranscendence::findReusable(const std::string& host, uint16_t port) {
    auto it = sessions_.find(sessionKey(host, port));
    if (it == sessions_.end()) return nullptr;
    Session* s = it->second.get();
    if (!s->tcp || s->tcp->state != TCPState::ESTABLISHED) {
        closeSessionResources(s);
        sessions_.erase(it);
        return nullptr;
    }
    if (s->tls && (!s->tls_conn || !s->tls_conn->connected)) {
        closeSessionResources(s);
        sessions_.erase(it);
        return nullptr;
    }
    return s;
}

std::unique_ptr<BackendTranscendence::Session>
BackendTranscendence::dialSession(const ParsedURL& url,
                                  const FetchConfig& config,
                                  FetchResult& sink) {
    TCPEngine* eng = ensureEngine();
    if (!eng) {
        sink.error = "TCP engine init failed";
        return nullptr;
    }

    uint16_t port = url.port ? url.port : ParsedURL::defaultPort(url.scheme);
    bool is_https = toLower(url.scheme) == "https";

    auto c0 = Clock::now();
    TCPConnection* tcp = eng->open(url.host, port, config.timeout_ms);
    if (!tcp) {
        sink.error = "TCP connect failed";
        return nullptr;
    }
    sink.timing.connect_us = usSince(c0);

    auto s = std::make_unique<Session>();
    s->host = url.host;
    s->port = port;
    s->tls = is_https;
    s->tcp = tcp;
    s->created_at = nowEpochSeconds();

    if (is_https) {
        std::vector<std::string> alpn = {"h2", "http/1.1"};
        tls_->setALPNProtocols(alpn);
        auto t0 = Clock::now();
        auto conn = tls_->connectOverTCP(eng, tcp, url.host, port,
                                         config.timeout_ms);
        if (!conn) {
            sink.error = "TLS handshake failed";
            eng->close(tcp);
            return nullptr;
        }
        sink.timing.tls_us = usSince(t0);
        s->alpn = conn->alpn;
        s->tls_conn = conn.release();
    }
    return s;
}

BackendTranscendence::Session*
BackendTranscendence::createSession(const std::string& host) {
    std::string h = host;
    uint16_t port = 443;
    std::string scheme = "https";

    if (host.find("://") != std::string::npos) {
        ParsedURL u = ParsedURL::parse(host);
        if (!u.valid || u.host.empty()) return nullptr;
        h = u.host;
        scheme = u.scheme.empty() ? std::string("https") : u.scheme;
        port = u.port ? u.port : ParsedURL::defaultPort(scheme);
    } else {
        auto colon = host.rfind(':');
        if (colon != std::string::npos && colon + 1 < host.size() &&
            host.find_first_not_of("0123456789", colon + 1) ==
                std::string::npos) {
            unsigned long p = std::strtoul(host.c_str() + colon + 1,
                                           nullptr, 10);
            if (p > 0 && p <= 65535) {
                port = static_cast<uint16_t>(p);
                h = host.substr(0, colon);
            }
        }
    }

    if (Session* live = findReusable(h, port)) return live;

    ParsedURL base;
    base.valid = true;
    base.scheme = scheme;
    base.host = h;
    base.port = port;

    FetchResult sink;
    auto s = dialSession(base, FetchConfig{}, sink);
    if (!s) return nullptr;

    auto* raw = s.get();
    sessions_[sessionKey(h, port)] = std::move(s);
    return raw;
}

void BackendTranscendence::destroySession(Session* session) {
    if (!session) return;
    closeSessionResources(session);
    for (auto it = sessions_.begin(); it != sessions_.end(); ++it) {
        if (it->second.get() == session) {
            sessions_.erase(it);
            return;
        }
    }
    delete session;
}

// ── Stealth ensemble ──────────────────────────────────────────────────

void BackendTranscendence::applyStealth(const StealthProfile& profile) {
    if (!ensemble_ || profile.layers.empty()) return;
    (void)ensemble_->initializeEnsemble();
    for (const auto& layer : profile.layers) {
        ensemble_->applyStealthLayer(layer);
    }
}

void BackendTranscendence::setEnsembleProfile(const StealthProfile& profile) {
    profile_ = profile;
    applyStealth(profile);
}

std::string BackendTranscendence::applyRewriteRules(
    const std::string& url, const std::vector<URLRewriteRule>& rules) {
    std::string out = url;
    for (const auto& rule : rules) {
        if (rule.match.empty()) continue;
        size_t pos = 0;
        while ((pos = out.find(rule.match, pos)) != std::string::npos) {
            out.replace(pos, rule.match.size(), rule.replace);
            pos += rule.replace.size();
        }
    }
    return out;
}

// ── HTTP/2 connection setup ───────────────────────────────────────────

bool BackendTranscendence::startH2(Session* s) {
    if (s->h2_started) return true;
    if (!s->tls_conn) return false;
    if (!s->h2) s->h2 = new Http2Parser();
    s->h2->sendPreface();

    Session* sess = s;
    s->h2->setOnHeaders([sess](uint32_t sid,
                               const std::vector<HpackHeaderField>& fields,
                               bool end_stream) {
        auto& st = sess->h2_streams[sid];
        for (const auto& f : fields) {
            if (f.name == ":status") {
                st.status = parseStatusValue(f.value);
                st.headers_seen = true;
            } else if (!f.name.empty() && f.name[0] != ':') {
                st.headers.add(f.name, f.value);
            }
        }
        if (!st.has_first_byte) {
            st.first_byte_at = Clock::now();
            st.has_first_byte = true;
        }
        if (end_stream) st.ended = true;
    });
    s->h2->setOnData([sess](uint32_t sid, const uint8_t* data, size_t len,
                            bool end_stream) {
        auto& st = sess->h2_streams[sid];
        if (!st.has_first_byte) {
            st.first_byte_at = Clock::now();
            st.has_first_byte = true;
        }
        if (st.body.size() + len <= MAX_BODY_BYTES) {
            st.body.insert(st.body.end(), data, data + len);
        } else {
            st.failed = true;
            st.ended = true;
        }
        if (end_stream) st.ended = true;
    });
    s->h2->setOnGoaway(
        [sess](uint32_t, Http2Error, const std::vector<uint8_t>&) {
            for (auto& kv : sess->h2_streams) {
                if (!kv.second.ended) kv.second.failed = true;
            }
        });
    s->h2->setOnStreamReset([sess](uint32_t sid, Http2Error) {
        auto it = sess->h2_streams.find(sid);
        if (it != sess->h2_streams.end()) {
            it->second.failed = true;
            it->second.ended = true;
        }
    });
    s->h2->setOnSettings([sess, this](const std::map<uint16_t, uint32_t>&) {
        if (!sess->tls_conn || !sess->h2) return;
        auto ack = sess->h2->serializeSettingsAck();
        (void)tls_->writeData(sess->tls_conn, ack.data(), ack.size());
    });

    static const char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (!tls_->writeData(s->tls_conn,
                         reinterpret_cast<const uint8_t*>(kPreface),
                         sizeof(kPreface) - 1)) {
        return false;
    }
    std::map<uint16_t, uint32_t> settings;
    settings[3] = 100;    // SETTINGS_MAX_CONCURRENT_STREAMS
    settings[4] = 65535;  // SETTINGS_INITIAL_WINDOW_SIZE
    auto frame = s->h2->serializeSettings(settings);
    if (!tls_->writeData(s->tls_conn, frame.data(), frame.size())) {
        return false;
    }
    s->h2_started = true;
    s->h2_t0 = Clock::now();
    return true;
}

bool BackendTranscendence::pumpH2(Session* s,
                                  const std::vector<uint32_t>& sids,
                                  uint32_t timeout_ms) {
    if (!s || !s->tls_conn || !s->h2) return false;

    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    auto all_done = [&]() {
        for (uint32_t sid : sids) {
            auto it = s->h2_streams.find(sid);
            if (it == s->h2_streams.end()) return false;
            if (!it->second.ended && !it->second.failed) return false;
        }
        return true;
    };

    while (!all_done() && !s->h2->goawayReceived()) {
        if (Clock::now() >= deadline) break;
        uint32_t remaining = STREAM_READ_TIMEOUT_MS;
        auto left_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                           deadline - Clock::now()).count();
        if (left_ms <= 0) break;
        if (static_cast<uint64_t>(left_ms) < remaining) {
            remaining = static_cast<uint32_t>(left_ms);
        }
        if (remaining == 0) remaining = 1;

        auto chunk = tls_->readData(s->tls_conn, remaining);
        if (chunk.empty()) {
            if (!s->tls_conn->connected) break;
            continue;
        }
        s->h2->feed(chunk.data(), chunk.size());
    }
    return all_done();
}

// ── Exchanges ─────────────────────────────────────────────────────────

FetchResult BackendTranscendence::exchange(Session* s, const ParsedURL& url,
                                           const FetchConfig& config,
                                           bool keep_alive,
                                           bool* peer_close) {
    if (peer_close) *peer_close = false;
    if (!s) {
        FetchResult r;
        r.error = "no connection";
        return r;
    }
    if (s->tls_conn && toLower(s->alpn) == "h2") {
        return exchangeHttp2(s, url, config);
    }
    return exchangeHttp1(s, url, config, keep_alive, peer_close);
}

FetchResult BackendTranscendence::exchangeHttp1(Session* s,
                                                const ParsedURL& url,
                                                const FetchConfig& config,
                                                bool keep_alive,
                                                bool* peer_close) {
    FetchResult result;
    result.protocol = "HTTP/1.1";
    if (peer_close) *peer_close = false;
    if (!s || !s->tcp) {
        result.error = "no connection";
        return result;
    }

    auto req = buildHttp1Request(url, config, keep_alive);

    bool written = false;
    if (s->tls_conn) {
        written = tls_->writeData(s->tls_conn, req.data(), req.size());
    } else if (engine_) {
        written = engine_->send(s->tcp, req.data(), req.size());
    }
    if (!written) {
        result.error = "write failed";
        return result;
    }

    Http1Parser parser;
    parser.reset();
    auto ttfb_start = Clock::now();
    bool got_ttfb = false;

    while (!parser.isComplete() && !parser.hasError()) {
        std::vector<uint8_t> chunk;
        if (s->tls_conn) {
            chunk = tls_->readData(s->tls_conn, STREAM_READ_TIMEOUT_MS);
        } else if (engine_) {
            auto r = engine_->recv(s->tcp, STREAM_READ_TIMEOUT_MS);
            if (r.error || r.closed) break;
            chunk = std::move(r.data);
        }
        if (chunk.empty()) break;
        if (!got_ttfb) {
            result.timing.ttfb_us = usSince(ttfb_start);
            got_ttfb = true;
        }
        parser.feed(chunk.data(), chunk.size());
        if (parser.getBody().size() > MAX_BODY_BYTES) {
            result.error = "response too large";
            return result;
        }
    }
    if (!got_ttfb) {
        result.timing.ttfb_us = usSince(ttfb_start);
    }

    result.status_code = parser.getResponse().status_code;
    for (const auto& h : parser.getHeaders()) {
        result.response_headers.add(h.name, h.value);
    }
    result.response_body = parser.getBody();

    if (result.status_code == 0 && result.response_body.empty()) {
        result.error = parser.hasError() ? "HTTP parse error" : "no response";
        return result;
    }

    std::vector<std::string> sc = result.response_headers.getAll("Set-Cookie");
    if (!sc.empty()) {
        cookie_jar_->setFromHeaders(url.serialize(), sc);
        s->cookies.clear();
        for (const auto& c : cookie_jar_->cookiesFor(url.serialize())) {
            s->cookies[c.name] = c.value;
        }
    }

    if (peer_close) *peer_close = parser.shouldClose();
    result.ok = (result.status_code >= 200 && result.status_code < 400);
    if (!result.ok && result.error.empty() && parser.hasError()) {
        result.error = "HTTP parse error";
    }
    return result;
}

FetchResult BackendTranscendence::exchangeHttp2(Session* s,
                                                const ParsedURL& url,
                                                const FetchConfig& config) {
    FetchResult result;
    result.protocol = "HTTP/2";
    if (!s || !s->tls_conn) {
        result.error = "no TLS connection";
        return result;
    }
    if (!startH2(s)) {
        result.error = "HTTP/2 setup failed";
        return result;
    }

    uint32_t sid = s->h2->openStream();
    if (sid == 0) {
        result.error = "no HTTP/2 stream available";
        return result;
    }

    auto hh = buildHttp2Headers(url, config);
    bool has_body = !config.body.empty();
    auto t0 = Clock::now();

    auto hdr_frame = s->h2->serializeHeaders(sid, hh, !has_body);
    if (!tls_->writeData(s->tls_conn, hdr_frame.data(), hdr_frame.size())) {
        result.error = "write failed";
        s->h2->closeStream(sid);
        s->h2_streams.erase(sid);
        return result;
    }
    if (has_body) {
        auto body_frame = s->h2->serializeData(
            sid, reinterpret_cast<const uint8_t*>(config.body.data()),
            config.body.size(), true);
        if (!tls_->writeData(s->tls_conn, body_frame.data(),
                             body_frame.size())) {
            result.error = "write failed";
            s->h2->closeStream(sid);
            s->h2_streams.erase(sid);
            return result;
        }
    }

    (void)pumpH2(s, {sid}, config.timeout_ms);

    auto it = s->h2_streams.find(sid);
    if (it != s->h2_streams.end()) {
        auto& st = it->second;
        result.status_code = st.status;
        result.response_headers = std::move(st.headers);
        result.response_body = std::move(st.body);
        if (st.has_first_byte) {
            result.timing.ttfb_us = usBetween(t0, st.first_byte_at);
        }
        if (st.failed && st.status == 0) {
            result.error = "HTTP/2 stream failed";
        } else if (!st.ended && !st.failed) {
            result.error = "timed out waiting for response";
        }
        s->h2->closeStream(sid);
        s->h2_streams.erase(it);
    } else if (result.error.empty()) {
        result.error = "HTTP/2 stream lost";
    }

    std::vector<std::string> sc = result.response_headers.getAll("Set-Cookie");
    if (!sc.empty()) {
        cookie_jar_->setFromHeaders(url.serialize(), sc);
        s->cookies.clear();
        for (const auto& c : cookie_jar_->cookiesFor(url.serialize())) {
            s->cookies[c.name] = c.value;
        }
    }

    result.ok = (result.status_code >= 200 && result.status_code < 400);
    return result;
}

// ── Single fetch ──────────────────────────────────────────────────────

FetchResult BackendTranscendence::fetchOnce(const std::string& url,
                                            const FetchConfig& config) {
    FetchResult result;
    auto t0 = Clock::now();
    uint64_t tsc0 = get_rdtsc_serialized();

    ParsedURL p = ParsedURL::parse(url);
    if (!p.valid || p.host.empty()) {
        result.error = "invalid URL";
        result.timing.total_us = usSince(t0);
        result.timing.tsc_cycles = get_rdtsc_serialized() - tsc0;
        return result;
    }

    uint16_t port = p.port ? p.port : ParsedURL::defaultPort(p.scheme);
    bool is_https = toLower(p.scheme) == "https";

    applyStealth(config.stealth_profile.layers.empty()
                     ? profile_
                     : config.stealth_profile);

    TCPEngine* eng = ensureEngine();
    if (!eng) {
        result.error = "TCP engine init failed";
        result.timing.total_us = usSince(t0);
        result.timing.tsc_cycles = get_rdtsc_serialized() - tsc0;
        return result;
    }

    // Native DNS — timed separately; the resolver caches, so the
    // subsequent TCPEngine::open() reuses this answer.
    auto d0 = Clock::now();
    auto dns = eng->getDNSResolver()->resolve(p.host, pntp::RecordType::A,
                                              5000);
    result.timing.dns_us = usSince(d0);
    if (!dns.success || dns.ipv4_addresses.empty()) {
        result.error = "DNS resolution failed";
        result.timing.total_us = usSince(t0);
        result.timing.tsc_cycles = get_rdtsc_serialized() - tsc0;
        return result;
    }

    // Session reuse (https only).
    Session* live = nullptr;
    if (is_https && config.cache_policy == CachePolicy::REUSE_IF_FRESH) {
        live = findReusable(p.host, port);
    }

    std::unique_ptr<Session> temp;
    Session* s = live;
    bool registered = live != nullptr;

    if (!s) {
        temp = dialSession(p, config, result);
        if (!temp) {
            result.timing.total_us = usSince(t0);
            result.timing.tsc_cycles = get_rdtsc_serialized() - tsc0;
            return result;
        }
        s = temp.get();
        if (is_https && config.cache_policy == CachePolicy::REUSE_IF_FRESH) {
            sessions_[sessionKey(p.host, port)] = std::move(temp);
            s = sessions_[sessionKey(p.host, port)].get();
            registered = true;
        }
    }

    bool keep_alive = registered;
    bool peer_close = false;
    FetchResult r = exchange(s, p, config, keep_alive, &peer_close);

    if (s->tcp) {
        r.packet_count = s->tcp->packets_sent;
        r.retransmit_count = s->tcp->retransmit_count;
    }
    r.timing.dns_us = result.timing.dns_us;
    r.timing.connect_us = result.timing.connect_us;
    r.timing.tls_us = result.timing.tls_us;

    if (registered) {
        if (peer_close || r.error == "write failed") {
            destroySession(s);
        }
    } else if (temp) {
        closeSessionResources(temp.get());
        temp.reset();
    }

    r.timing.total_us = usSince(t0);
    r.timing.tsc_cycles = get_rdtsc_serialized() - tsc0;
    return r;
}

FetchResult BackendTranscendence::transcendFetch(const std::string& url,
                                                 const FetchConfig& config) {
    auto t0 = Clock::now();
    uint64_t tsc0 = get_rdtsc_serialized();

    std::string current = url;
    FetchResult result;
    uint32_t hops = 0;

    while (true) {
        result = fetchOnce(current, config);
        if (!config.follow_redirects) break;
        if (!result.ok) break;
        if (!isRedirectStatus(result.status_code)) break;

        std::string loc = result.response_headers.get("Location");
        if (loc.empty()) break;
        if (++hops > config.max_redirects) {
            result.ok = false;
            result.error = "too many redirects";
            break;
        }
        std::string next = UrlManipulator::resolveRedirect(current, loc);
        if (next.empty() || next == current) {
            result.ok = false;
            result.error = "redirect loop";
            break;
        }
        current = std::move(next);
    }

    result.timing.total_us = usSince(t0);
    result.timing.tsc_cycles = get_rdtsc_serialized() - tsc0;
    return result;
}

// ── Multiplexed fetch ─────────────────────────────────────────────────

std::vector<FetchResult> BackendTranscendence::parallelFetch(
    const std::vector<std::string>& urls, const FetchConfig& config) {
    std::vector<FetchResult> out(urls.size());
    if (urls.empty()) return out;

    struct Item {
        size_t idx;
        std::string url;
        ParsedURL parsed;
    };
    std::map<std::string, std::vector<Item>> groups;

    for (size_t i = 0; i < urls.size(); ++i) {
        ParsedURL p = ParsedURL::parse(urls[i]);
        if (!p.valid || p.host.empty()) {
            out[i].error = "invalid URL";
            continue;
        }
        if (toLower(p.scheme) != "https") {
            // Multiplexing requires TLS; cleartext falls back.
            out[i] = fetchOnce(urls[i], config);
            continue;
        }
        uint16_t port = p.port ? p.port : ParsedURL::defaultPort(p.scheme);
        groups[sessionKey(p.host, port)].push_back(Item{i, urls[i], p});
    }

    for (auto& [key, items] : groups) {
        (void)key;
        ParsedURL& base = items[0].parsed;
        uint16_t port = base.port ? base.port : ParsedURL::defaultPort(base.scheme);

        FetchResult dial;
        std::unique_ptr<Session> temp;
        Session* s = nullptr;
        bool registered = false;

        auto fallback_sequential = [&]() {
            for (auto& it : items) out[it.idx] = fetchOnce(it.url, config);
        };

        // Reuse an existing session only when the caller allows it.
        if (config.cache_policy == CachePolicy::REUSE_IF_FRESH) {
            s = findReusable(base.host, port);
            registered = (s != nullptr);
        }

        if (!s) {
            // Time DNS for the batch (cached afterwards for open()).
            TCPEngine* eng = ensureEngine();
            if (!eng) {
                fallback_sequential();
                continue;
            }
            auto d0 = Clock::now();
            auto dns = eng->getDNSResolver()->resolve(base.host,
                                                      pntp::RecordType::A,
                                                      5000);
            dial.timing.dns_us = usSince(d0);
            if (!dns.success || dns.ipv4_addresses.empty()) {
                fallback_sequential();
                continue;
            }

            temp = dialSession(base, config, dial);
            if (!temp || toLower(temp->alpn) != "h2") {
                if (temp) {
                    closeSessionResources(temp.get());
                    temp.reset();
                }
                fallback_sequential();
                continue;
            }
            s = temp.get();
            if (config.cache_policy == CachePolicy::REUSE_IF_FRESH) {
                sessions_[key] = std::move(temp);
                s = sessions_[key].get();
                registered = true;
            }
        } else if (toLower(s->alpn) != "h2") {
            fallback_sequential();
            continue;
        }

        if (!startH2(s)) {
            if (registered) destroySession(s);
            else if (temp) {
                closeSessionResources(temp.get());
                temp.reset();
            }
            fallback_sequential();
            continue;
        }

        auto batch_t0 = Clock::now();
        uint64_t batch_tsc0 = get_rdtsc_serialized();

        std::vector<uint32_t> sids;
        std::map<uint32_t, size_t> sid_to_idx;
        std::map<uint32_t, Clock::time_point> stream_t0;

        for (auto& it : items) {
            uint32_t sid = s->h2->openStream();
            if (sid == 0) {
                out[it.idx].error = "no HTTP/2 stream available";
                continue;
            }
            auto hh = buildHttp2Headers(it.parsed, config);
            bool has_body = !config.body.empty();
            auto w0 = Clock::now();

            auto frame = s->h2->serializeHeaders(sid, hh, !has_body);
            bool ok = tls_->writeData(s->tls_conn, frame.data(), frame.size());
            if (ok && has_body) {
                auto bf = s->h2->serializeData(
                    sid, reinterpret_cast<const uint8_t*>(config.body.data()),
                    config.body.size(), true);
                ok = tls_->writeData(s->tls_conn, bf.data(), bf.size());
            }
            if (!ok) {
                out[it.idx].error = "write failed";
                s->h2->closeStream(sid);
                continue;
            }
            sids.push_back(sid);
            sid_to_idx[sid] = it.idx;
            stream_t0[sid] = w0;
        }

        if (!sids.empty()) {
            (void)pumpH2(s, sids, config.timeout_ms);
        }

        for (uint32_t sid : sids) {
            size_t idx = sid_to_idx[sid];
            FetchResult& r = out[idx];
            r.protocol = "HTTP/2";
            auto st_it = s->h2_streams.find(sid);
            if (st_it != s->h2_streams.end()) {
                auto& st = st_it->second;
                r.status_code = st.status;
                r.response_headers = std::move(st.headers);
                r.response_body = std::move(st.body);
                if (st.has_first_byte) {
                    r.timing.ttfb_us = usBetween(stream_t0[sid],
                                                 st.first_byte_at);
                }
                if (st.failed && st.status == 0) {
                    r.error = "HTTP/2 stream failed";
                } else if (!st.ended && !st.failed) {
                    r.error = "timed out waiting for response";
                }
                s->h2->closeStream(sid);
                s->h2_streams.erase(st_it);
            } else if (r.error.empty()) {
                r.error = "HTTP/2 stream lost";
            }

            std::vector<std::string> sc =
                r.response_headers.getAll("Set-Cookie");
            if (!sc.empty()) cookie_jar_->setFromHeaders(urls[idx], sc);

            r.ok = (r.status_code >= 200 && r.status_code < 400);
            r.timing.dns_us = dial.timing.dns_us;
            r.timing.connect_us = dial.timing.connect_us;
            r.timing.tls_us = dial.timing.tls_us;
            r.timing.total_us = usSince(batch_t0);
            r.timing.tsc_cycles = get_rdtsc_serialized() - batch_tsc0;
            if (s->tcp) {
                r.packet_count = s->tcp->packets_sent;
                r.retransmit_count = s->tcp->retransmit_count;
            }
        }

        if (!registered && temp) {
            closeSessionResources(temp.get());
            temp.reset();
        }
    }

    return out;
}

// ── Plan-driven pipeline ──────────────────────────────────────────────

FetchResult BackendTranscendence::transcendWithPlan(
    const std::string& url, const TranscendencePlan& plan) {
    for (const auto& sp : plan.stealth_profiles) {
        setEnsembleProfile(sp);
    }

    std::string target = applyRewriteRules(url, plan.rewrite_rules);

    FetchConfig cfg;
    cfg.cache_policy = CachePolicy::REUSE_IF_FRESH;
    FetchResult result = transcendFetch(target, cfg);

    std::string content_type = result.response_headers.get("Content-Type");
    for (const auto& ep : plan.extraction_plans) {
        result.extractions.push_back(
            extractor_->extract(ep, result.bodyString(), content_type));
    }
    return result;
}
