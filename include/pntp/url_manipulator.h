#ifndef PNTP_URL_MANIPULATOR_H
#define PNTP_URL_MANIPULATOR_H

#include <string>
#include <string_view>
#include <map>
#include <vector>
#include <functional>
#include <cstdint>

#include "pntp/pntp_core.h"

struct ParsedURL {
    std::string scheme;
    std::string userinfo;
    std::string host;
    uint16_t port = 0;
    std::string path;
    std::string query;
    std::string fragment;
    bool valid = false;

    std::string serialize() const;
    static ParsedURL parse(std::string_view url);
    static uint16_t defaultPort(std::string_view scheme);
};

std::string urlEncode(std::string_view input);
std::string urlDecode(std::string_view input);

enum class QueryOpType : uint8_t {
    SET,
    DELETE,
    RENAME,
    SIGN
};

struct QueryOp {
    QueryOpType type = QueryOpType::SET;
    std::string key;
    std::string new_key;
    std::string value;
    std::vector<std::string> sign_keys;
};

class UrlManipulator {
public:
    struct AuthProvider {
        std::string type;
        std::string credentials;
    };

    UrlManipulator();
    ~UrlManipulator() = default;

    std::string rewriteUrl(const std::string& original_url);

    std::map<std::string, std::string> modifyRequestHeaders(
        const std::string& url,
        const std::map<std::string, std::string>& original_headers);

    std::map<std::string, std::string> injectAuth(
        const std::string& url,
        const std::map<std::string, std::string>& headers,
        const std::string& auth_type,
        const std::string& credentials);

    void setAuthProvider(const AuthProvider& provider);

    std::string normalize(const std::string& url);

    std::string mutateQuery(const std::string& url,
                            const std::vector<QueryOp>& ops);

    static std::string resolveRedirect(
        const std::string& original_url,
        const std::string& location_header);

    bool shouldIntercept(const std::string& url) const;

    void setAuthenticationToken(const std::string& token);
    std::string getAuthenticationToken() const;

private:
    static std::string base64Encode(const std::string& input);

    AuthProvider auth_provider_{"BEARER", ""};
    bool has_auth_provider_ = false;
    std::string auth_token_;
};

// ── Redirect chain tracer ───────────────────────────────────────────
// Walks an HTTP 3xx redirect chain hop-by-hop up to a configurable
// limit. Transport-agnostic: the caller provides a responder that
// returns the {status, Location} pair for a given URL (e.g. backed by
// TCPEngine + HTTP parser, a raw loopback socket, the system curl, or a
// canned table in tests). Loop detection compares normalized URLs, so
// chains that revisit an already-requested URL stop with "loop".
// max_hops is the maximum number of *redirects* followed (the initial
// request is hop 0 and does not count against the limit).

struct RedirectResponse {
    uint16_t status = 0;
    std::string location;
};

struct RedirectStep {
    std::string url;        // URL requested at this hop
    uint16_t status = 0;    // HTTP status received
    std::string location;   // raw Location header ("" when absent)
    bool followed = false;  // true when the hop produced a next URL
};

struct RedirectTrace {
    std::vector<RedirectStep> hops;   // every requested URL, in order
    std::string final_url;            // last URL reached
    bool completed = false;           // true when resolved to a non-3xx
    bool loop_detected = false;
    bool too_many_hops = false;
    std::string stop_reason;  // "done" | "loop" | "max_hops"
                              // | "invalid_location" | "fetch_failed"
};

class RedirectTracer {
public:
    using Responder =
        std::function<RedirectResponse(const std::string& url)>;

    explicit RedirectTracer(uint32_t max_hops);

    RedirectTrace trace(const std::string& start_url,
                        Responder responder) const;

    uint32_t maxHops() const { return max_hops_; }

private:
    uint32_t max_hops_;
};

#endif
