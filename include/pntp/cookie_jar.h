#ifndef PNTP_COOKIE_JAR_H
#define PNTP_COOKIE_JAR_H

#include <cstdint>
#include <string>
#include <vector>

// ── HTTP Cookie (RFC 6265) ───────────────────────────────────────────
//
// A single stored cookie. Domain scoping and path scoping are applied
// when building the Cookie request header; the jar itself keeps every
// cookie (including expired ones, which are evicted lazily on access).
struct HTTPCookie {
    std::string name;
    std::string value;
    std::string domain;          // normalized (leading dot stripped)
    std::string path = "/";
    uint64_t expires_at = 0;     // epoch seconds; 0 = session cookie
    bool secure = false;
    bool http_only = false;
    bool host_only = false;      // no Domain attribute (exact host match)
    uint64_t created_at = 0;
    uint64_t last_access = 0;

    bool isExpired(uint64_t now) const {
        return expires_at != 0 && expires_at <= now;
    }
};

// Offline, deterministic cookie store. Parses Set-Cookie response
// headers, stores them with RFC 6265 domain/path scoping, and produces
// the merged Cookie request header value for a given URL.
class CookieJar {
public:
    CookieJar() = default;

    // Parse every Set-Cookie value from a response and store the
    // resulting cookies scoped against request_url. Returns the number
    // of cookies stored (including overwrites).
    size_t setFromHeaders(const std::string& request_url,
                          const std::vector<std::string>& set_cookie_values);

    // Parse a single Set-Cookie header value against request_url.
    // Returns true and fills out_cookie on success.
    static bool parseSetCookie(const std::string& request_url,
                               const std::string& set_cookie,
                               HTTPCookie& out_cookie);

    // Build the Cookie request header value ("a=b; c=d") for url.
    // Returns an empty string when no cookie applies. Cookies are
    // ordered by descending path length, then by creation time.
    std::string cookieHeaderFor(const std::string& url) const;

    // All cookies that apply to url (qualified by domain/path/secure).
    std::vector<HTTPCookie> cookiesFor(const std::string& url) const;

    void clear() { cookies_.clear(); }
    size_t size() const { return cookies_.size(); }
    const std::vector<HTTPCookie>& all() const { return cookies_; }

    // RFC 6265 §5.1.3 domain matching.
    static bool domainMatches(const std::string& host,
                              const std::string& cookie_domain,
                              bool host_only);
    // RFC 6265 §5.1.4 path matching.
    static bool pathMatches(const std::string& request_path,
                            const std::string& cookie_path);

private:
    void store(const HTTPCookie& cookie);
    static uint64_t nowEpoch();
    static std::string normalizeDomain(const std::string& raw);
    static bool parseDate(const std::string& value, uint64_t& out_epoch);

    std::vector<HTTPCookie> cookies_;
};

#endif // PNTP_COOKIE_JAR_H