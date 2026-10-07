#include "pntp/url_manipulator.h"

#include <cctype>
#include <algorithm>
#include <cstring>
#include <cstdlib>

static const char HEX_DIGITS[17] = "0123456789ABCDEF";

static uint8_t hexValue(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0;
}

static bool needsEncode(unsigned char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'))
        return false;
    switch (c) {
        case '-': case '.': case '_': case '~':
            return false;
        default:
            return true;
    }
}

static const char* schemeDefaultPort(std::string_view scheme, bool* found) {
    struct { const char* name; const char* port; } table[] = {
        {"http", "80"}, {"https", "443"}, {"ftp", "21"},
        {"ssh", "22"}, {"telnet", "23"}, {"smtp", "25"},
        {"ldap", "389"}, {"ldaps", "636"}, {"ws", "80"},
        {"wss", "443"}, {"mqtt", "1883"}, {"mqtts", "8883"},
    };
    for (auto& entry : table) {
        if (scheme == entry.name) {
            *found = true;
            return entry.port;
        }
    }
    *found = false;
    return nullptr;
}

// ── Percent Encoding ─────────────────────────────────────────────────

std::string urlEncode(std::string_view input) {
    std::string result;
    result.reserve(input.size() + input.size() / 2);
    for (size_t i = 0; i < input.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(input[i]);
        if (needsEncode(c)) {
            result += '%';
            result += HEX_DIGITS[c >> 4];
            result += HEX_DIGITS[c & 0x0F];
        } else {
            result += static_cast<char>(c);
        }
    }
    return result;
}

std::string urlDecode(std::string_view input) {
    std::string result;
    result.reserve(input.size());
    for (size_t i = 0; i < input.size(); ++i) {
        char c = input[i];
        if (c == '%' && i + 2 < input.size()) {
            char hi_c = input[i + 1];
            char lo_c = input[i + 2];
            if (std::isxdigit(static_cast<unsigned char>(hi_c)) &&
                std::isxdigit(static_cast<unsigned char>(lo_c))) {
                uint8_t hi = hexValue(hi_c);
                uint8_t lo = hexValue(lo_c);
                result += static_cast<char>((hi << 4) | lo);
                i += 2;
            } else {
                result += c;
            }
        } else if (c == '+') {
            result += ' ';
        } else {
            result += c;
        }
    }
    return result;
}

// ── ParsedURL ────────────────────────────────────────────────────────

ParsedURL ParsedURL::parse(std::string_view url) {
    ParsedURL result;
    if (url.empty()) return result;

    size_t pos = 0;
    size_t n = url.size();

    // scheme = ALPHA *(ALPHA / DIGIT / "+" / "-" / ".")
    size_t scheme_end = url.find(':');
    if (scheme_end == std::string_view::npos || scheme_end == 0)
        return result;
    bool scheme_ok = std::isalpha(static_cast<unsigned char>(url[0])) != 0;
    for (size_t i = 1; i < scheme_end && scheme_ok; ++i) {
        char c = url[i];
        if (!std::isalpha(static_cast<unsigned char>(c)) &&
            !std::isdigit(static_cast<unsigned char>(c)) &&
            c != '+' && c != '-' && c != '.')
            scheme_ok = false;
    }
    if (!scheme_ok) return result;

    result.scheme = std::string(url.substr(0, scheme_end));
    pos = scheme_end + 1;

    // authority (if "//")
    if (pos + 1 < n && url[pos] == '/' && url[pos + 1] == '/') {
        pos += 2;
        size_t auth_end = url.find_first_of("/?#", pos);
        if (auth_end == std::string_view::npos) auth_end = n;
        std::string_view authority = url.substr(pos, auth_end - pos);

        // userinfo@
        size_t at_pos = authority.find('@');
        size_t host_start = 0;
        if (at_pos != std::string_view::npos) {
            result.userinfo = std::string(authority.substr(0, at_pos));
            host_start = at_pos + 1;
        }

        // host with possible IPv6
        std::string_view host_part;
        size_t port_start = std::string_view::npos;
        if (host_start < authority.size() && authority[host_start] == '[') {
            size_t close_bracket = authority.find(']', host_start + 1);
            if (close_bracket == std::string_view::npos) return result;
            host_part = authority.substr(host_start, close_bracket - host_start + 1);
            if (close_bracket + 1 < authority.size() && authority[close_bracket + 1] == ':') {
                port_start = close_bracket + 2;
            }
        } else {
            size_t colon_pos = authority.find_first_of(':', host_start);
            if (colon_pos != std::string_view::npos) {
                host_part = authority.substr(host_start, colon_pos - host_start);
                port_start = colon_pos + 1;
            } else {
                host_part = authority.substr(host_start);
            }
        }
        result.host = std::string(host_part);

        if (result.host.empty()) return result;

        if (port_start != std::string_view::npos && port_start <= authority.size()) {
            std::string_view port_str = authority.substr(port_start);
            long p = std::strtol(std::string(port_str).c_str(), nullptr, 10);
            if (p > 0 && p <= 65535)
                result.port = static_cast<uint16_t>(p);
        }

        pos = auth_end;
    }

    // path
    size_t query_start = url.find('?', pos);
    size_t frag_start = url.find('#', pos);

    if (frag_start != std::string_view::npos && (query_start == std::string_view::npos || frag_start < query_start)) {
        result.path = std::string(url.substr(pos, frag_start - pos));
        result.fragment = std::string(url.substr(frag_start + 1));
    } else if (query_start != std::string_view::npos) {
        result.path = std::string(url.substr(pos, query_start - pos));
        if (frag_start != std::string_view::npos) {
            result.query = std::string(url.substr(query_start + 1, frag_start - query_start - 1));
            result.fragment = std::string(url.substr(frag_start + 1));
        } else {
            result.query = std::string(url.substr(query_start + 1));
        }
    } else {
        result.path = std::string(url.substr(pos));
    }

    result.valid = true;
    return result;
}

uint16_t ParsedURL::defaultPort(std::string_view scheme) {
    bool found = false;
    const char* p = schemeDefaultPort(scheme, &found);
    if (found && p) return static_cast<uint16_t>(std::strtol(p, nullptr, 10));
    return 0;
}

std::string ParsedURL::serialize() const {
    std::string result;
    if (!valid) return result;

    result = scheme;
    result += ':';

    bool has_authority = !host.empty();
    if (has_authority) {
        result += "//";
        if (!userinfo.empty()) {
            result += userinfo;
            result += '@';
        }
        result += host;
        if (port != 0) {
            result += ':';
            result += std::to_string(port);
        }
    }

    result += path;

    if (!query.empty()) {
        result += '?';
        result += query;
    }
    if (!fragment.empty()) {
        result += '#';
        result += fragment;
    }

    return result;
}

// ── Base64 (manual) ──────────────────────────────────────────────────

static const char B64_ALPHABET[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string UrlManipulator::base64Encode(const std::string& input) {
    if (input.empty()) return {};

    size_t len = input.size();
    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    const unsigned char* data = reinterpret_cast<const unsigned char*>(input.data());
    size_t i = 0;
    while (i < len) {
        size_t rem = len - i;
        unsigned char a = data[i];
        unsigned char b = (rem > 1) ? data[i + 1] : 0;
        unsigned char c = (rem > 2) ? data[i + 2] : 0;

        unsigned int triple = (static_cast<unsigned int>(a) << 16) |
                              (static_cast<unsigned int>(b) << 8) |
                              static_cast<unsigned int>(c);

        result += B64_ALPHABET[(triple >> 18) & 0x3F];
        result += B64_ALPHABET[(triple >> 12) & 0x3F];
        result += (rem > 1) ? B64_ALPHABET[(triple >> 6) & 0x3F] : '=';
        result += (rem > 2) ? B64_ALPHABET[triple & 0x3F] : '=';
        i += 3;
    }

    return result;
}

// ── UrlManipulator ───────────────────────────────────────────────────

UrlManipulator::UrlManipulator() = default;

void UrlManipulator::setAuthProvider(const AuthProvider& provider) {
    auth_provider_ = provider;
    has_auth_provider_ = true;
}

void UrlManipulator::setAuthenticationToken(const std::string& token) {
    auth_token_ = token;
}

std::string UrlManipulator::getAuthenticationToken() const {
    return auth_token_;
}

// ── Dot-segment resolution (RFC 3986 §5.2.4) ─────────────────────────

static std::string resolveDotSegments(const std::string& path) {
    if (path.empty() || path == "/") return path;

    bool absolute = (!path.empty() && path[0] == '/');
    std::vector<std::string> segments;
    size_t start = absolute ? 1 : 0;
    size_t end;
    do {
        end = path.find('/', start);
        std::string seg = (end == std::string::npos)
            ? path.substr(start)
            : path.substr(start, end - start);
        if (seg == "..") {
            if (!segments.empty()) segments.pop_back();
        } else if (seg != "." && !seg.empty()) {
            segments.push_back(seg);
        }
        start = end + 1;
    } while (end != std::string::npos);

    std::string result;
    if (absolute) result += '/';
    for (size_t i = 0; i < segments.size(); ++i) {
        if (i > 0) result += '/';
        result += segments[i];
    }
    if (path.size() > 1 && path.back() == '/' && !segments.empty())
        result += '/';

    return result;
}

// ── normalize ─────────────────────────────────────────────────────────

std::string UrlManipulator::normalize(const std::string& url) {
    ParsedURL parsed = ParsedURL::parse(url);
    if (!parsed.valid) return url;

    // Lowercase scheme and host
    for (auto& c : parsed.scheme) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    for (auto& c : parsed.host) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

    // Remove default port
    if (parsed.port != 0) {
        uint16_t def = ParsedURL::defaultPort(parsed.scheme);
        if (def != 0 && parsed.port == def) parsed.port = 0;
    }

    // Resolve dot-segments
    parsed.path = resolveDotSegments(parsed.path);

    // Remove empty query and fragment
    if (parsed.query.empty()) parsed.query.clear();
    if (parsed.fragment.empty()) parsed.fragment.clear();

    return parsed.serialize();
}

// ── Redirect resolution ──────────────────────────────────────────────

std::string UrlManipulator::resolveRedirect(
    const std::string& original_url,
    const std::string& location_header)
{
    if (location_header.empty()) return original_url;

    // Absolute URL
    if (location_header.find("://") != std::string::npos)
        return location_header;

    // Protocol-relative
    if (location_header.size() >= 2 && location_header[0] == '/' && location_header[1] == '/') {
        ParsedURL parsed = ParsedURL::parse(original_url);
        if (!parsed.valid) return location_header;
        return parsed.scheme + ':' + location_header;
    }

    ParsedURL parsed = ParsedURL::parse(original_url);
    if (!parsed.valid) return location_header;

    // Root-relative
    if (!location_header.empty() && location_header[0] == '/') {
        std::string base = parsed.scheme + "://";
        if (!parsed.userinfo.empty()) {
            base += parsed.userinfo + '@';
        }
        base += parsed.host;
        if (parsed.port != 0) {
            base += ':' + std::to_string(parsed.port);
        }
        base += location_header;
        // Resolve any dot-segments in the result path
        size_t qpos = base.find('?');
        size_t hpos = base.find('#');
        size_t path_start = base.find('/', base.find("://") + 3);
        size_t path_end = (qpos != std::string::npos) ? qpos :
                          (hpos != std::string::npos) ? hpos : base.size();
        if (path_start != std::string::npos && path_start < path_end) {
            std::string resolved = resolveDotSegments(base.substr(path_start, path_end - path_start));
            base = base.substr(0, path_start) + resolved + base.substr(path_end);
        }
        return base;
    }

    // Relative path — resolve against base directory
    std::string base = parsed.scheme + "://";
    if (!parsed.userinfo.empty()) base += parsed.userinfo + '@';
    base += parsed.host;
    if (parsed.port != 0) base += ':' + std::to_string(parsed.port);

    // Remove last segment of path (up to last '/')
    std::string base_path = parsed.path;
    size_t last_slash = base_path.rfind('/');
    if (last_slash != std::string::npos)
        base_path = base_path.substr(0, last_slash + 1);
    else
        base_path = "/";

    std::string result = base + base_path + location_header;
    // Resolve any dot-segments
    size_t qpos = result.find('?');
    size_t hpos = result.find('#');
    size_t path_start = result.find('/', result.find("://") + 3);
    size_t path_end = (qpos != std::string::npos) ? qpos :
                      (hpos != std::string::npos) ? hpos : result.size();
    if (path_start != std::string::npos && path_start < path_end) {
        std::string resolved = resolveDotSegments(result.substr(path_start, path_end - path_start));
        result = result.substr(0, path_start) + resolved + result.substr(path_end);
    }
    return result;
}

// ── Redirect chain tracer ───────────────────────────────────────────

RedirectTracer::RedirectTracer(uint32_t max_hops)
    : max_hops_(max_hops == 0 ? 1 : max_hops) {}

RedirectTrace RedirectTracer::trace(const std::string& start_url,
                                    Responder responder) const {
    RedirectTrace trace;
    std::string current = start_url;
    std::vector<std::string> seen;
    UrlManipulator manip;

    for (uint32_t redirects = 0;;) {
        RedirectStep step;
        step.url = current;

        RedirectResponse resp = responder(current);
        step.status = resp.status;
        step.location = resp.location;

        if (resp.status == 0) {
            trace.hops.push_back(std::move(step));
            trace.completed = false;
            trace.stop_reason = "fetch_failed";
            trace.final_url = current;
            return trace;
        }

        std::string fingerprint = manip.normalize(current);
        if (std::find(seen.begin(), seen.end(), fingerprint) != seen.end()) {
            trace.hops.push_back(std::move(step));
            trace.loop_detected = true;
            trace.stop_reason = "loop";
            trace.final_url = current;
            return trace;
        }
        seen.push_back(std::move(fingerprint));
        trace.hops.push_back(std::move(step));

        bool is_redirect = (resp.status >= 300 && resp.status < 400) &&
                           !resp.location.empty();
        if (!is_redirect) {
            trace.completed = true;
            trace.stop_reason = "done";
            trace.final_url = current;
            return trace;
        }

        std::string next =
            UrlManipulator::resolveRedirect(current, resp.location);
        trace.hops.back().followed = true;
        if (next.empty() || next == current) {
            trace.loop_detected = (next == current);
            trace.stop_reason =
                trace.loop_detected ? "loop" : "invalid_location";
            trace.final_url = current;
            return trace;
        }

        if (redirects >= max_hops_) {
            trace.completed = false;
            trace.too_many_hops = true;
            trace.stop_reason = "max_hops";
            trace.final_url = current;
            return trace;
        }
        ++redirects;
        current = std::move(next);
    }
}

// ── Query mutation ───────────────────────────────────────────────────

static std::vector<std::pair<std::string, std::string>> parseQuery(std::string_view qs) {
    std::vector<std::pair<std::string, std::string>> result;
    size_t pos = 0;
    while (pos < qs.size()) {
        size_t amp = qs.find('&', pos);
        std::string_view piece = (amp == std::string_view::npos)
            ? qs.substr(pos) : qs.substr(pos, amp - pos);
        if (!piece.empty()) {
            size_t eq = piece.find('=');
            if (eq != std::string_view::npos) {
                std::string key = urlDecode(piece.substr(0, eq));
                std::string val = urlDecode(piece.substr(eq + 1));
                result.emplace_back(std::move(key), std::move(val));
            } else {
                std::string key = urlDecode(piece);
                result.emplace_back(std::move(key), std::string());
            }
        }
        pos = (amp == std::string_view::npos) ? qs.size() : amp + 1;
    }
    return result;
}

static std::string serializeQuery(const std::vector<std::pair<std::string, std::string>>& pairs) {
    if (pairs.empty()) return {};
    std::string result;
    for (size_t i = 0; i < pairs.size(); ++i) {
        if (i > 0) result += '&';
        result += urlEncode(pairs[i].first);
        if (!pairs[i].second.empty() || pairs[i].first.empty()) {
            result += '=';
            result += urlEncode(pairs[i].second);
        }
    }
    return result;
}

std::string UrlManipulator::mutateQuery(const std::string& url,
                                        const std::vector<QueryOp>& ops)
{
    ParsedURL parsed = ParsedURL::parse(url);
    if (!parsed.valid) return url;

    auto pairs = parseQuery(parsed.query);

    for (const auto& op : ops) {
        switch (op.type) {
        case QueryOpType::SET: {
            // Replace or add
            bool found = false;
            for (auto& p : pairs) {
                if (p.first == op.key) {
                    p.second = op.value;
                    found = true;
                }
            }
            if (!found)
                pairs.emplace_back(op.key, op.value);
            break;
        }
        case QueryOpType::DELETE: {
            for (auto it = pairs.begin(); it != pairs.end(); ) {
                if (it->first == op.key)
                    it = pairs.erase(it);
                else
                    ++it;
            }
            break;
        }
        case QueryOpType::RENAME: {
            for (auto& p : pairs) {
                if (p.first == op.key)
                    p.first = op.new_key;
            }
            break;
        }
        case QueryOpType::SIGN: {
            // XOR parameter values with stealth_rand() bytes, hex-encode
            std::string data;
            for (const auto& sk : op.sign_keys) {
                for (const auto& p : pairs) {
                    if (p.first == sk) {
                        if (!data.empty()) data += '&';
                        data += p.second;
                        break;
                    }
                }
            }
            if (!data.empty()) {
                for (size_t i = 0; i < data.size(); ++i) {
                    data[i] ^= static_cast<char>(static_cast<uint8_t>(stealth_rand() & 0xFF));
                }
                std::string sig;
                sig.reserve(data.size() * 2);
                for (char c_char : data) {
                    unsigned char uc = static_cast<unsigned char>(c_char);
                    sig += HEX_DIGITS[uc >> 4];
                    sig += HEX_DIGITS[uc & 0x0F];
                }
                pairs.emplace_back("_sig", sig);
            }
            break;
        }
        }
    }

    parsed.query = serializeQuery(pairs);
    return parsed.serialize();
}

// ── Auth injection ───────────────────────────────────────────────────

std::map<std::string, std::string> UrlManipulator::injectAuth(
    const std::string& url,
    const std::map<std::string, std::string>& headers,
    const std::string& auth_type,
    const std::string& credentials)
{
    std::map<std::string, std::string> result = headers;
    (void)url;

    std::string type_upper = auth_type;
    for (auto& c : type_upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));

    if (type_upper == "BEARER") {
        result["Authorization"] = "Bearer " + credentials;
    } else if (type_upper == "BASIC") {
        result["Authorization"] = "Basic " + base64Encode(credentials);
    } else if (type_upper == "COOKIE") {
        result["Cookie"] = credentials;
    } else if (type_upper == "DIGEST") {
        // credentials format: "username=..., realm=..., nonce=..., uri=..., response=..."
        // For now, just pass through formatted with the parsed values
        std::string digest_header = "Digest ";
        std::string creds = credentials;
        // Replace commas with commas in the format
        bool first = true;
        size_t pos = 0;
        while (pos < creds.size()) {
            size_t comma = creds.find(',', pos);
            std::string_view pair = (comma == std::string::npos)
                ? std::string_view(creds).substr(pos)
                : std::string_view(creds).substr(pos, comma - pos);
            // Trim leading spaces
            while (!pair.empty() && pair.front() == ' ') pair.remove_prefix(1);
            if (!pair.empty()) {
                size_t eq = pair.find('=');
                if (eq != std::string_view::npos) {
                    std::string key(pair.substr(0, eq));
                    std::string val(pair.substr(eq + 1));
                    if (!first) digest_header += ", ";
                    digest_header += key + "=\"" + val + "\"";
                    first = false;
                }
            }
            pos = (comma == std::string::npos) ? creds.size() : comma + 1;
        }
        result["Authorization"] = digest_header;
    }

    return result;
}

std::map<std::string, std::string> UrlManipulator::modifyRequestHeaders(
    const std::string& url,
    const std::map<std::string, std::string>& original_headers)
{
    std::map<std::string, std::string> result = original_headers;

    // User-Agent
    result["User-Agent"] = "PNTP-Transcendent-Browser/4.0";

    // Auth injection if provider is set or token is set
    if (has_auth_provider_) {
        result = injectAuth(url, result, auth_provider_.type, auth_provider_.credentials);
    } else if (!auth_token_.empty()) {
        result = injectAuth(url, result, "BEARER", auth_token_);
    }

    return result;
}

// ── rewriteUrl ───────────────────────────────────────────────────────

std::string UrlManipulator::rewriteUrl(const std::string& original_url) {
    return normalize(original_url);
}

// ── shouldIntercept ──────────────────────────────────────────────────

bool UrlManipulator::shouldIntercept(const std::string& url) const {
    ParsedURL parsed = ParsedURL::parse(url);
    if (!parsed.valid) return false;
    // Normalize scheme for comparison
    std::string scheme = parsed.scheme;
    for (auto& c : scheme) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return scheme == "https";
}
