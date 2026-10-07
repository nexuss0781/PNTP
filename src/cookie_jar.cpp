#include "pntp/cookie_jar.h"
#include "pntp/url_manipulator.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>

namespace {

std::string toLower(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string trim(const std::string& s) {
    size_t a = 0, b = s.size();
    while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
    while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
    return s.substr(a, b - a);
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    size_t start = 0;
    while (true) {
        size_t pos = s.find(delim, start);
        if (pos == std::string::npos) {
            out.push_back(s.substr(start));
            break;
        }
        out.push_back(s.substr(start, pos - start));
        start = pos + 1;
    }
    return out;
}

// Default cookie path per RFC 6265 §5.1.4.
std::string defaultPath(const std::string& req_path) {
    if (req_path.empty() || req_path[0] != '/') return "/";
    size_t last_slash = req_path.rfind('/');
    if (last_slash == 0 || last_slash == std::string::npos) return "/";
    return req_path.substr(0, last_slash);
}

} // namespace

uint64_t CookieJar::nowEpoch() {
    return static_cast<uint64_t>(std::time(nullptr));
}

std::string CookieJar::normalizeDomain(const std::string& raw) {
    std::string d = trim(raw);
    if (!d.empty() && d.front() == '.') d.erase(d.begin());
    if (!d.empty() && d.back() == '.') d.pop_back();
    return toLower(d);
}

bool CookieJar::parseDate(const std::string& value, uint64_t& out_epoch) {
    const char* formats[] = {
        "%a, %d %b %Y %H:%M:%S",
        "%a, %d-%b-%Y %H:%M:%S",
        "%a, %d-%b-%y %H:%M:%S",
        "%a %b %d %H:%M:%S %Y",
        "%d %b %Y %H:%M:%S",
        "%d-%b-%Y %H:%M:%S",
    };
    for (const char* fmt : formats) {
        std::tm tm{};
        const char* end = strptime(value.c_str(), fmt, &tm);
        if (end != nullptr) {
            time_t t = timegm(&tm);
            if (t != static_cast<time_t>(-1)) {
                out_epoch = static_cast<uint64_t>(t);
                return true;
            }
        }
    }
    return false;
}

bool CookieJar::domainMatches(const std::string& host,
                              const std::string& cookie_domain,
                              bool host_only) {
    std::string h = toLower(host);
    std::string d = toLower(cookie_domain);
    if (d.empty()) return false;
    if (host_only) return h == d;
    if (h == d) return true;
    if (h.size() > d.size() + 1 &&
        h.compare(h.size() - d.size() - 1, d.size() + 1, "." + d) == 0) {
        return true;
    }
    return false;
}

bool CookieJar::pathMatches(const std::string& request_path,
                            const std::string& cookie_path) {
    if (cookie_path.empty()) return true;
    if (request_path == cookie_path) return true;
    if (request_path.size() > cookie_path.size() &&
        request_path.compare(0, cookie_path.size(), cookie_path) == 0) {
        if (cookie_path.back() == '/') return true;
        if (request_path[cookie_path.size()] == '/') return true;
    }
    return false;
}

bool CookieJar::parseSetCookie(const std::string& request_url,
                               const std::string& set_cookie,
                               HTTPCookie& out_cookie) {
    ParsedURL url = ParsedURL::parse(request_url);
    if (!url.valid || url.host.empty()) return false;

    std::vector<std::string> parts = split(set_cookie, ';');
    if (parts.empty()) return false;

    std::string name_value = trim(parts[0]);
    size_t eq = name_value.find('=');
    if (eq == std::string::npos) return false;

    HTTPCookie cookie;
    cookie.name = trim(name_value.substr(0, eq));
    cookie.value = trim(name_value.substr(eq + 1));
    if (cookie.name.empty()) return false;

    std::string host = toLower(url.host);
    std::string req_path = url.path.empty() ? std::string("/") : url.path;

    cookie.domain = host;
    cookie.host_only = true;
    cookie.path = defaultPath(req_path);
    cookie.created_at = nowEpoch();
    cookie.last_access = cookie.created_at;

    bool max_age_set = false;
    int64_t max_age = 0;

    for (size_t i = 1; i < parts.size(); ++i) {
        std::string attr = trim(parts[i]);
        if (attr.empty()) continue;

        size_t aeq = attr.find('=');
        std::string key = toLower(trim(aeq == std::string::npos
                                           ? attr
                                           : attr.substr(0, aeq)));
        std::string val = (aeq == std::string::npos)
                              ? std::string()
                              : trim(attr.substr(aeq + 1));

        if (key == "domain") {
            std::string d = normalizeDomain(val);
            if (d.empty()) return false;
            if (!domainMatches(host, d, false)) return false;
            cookie.domain = d;
            cookie.host_only = false;
        } else if (key == "path") {
            if (!val.empty() && val[0] == '/') cookie.path = val;
        } else if (key == "expires") {
            uint64_t exp = 0;
            if (parseDate(val, exp)) cookie.expires_at = exp;
        } else if (key == "max-age") {
            char* endp = nullptr;
            long long v = std::strtoll(val.c_str(), &endp, 10);
            if (endp != nullptr && endp != val.c_str()) {
                max_age = v;
                max_age_set = true;
            }
        } else if (key == "secure") {
            cookie.secure = true;
        } else if (key == "httponly") {
            cookie.http_only = true;
        }
    }

    if (max_age_set) {
        uint64_t now = nowEpoch();
        cookie.expires_at = (max_age <= 0)
                                ? now - 1
                                : now + static_cast<uint64_t>(max_age);
    }

    out_cookie = cookie;
    return true;
}

void CookieJar::store(const HTTPCookie& cookie) {
    for (auto it = cookies_.begin(); it != cookies_.end(); ++it) {
        if (it->name == cookie.name && it->domain == cookie.domain &&
            it->path == cookie.path) {
            cookies_.erase(it);
            break;
        }
    }
    cookies_.push_back(cookie);
}

size_t CookieJar::setFromHeaders(
    const std::string& request_url,
    const std::vector<std::string>& set_cookie_values) {
    size_t stored = 0;
    for (const std::string& sc : set_cookie_values) {
        HTTPCookie cookie;
        if (parseSetCookie(request_url, sc, cookie)) {
            store(cookie);
            ++stored;
        }
    }
    return stored;
}

std::vector<HTTPCookie> CookieJar::cookiesFor(const std::string& url) const {
    std::vector<HTTPCookie> out;
    ParsedURL u = ParsedURL::parse(url);
    if (!u.valid) return out;

    std::string host = toLower(u.host);
    std::string req_path = u.path.empty() ? std::string("/") : u.path;
    bool secure_channel = (toLower(u.scheme) == "https");
    uint64_t now = nowEpoch();

    for (const HTTPCookie& c : cookies_) {
        if (c.isExpired(now)) continue;
        if (c.secure && !secure_channel) continue;
        if (!domainMatches(host, c.domain, c.host_only)) continue;
        if (!pathMatches(req_path, c.path)) continue;
        out.push_back(c);
    }

    std::sort(out.begin(), out.end(),
              [](const HTTPCookie& a, const HTTPCookie& b) {
                  if (a.path.size() != b.path.size())
                      return a.path.size() > b.path.size();
                  return a.created_at > b.created_at;
              });
    return out;
}

std::string CookieJar::cookieHeaderFor(const std::string& url) const {
    std::vector<HTTPCookie> cs = cookiesFor(url);
    std::string result;
    for (const HTTPCookie& c : cs) {
        if (!result.empty()) result += "; ";
        result += c.name;
        result += '=';
        result += c.value;
    }
    return result;
}