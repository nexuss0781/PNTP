#include "pntp/data_extractor.h"

#include <cctype>
#include <cstring>
#include <cstdlib>
#include <algorithm>
#include <vector>
#include <chrono>
#include <regex>
#include <map>
#ifdef HAS_ICONV
#include <iconv.h>
#endif

// ── File-local helpers ──────────────────────────────────────────

static bool iequal(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) !=
            std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

static bool isTagChar(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) != 0 || c == '-' || c == ':';
}

static const char* const VOID_TAGS[] = {
    "area", "base", "br", "col", "embed", "hr", "img", "input",
    "link", "meta", "param", "source", "track", "wbr"
};

static const char* const RAW_TAGS[] = {
    "script", "style", "textarea", "title"
};

// ── Constructor (default) ───────────────────────────────────────

DataExtractor::DataExtractor() {}

// ── hexNibble ──────────────────────────────────────────────────

uint8_t DataExtractor::hexNibble(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0xFF;
}

// ── decodeUtf8Codepoint ────────────────────────────────────────

uint32_t DataExtractor::decodeUtf8Codepoint(const char*& it, const char* end) {
    if (it >= end) return 0;
    unsigned char lead = static_cast<unsigned char>(*it);

    if (lead < 0x80) {
        ++it;
        return lead;
    }

    if ((lead & 0xE0) == 0xC0 && end - it >= 2) {
        unsigned char b1 = static_cast<unsigned char>(*(it + 1));
        if ((b1 & 0xC0) == 0x80) {
            it += 2;
            return static_cast<uint32_t>((lead & 0x1F) << 6) | (b1 & 0x3F);
        }
    }

    if ((lead & 0xF0) == 0xE0 && end - it >= 3) {
        unsigned char b1 = static_cast<unsigned char>(*(it + 1));
        unsigned char b2 = static_cast<unsigned char>(*(it + 2));
        if ((b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80) {
            it += 3;
            return static_cast<uint32_t>((lead & 0x0F) << 12)
                 | static_cast<uint32_t>((b1 & 0x3F) << 6)
                 | (b2 & 0x3F);
        }
    }

    if ((lead & 0xF8) == 0xF0 && end - it >= 4) {
        unsigned char b1 = static_cast<unsigned char>(*(it + 1));
        unsigned char b2 = static_cast<unsigned char>(*(it + 2));
        unsigned char b3 = static_cast<unsigned char>(*(it + 3));
        if ((b1 & 0xC0) == 0x80 && (b2 & 0xC0) == 0x80 && (b3 & 0xC0) == 0x80) {
            it += 4;
            return static_cast<uint32_t>((lead & 0x07) << 18)
                 | static_cast<uint32_t>((b1 & 0x3F) << 12)
                 | static_cast<uint32_t>((b2 & 0x3F) << 6)
                 | (b3 & 0x3F);
        }
    }

    ++it;
    return 0xFFFD;
}

// ── htmlEntityDecode ───────────────────────────────────────────

std::string DataExtractor::htmlEntityDecode(std::string_view text) {
    std::string result;
    result.reserve(text.size());

    const char* p = text.data();
    const char* end = p + text.size();

    while (p < end) {
        if (*p != '&') {
            result += *p++;
            continue;
        }

        const char* after = p + 1;
        bool decoded = false;

        // Numeric entity &#NN; or &#xNN;
        if (after < end && *after == '#') {
            const char* h = after + 1;
            bool is_hex = false;
            if (h < end && (*h == 'x' || *h == 'X')) {
                is_hex = true;
                ++h;
            }
            const char* ns = h;
            const char* ne = ns;
            if (is_hex) {
                while (ne < end && std::isxdigit(static_cast<unsigned char>(*ne)))
                    ++ne;
            } else {
                while (ne < end && std::isdigit(static_cast<unsigned char>(*ne)))
                    ++ne;
            }
            if (ne < end && *ne == ';' && ne > ns) {
                uint32_t cp;
                if (is_hex)
                    cp = static_cast<uint32_t>(std::strtoul(std::string(ns, static_cast<size_t>(ne - ns)).c_str(), nullptr, 16));
                else
                    cp = static_cast<uint32_t>(std::strtoul(std::string(ns, static_cast<size_t>(ne - ns)).c_str(), nullptr, 10));

                if (cp < 0x80) {
                    result += static_cast<char>(cp);
                } else if (cp < 0x800) {
                    result += static_cast<char>(0xC0 | static_cast<unsigned char>(cp >> 6));
                    result += static_cast<char>(0x80 | (cp & 0x3F));
                } else if (cp < 0x10000) {
                    result += static_cast<char>(0xE0 | static_cast<unsigned char>(cp >> 12));
                    result += static_cast<char>(0x80 | static_cast<unsigned char>((cp >> 6) & 0x3F));
                    result += static_cast<char>(0x80 | (cp & 0x3F));
                } else if (cp < 0x110000) {
                    result += static_cast<char>(0xF0 | static_cast<unsigned char>(cp >> 18));
                    result += static_cast<char>(0x80 | static_cast<unsigned char>((cp >> 12) & 0x3F));
                    result += static_cast<char>(0x80 | static_cast<unsigned char>((cp >> 6) & 0x3F));
                    result += static_cast<char>(0x80 | (cp & 0x3F));
                }
                p = ne + 1;
                decoded = true;
            }
        } else if (after < end && std::isalpha(static_cast<unsigned char>(*after))) {
            const char* ns = after;
            const char* ne = ns;
            while (ne < end && std::isalpha(static_cast<unsigned char>(*ne)))
                ++ne;
            if (ne < end && *ne == ';') {
                std::string_view name(ns, static_cast<size_t>(ne - ns));
                char repl = 0;
                if (name == "amp") repl = '&';
                else if (name == "lt") repl = '<';
                else if (name == "gt") repl = '>';
                else if (name == "quot") repl = '"';
                else if (name == "apos") repl = '\'';
                if (repl) {
                    result += repl;
                    p = ne + 1;
                    decoded = true;
                }
            }
        }

        if (!decoded)
            result += *p++;
    }

    return result;
}

// ── SAXParser static methods ───────────────────────────────────

bool DataExtractor::SAXParser::isVoidElement(std::string_view tag) {
    for (auto v : VOID_TAGS)
        if (iequal(tag, v)) return true;
    return false;
}

bool DataExtractor::SAXParser::isRawTextElement(std::string_view tag) {
    for (auto r : RAW_TAGS)
        if (iequal(tag, r)) return true;
    return false;
}

bool DataExtractor::SAXParser::isWhitespace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f';
}

// ── SAXParser::parse (callback) ────────────────────────────────

void DataExtractor::SAXParser::parse(std::string_view html, TokenCallback cb) {
    if (html.empty()) {
        SAXToken eof;
        eof.type = SAXToken::EOF_;
        eof.offset = 0;
        eof.length = 0;
        cb(eof);
        return;
    }

    const char* base = html.data();
    const char* p = base;
    const char* end = p + html.size();

    // State machine
    enum St : uint8_t {
        TEXT,
        LANGLE,
        TAG_OPEN,
        TAG_CLOSE,
        BEFORE_ATTR,
        ATTR_NAME,
        ATTR_EQ,
        ATTR_VAL_DQ,
        ATTR_VAL_SQ,
        ATTR_VAL_UQ,
        SELF_CLOSE,
        BANG,
        BANG_DASH
    };

    St st = TEXT;
    size_t token_start = 0;
    std::string text_buf;
    std::string tag_name;
    std::vector<Attribute> attrs;
    std::string attr_name;
    std::string attr_val;

    // ── Scan helper for comments ──
    auto scanComment = [&]() {
        const char* content_start = p;
        while (p < end) {
            if (*p == '-' && end - p >= 3 && *(p + 1) == '-' && *(p + 2) == '>') {
                SAXToken t;
                t.type = SAXToken::COMMENT;
                t.content = std::string(content_start, static_cast<size_t>(p - content_start));
                t.offset = token_start;
                t.length = static_cast<size_t>((p + 3) - base) - token_start;
                cb(t);
                p += 3;
                st = TEXT;
                text_buf.clear();
                return;
            }
            ++p;
        }
        SAXToken t;
        t.type = SAXToken::COMMENT;
        t.content = std::string(content_start, static_cast<size_t>(p - content_start));
        t.offset = token_start;
        t.length = static_cast<size_t>(p - base) - token_start;
        cb(t);
        st = TEXT;
        text_buf.clear();
    };

    // ── Scan helper for CDATA ──
    auto scanCDATA = [&]() {
        const char* content_start = p;
        while (p < end) {
            if (*p == ']' && end - p >= 3 && *(p + 1) == ']' && *(p + 2) == '>') {
                SAXToken t;
                t.type = SAXToken::CDATA;
                t.content = std::string(content_start, static_cast<size_t>(p - content_start));
                t.offset = token_start;
                t.length = static_cast<size_t>((p + 3) - base) - token_start;
                cb(t);
                p += 3;
                st = TEXT;
                text_buf.clear();
                return;
            }
            ++p;
        }
        SAXToken t;
        t.type = SAXToken::CDATA;
        t.content = std::string(content_start, static_cast<size_t>(p - content_start));
        t.offset = token_start;
        t.length = static_cast<size_t>(p - base) - token_start;
        cb(t);
        st = TEXT;
        text_buf.clear();
    };

    // ── Scan helper for raw text (script, style, textarea, title) ──
    auto scanRawText = [&](const std::string& raw_tag, SAXToken::Type content_type) {
        const char* content_start = p;
        while (p < end) {
            if (*p == '<' && static_cast<size_t>(end - p) >= 3 + raw_tag.size()) {
                if (*(p + 1) == '/') {
                    const char* ns = p + 2;
                    const char* ne = ns;
                    while (ne < end && isTagChar(*ne))
                        ++ne;
                    std::string_view candidate(ns, static_cast<size_t>(ne - ns));
                    if (iequal(candidate, raw_tag)) {
                        const char* gt = ne;
                        while (gt < end && (*gt == ' ' || *gt == '\t' || *gt == '\n' || *gt == '\r'))
                            ++gt;
                        if (gt < end && *gt == '>') {
                            SAXToken ct;
                            ct.type = content_type;
                            ct.content = std::string(content_start, static_cast<size_t>(p - content_start));
                            ct.offset = static_cast<size_t>(content_start - base);
                            ct.length = static_cast<size_t>(p - content_start);
                            cb(ct);

                            SAXToken close;
                            close.type = SAXToken::TAG_CLOSE;
                            close.name = std::string(raw_tag);
                            close.offset = static_cast<size_t>(p - base);
                            close.length = static_cast<size_t>((gt + 1) - p);
                            cb(close);

                            p = gt + 1;
                            st = TEXT;
                            text_buf.clear();
                            return;
                        }
                    }
                }
            }
            ++p;
        }
        // EOF — emit remaining content, no close tag
        SAXToken ct;
        ct.type = content_type;
        ct.content = std::string(content_start, static_cast<size_t>(p - content_start));
        ct.offset = static_cast<size_t>(content_start - base);
        ct.length = static_cast<size_t>(p - content_start);
        cb(ct);
        st = TEXT;
        text_buf.clear();
    };

    // ── Scan helper for bogus comments (scan to '>') ──
    auto scanToGt = [&](std::string&& prefix) {
        std::string buf = std::move(prefix);
        while (p < end && *p != '>') {
            buf += *p;
            ++p;
        }
        if (p < end)
            ++p; // skip '>'
        SAXToken t;
        t.type = SAXToken::COMMENT;
        t.content = std::move(buf);
        t.offset = token_start;
        t.length = static_cast<size_t>(p - base) - token_start;
        cb(t);
        st = TEXT;
        text_buf.clear();
    };

    // ── Main loop ──
    while (p < end) {
        char c = *p;

        switch (st) {

        case TEXT:
            if (c == '<') {
                if (!text_buf.empty()) {
                    SAXToken t;
                    t.type = SAXToken::TEXT;
                    t.content = std::move(text_buf);
                    t.offset = token_start;
                    t.length = static_cast<size_t>(p - base) - token_start;
                    cb(t);
                    text_buf.clear();
                }
                token_start = static_cast<size_t>(p - base);
                st = LANGLE;
                ++p;
            } else {
                if (text_buf.empty())
                    token_start = static_cast<size_t>(p - base);
                text_buf += c;
                ++p;
            }
            break;

        case LANGLE:
            if (c == '/') {
                st = TAG_CLOSE;
                tag_name.clear();
                ++p;
            } else if (c == '!') {
                st = BANG;
                ++p;
            } else if (c == '?') {
                ++p;
                scanToGt(std::string("?"));
            } else if (std::isalpha(static_cast<unsigned char>(c))) {
                st = TAG_OPEN;
                tag_name.clear();
                tag_name += c;
                ++p;
            } else {
                text_buf += '<';
                text_buf += c;
                st = TEXT;
                ++p;
            }
            break;

        case TAG_OPEN:
            if (isTagChar(c)) {
                tag_name += c;
                ++p;
            } else if (DataExtractor::SAXParser::isWhitespace(c)) {
                st = BEFORE_ATTR;
                ++p;
            } else if (c == '/') {
                st = SELF_CLOSE;
                ++p;
            } else if (c == '>') {
                std::string raw_check = tag_name;
                {
                    SAXToken t;
                    t.type = SAXToken::TAG_OPEN;
                    t.name = std::move(tag_name);
                    t.attributes = std::move(attrs);
                    t.offset = token_start;
                    t.length = static_cast<size_t>((p + 1) - base) - token_start;
                    cb(t);
                    tag_name.clear();
                    attrs.clear();
                }
                ++p;
                if (isRawTextElement(raw_check)) {
                    SAXToken::Type ct;
                    if (iequal(raw_check, "script"))
                        ct = SAXToken::SCRIPT;
                    else if (iequal(raw_check, "style"))
                        ct = SAXToken::STYLE;
                    else
                        ct = SAXToken::TEXT;
                    scanRawText(raw_check, ct);
                } else {
                    st = TEXT;
                    text_buf.clear();
                }
            } else {
                text_buf += '<';
                text_buf += tag_name;
                text_buf += c;
                tag_name.clear();
                st = TEXT;
                ++p;
            }
            break;

        case TAG_CLOSE:
            if (isTagChar(c)) {
                tag_name += c;
                ++p;
            } else if (c == '>') {
                SAXToken t;
                t.type = SAXToken::TAG_CLOSE;
                t.name = std::move(tag_name);
                t.offset = token_start;
                t.length = static_cast<size_t>((p + 1) - base) - token_start;
                cb(t);
                tag_name.clear();
                st = TEXT;
                text_buf.clear();
                ++p;
            } else if (DataExtractor::SAXParser::isWhitespace(c)) {
                ++p;
            } else {
                tag_name += c;
                ++p;
            }
            break;

        case BEFORE_ATTR:
            if (DataExtractor::SAXParser::isWhitespace(c)) {
                ++p;
            } else if (c == '>') {
                {
                    SAXToken t;
                    t.type = SAXToken::TAG_OPEN;
                    t.name = std::move(tag_name);
                    t.attributes = std::move(attrs);
                    t.offset = token_start;
                    t.length = static_cast<size_t>((p + 1) - base) - token_start;
                    cb(t);
                    tag_name.clear();
                    attrs.clear();
                }
                ++p;
                st = TEXT;
                text_buf.clear();
            } else if (c == '/') {
                st = SELF_CLOSE;
                ++p;
            } else if (c != '"' && c != '\'' && c != '=' && c != '<') {
                attr_name.clear();
                attr_name += c;
                st = ATTR_NAME;
                ++p;
            } else {
                ++p;
            }
            break;

        case ATTR_NAME:
            if (c == '=') {
                st = ATTR_EQ;
                ++p;
            } else if (DataExtractor::SAXParser::isWhitespace(c) || c == '>' || c == '/') {
                attrs.push_back({std::move(attr_name), std::string(), false});
                attr_name.clear();
                if (c == '>') {
                    SAXToken t;
                    t.type = SAXToken::TAG_OPEN;
                    t.name = std::move(tag_name);
                    t.attributes = std::move(attrs);
                    t.offset = token_start;
                    t.length = static_cast<size_t>((p + 1) - base) - token_start;
                    cb(t);
                    tag_name.clear();
                    attrs.clear();
                    ++p;
                    st = TEXT;
                    text_buf.clear();
                } else if (c == '/') {
                    st = SELF_CLOSE;
                    ++p;
                } else {
                    st = BEFORE_ATTR;
                    ++p;
                }
            } else if (c != '"' && c != '\'' && c != '<') {
                attr_name += c;
                ++p;
            } else {
                ++p;
            }
            break;

        case ATTR_EQ:
            if (c == '"') {
                attr_val.clear();
                st = ATTR_VAL_DQ;
                ++p;
            } else if (c == '\'') {
                attr_val.clear();
                st = ATTR_VAL_SQ;
                ++p;
            } else if (DataExtractor::SAXParser::isWhitespace(c)) {
                ++p;
            } else if (c != '>' && c != '/') {
                attr_val.clear();
                attr_val += c;
                st = ATTR_VAL_UQ;
                ++p;
            } else {
                attrs.push_back({std::move(attr_name), std::string(), false});
                attr_name.clear();
            }
            break;

        case ATTR_VAL_DQ:
            if (c == '"') {
                attrs.push_back({std::move(attr_name), std::move(attr_val), true});
                attr_name.clear();
                st = BEFORE_ATTR;
                ++p;
            } else {
                attr_val += c;
                ++p;
            }
            break;

        case ATTR_VAL_SQ:
            if (c == '\'') {
                attrs.push_back({std::move(attr_name), std::move(attr_val), true});
                attr_name.clear();
                st = BEFORE_ATTR;
                ++p;
            } else {
                attr_val += c;
                ++p;
            }
            break;

        case ATTR_VAL_UQ:
            if (DataExtractor::SAXParser::isWhitespace(c) || c == '>' || c == '/') {
                attrs.push_back({std::move(attr_name), std::move(attr_val), false});
                attr_name.clear();
                if (c == '>') {
                    SAXToken t;
                    t.type = SAXToken::TAG_OPEN;
                    t.name = std::move(tag_name);
                    t.attributes = std::move(attrs);
                    t.offset = token_start;
                    t.length = static_cast<size_t>((p + 1) - base) - token_start;
                    cb(t);
                    tag_name.clear();
                    attrs.clear();
                    ++p;
                    st = TEXT;
                    text_buf.clear();
                } else if (c == '/') {
                    st = SELF_CLOSE;
                    ++p;
                } else {
                    st = BEFORE_ATTR;
                    ++p;
                }
            } else {
                attr_val += c;
                ++p;
            }
            break;

        case SELF_CLOSE:
            if (c == '>') {
                SAXToken t;
                t.type = SAXToken::TAG_OPEN;
                t.name = std::move(tag_name);
                t.attributes = std::move(attrs);
                t.offset = token_start;
                t.length = static_cast<size_t>((p + 1) - base) - token_start;
                cb(t);
                tag_name.clear();
                attrs.clear();
                ++p;
                st = TEXT;
                text_buf.clear();
            } else if (DataExtractor::SAXParser::isWhitespace(c)) {
                ++p;
            } else {
                ++p;
            }
            break;

        case BANG: {
            if (c == '-') {
                st = BANG_DASH;
                ++p;
            } else if (c == '[') {
                if (end - p >= 7 && std::string_view(p + 1, 6) == "CDATA[") {
                    p += 7;
                    scanCDATA();
                } else {
                    ++p;
                    scanToGt(std::string("!["));
                }
            } else if (std::tolower(static_cast<unsigned char>(c)) == 'd') {
                if (end - p >= 7) {
                    std::string lower;
                    for (int i = 0; i < 7; ++i)
                        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(p[i])));
                    if (lower == "doctype") {
                        p += 7;
                        std::string content;
                        while (p < end && *p != '>') {
                            content += *p;
                            ++p;
                        }
                        SAXToken t;
                        t.type = SAXToken::DOCTYPE;
                        t.content = std::move(content);
                        t.offset = token_start;
                        t.length = static_cast<size_t>((p < end ? p + 1 : p) - base) - token_start;
                        cb(t);
                        if (p < end) ++p;
                        st = TEXT;
                        text_buf.clear();
                        break;
                    }
                }
                std::string bogus = "!";
                bogus += c;
                ++p;
                scanToGt(std::move(bogus));
            } else {
                std::string bogus = "!";
                bogus += c;
                ++p;
                scanToGt(std::move(bogus));
            }
            break;
        }

        case BANG_DASH:
            if (c == '-') {
                ++p;
                scanComment();
            } else {
                std::string bogus = "!-";
                bogus += c;
                ++p;
                scanToGt(std::move(bogus));
            }
            break;
        }
    }

    // ── End of input ──
    if (!text_buf.empty()) {
        SAXToken t;
        t.type = SAXToken::TEXT;
        t.content = std::move(text_buf);
        t.offset = token_start;
        t.length = static_cast<size_t>(p - base) - token_start;
        cb(t);
        text_buf.clear();
    }

    SAXToken eof;
    eof.type = SAXToken::EOF_;
    eof.offset = static_cast<size_t>(p - base);
    eof.length = 0;
    cb(eof);
}

// ── SAXParser::parse (vector) ──────────────────────────────────

std::vector<SAXToken> DataExtractor::SAXParser::parse(std::string_view html) {
    std::vector<SAXToken> tokens;
    parse(html, [&](const SAXToken& t) -> bool {
        tokens.push_back(t);
        return true;
    });
    return tokens;
}

// ── CSS Selector Helpers ──────────────────────────────────────

static bool isIdentCharCss(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_';
}

static const char* skipWsCss(const char* p, const char* end) {
    while (p < end && DataExtractor::SAXParser::isWhitespace(*p)) ++p;
    return p;
}

static std::string parseIdentCss(const char*& p, const char* end) {
    const char* start = p;
    while (p < end && isIdentCharCss(*p)) ++p;
    return std::string(start, static_cast<size_t>(p - start));
}

// ── nth-child formula parsing ───────────────────────────────

struct NthFormula { int a; int b; };

static bool parseNthFormula(std::string_view s, NthFormula& out) {
    while (!s.empty() && DataExtractor::SAXParser::isWhitespace(s.front())) s.remove_prefix(1);
    while (!s.empty() && DataExtractor::SAXParser::isWhitespace(s.back())) s.remove_suffix(1);

    if (s == "odd")  { out = {2, 1}; return true; }
    if (s == "even") { out = {2, 0}; return true; }

    const char* p = s.data();
    const char* end = p + s.size();

    int a = 0, b = 0;
    int sign = 1;
    if (p < end && *p == '-') { sign = -1; ++p; }
    else if (p < end && *p == '+') { ++p; }

    const char* ns = p;
    while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;

    if (p < end && *p == 'n') {
        int coeff = 1;
        if (ns < p)
            coeff = std::atoi(std::string(ns, static_cast<size_t>(p - ns)).c_str());
        a = sign * coeff;
        ++p;
    } else {
        p = s.data();
        if (*p == '-' || *p == '+') ++p;
        ns = p;
        while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        if (p > ns)
            b = std::atoi(std::string(ns, static_cast<size_t>(p - ns)).c_str());
        out = {0, b};
        return true;
    }

    p = skipWsCss(p, end);
    if (p < end && (*p == '+' || *p == '-')) {
        int b_sign = (*p == '-') ? -1 : 1;
        ++p;
        p = skipWsCss(p, end);
        ns = p;
        while (p < end && std::isdigit(static_cast<unsigned char>(*p))) ++p;
        if (p > ns)
            b = b_sign * std::atoi(std::string(ns, static_cast<size_t>(p - ns)).c_str());
    }

    out = {a, b};
    return true;
}

// ── Element info for matching ───────────────────────────────

struct ElemInfo {
    std::string tag;
    std::string id;
    std::vector<std::string> classes;
    std::map<std::string, std::string> attrs;
    size_t token_index;
    size_t depth;
};

static ElemInfo buildElemInfo(const SAXToken& tok, size_t depth) {
    ElemInfo info;
    info.tag = tok.name;
    info.token_index = 0;
    info.depth = depth;

    for (const auto& attr : tok.attributes) {
        info.attrs[attr.name] = attr.value;
        if (iequal(attr.name, "id"))
            info.id = attr.value;
        if (iequal(attr.name, "class")) {
            const char* p = attr.value.data();
            const char* end = p + attr.value.size();
            while (p < end) {
                while (p < end && DataExtractor::SAXParser::isWhitespace(*p)) ++p;
                const char* start = p;
                while (p < end && !DataExtractor::SAXParser::isWhitespace(*p)) ++p;
                if (p > start)
                    info.classes.emplace_back(start, p - start);
            }
        }
    }

    return info;
}

// ── Simple / Compound matching ─────────────────────────────

static bool simpleMatches(const ElemInfo& elem, const SimpleSelector& sel) {
    switch (sel.type) {
    case SimpleSelector::TAG:
        if (elem.tag.empty()) return false;
        if (sel.name == "*") return true;
        return iequal(elem.tag, sel.name);
    case SimpleSelector::ID:
        return iequal(elem.id, sel.name);
    case SimpleSelector::CLASS:
        for (const auto& cls : elem.classes)
            if (iequal(cls, sel.name)) return true;
        return false;
    case SimpleSelector::ATTR_PRESENCE:
        return elem.attrs.find(sel.name) != elem.attrs.end();
    case SimpleSelector::ATTR_EQUALS: {
        auto it = elem.attrs.find(sel.name);
        if (it == elem.attrs.end()) return false;
        return it->second == sel.value;
    }
    case SimpleSelector::ATTR_CONTAINS_WORD: {
        auto it = elem.attrs.find(sel.name);
        if (it == elem.attrs.end()) return false;
        const std::string& val = it->second;
        const char* p = val.data();
        const char* end = p + val.size();
        while (p < end) {
            while (p < end && DataExtractor::SAXParser::isWhitespace(*p)) ++p;
            const char* start = p;
            while (p < end && !DataExtractor::SAXParser::isWhitespace(*p)) ++p;
            if (static_cast<size_t>(p - start) == sel.value.size() &&
                std::equal(start, p, sel.value.begin()))
                return true;
        }
        return false;
    }
    case SimpleSelector::ATTR_BEGINS: {
        auto it = elem.attrs.find(sel.name);
        if (it == elem.attrs.end()) return false;
        if (sel.value.size() > it->second.size()) return false;
        return std::equal(sel.value.begin(), sel.value.end(), it->second.begin());
    }
    case SimpleSelector::ATTR_ENDS: {
        auto it = elem.attrs.find(sel.name);
        if (it == elem.attrs.end()) return false;
        if (sel.value.size() > it->second.size()) return false;
        return std::equal(sel.value.begin(), sel.value.end(),
                          it->second.end() - static_cast<std::string::difference_type>(sel.value.size()));
    }
    case SimpleSelector::ATTR_CONTAINS: {
        auto it = elem.attrs.find(sel.name);
        if (it == elem.attrs.end()) return false;
        return it->second.find(sel.value) != std::string::npos;
    }
    case SimpleSelector::NTH_CHILD:
        return true;
    }
    return false;
}

static bool nthChildMatches(int n, const SimpleSelector& sel) {
    NthFormula f;
    std::string_view sv = sel.value.empty() ? sel.name : sel.value;
    if (!parseNthFormula(sv, f)) return false;
    if (f.a == 0) return n == f.b;
    int diff = n - f.b;
    if (f.a > 0) {
        if (diff < 0) return false;
        return diff % f.a == 0;
    } else {
        if (diff > 0) return false;
        return diff % f.a == 0;
    }
}

static bool compoundMatches(const ElemInfo& elem,
                            const CompoundSelector& compound,
                            size_t sibling_pos)
{
    for (const auto& sel : compound.simples) {
        if (sel.type == SimpleSelector::NTH_CHILD) {
            if (!nthChildMatches(static_cast<int>(sibling_pos), sel))
                return false;
        } else {
            if (!simpleMatches(elem, sel))
                return false;
        }
    }
    return true;
}

// Count elements in all_elems at given depth (for current-element sibling count)
static size_t countSiblingsAtDepth(const std::vector<ElemInfo>& all_elems, size_t depth) {
    size_t count = 0;
    for (size_t i = 0; i < all_elems.size(); ++i)
        if (all_elems[i].depth == depth) ++count;
    return count;
}

// Count siblings before given index in all_elems
static size_t countSiblingsBefore(const std::vector<ElemInfo>& all_elems, size_t idx) {
    if (idx >= all_elems.size()) return 0;
    size_t depth = all_elems[idx].depth;
    size_t count = 0;
    for (size_t i = 0; i < idx; ++i)
        if (all_elems[i].depth == depth) ++count;
    return count;
}

// Find nearest preceding element at (depth-1) — the parent
static int findParentInAllElems(const std::vector<ElemInfo>& all_elems, size_t idx) {
    if (idx == 0 || idx > all_elems.size()) return -1;
    size_t pd = all_elems[idx].depth - 1;
    for (int i = static_cast<int>(idx) - 1; i >= 0; --i)
        if (all_elems[static_cast<size_t>(i)].depth == pd)
            return i;
    return -1;
}

// Find nearest preceding element at same depth — previous sibling
static int findPrevSiblingInAllElems(const std::vector<ElemInfo>& all_elems, size_t idx) {
    if (idx == 0 || idx > all_elems.size()) return -1;
    size_t d = all_elems[idx].depth;
    for (int i = static_cast<int>(idx) - 1; i >= 0; --i)
        if (all_elems[static_cast<size_t>(i)].depth == d)
            return i;
    return -1;
}

// ── Match::textContent ──────────────────────────────────────

std::string Match::textContent(const std::vector<SAXToken>& tokens) const {
    if (!token) return {};

    size_t start = static_cast<size_t>(token - tokens.data());
    if (start >= tokens.size()) return {};

    std::string result;
    int depth = 0;

    for (size_t i = start; i < tokens.size(); ++i) {
        const SAXToken& tok = tokens[i];
        if (tok.type == SAXToken::TAG_OPEN) {
            if (i != start) ++depth;
        } else if (tok.type == SAXToken::TAG_CLOSE) {
            if (depth == 0 && i != start) break;
            if (depth > 0) --depth;
        } else if (tok.type == SAXToken::TEXT) {
            result += tok.content;
        }
    }

    return DataExtractor::htmlEntityDecode(result);
}

// ── Match::attribute ────────────────────────────────────────

std::string Match::attribute(const std::vector<SAXToken>& tokens,
                              const std::string& attr_name) const
{
    (void)tokens;
    if (!token) return {};
    for (const auto& attr : token->attributes)
        if (iequal(attr.name, attr_name))
            return attr.value;
    return {};
}

// ── SelectorEngine::compile (single) ─────────────────────────

CompiledSelector DataExtractor::SelectorEngine::compile(const std::string& selector) {
    CompiledSelector cs;
    cs.original = selector;
    if (selector.empty()) return cs;

    const char* p = selector.data();
    const char* end = p + selector.size();

    auto parseCompound = [&](CompoundSelector& comp) -> bool {
        comp.simples.clear();

        if (p < end && (*p == '*' || std::isalpha(static_cast<unsigned char>(*p)))) {
            std::string tname;
            tname += *p;
            ++p;
            while (p < end && isTagChar(*p)) {
                tname += *p;
                ++p;
            }
            SimpleSelector ss;
            ss.type = SimpleSelector::TAG;
            ss.name = std::move(tname);
            comp.simples.push_back(std::move(ss));
        }

        while (p < end) {
            char c = *p;

            if (c == '#') {
                ++p;
                std::string id = parseIdentCss(p, end);
                if (id.empty()) return false;
                SimpleSelector ss;
                ss.type = SimpleSelector::ID;
                ss.name = std::move(id);
                comp.simples.push_back(std::move(ss));

            } else if (c == '.') {
                ++p;
                std::string cls = parseIdentCss(p, end);
                if (cls.empty()) return false;
                SimpleSelector ss;
                ss.type = SimpleSelector::CLASS;
                ss.name = std::move(cls);
                comp.simples.push_back(std::move(ss));

            } else if (c == '[') {
                ++p;
                p = skipWsCss(p, end);
                std::string aname;
                while (p < end && *p != ']' && *p != '=' && *p != '~' &&
                       *p != '|' && *p != '^' && *p != '$' && *p != '*' &&
                       !DataExtractor::SAXParser::isWhitespace(*p))
                {
                    aname += *p;
                    ++p;
                }
                if (aname.empty()) return false;
                p = skipWsCss(p, end);

                SimpleSelector ss;
                ss.type = SimpleSelector::ATTR_PRESENCE;
                ss.name = aname;

                if (p < end && *p == ']') {
                    ++p;
                    comp.simples.push_back(std::move(ss));
                    continue;
                }

                std::string op;
                if (p < end && (*p == '~' || *p == '|' || *p == '^' ||
                                *p == '$' || *p == '*'))
                {
                    op += *p;
                    ++p;
                    if (p < end && *p == '=') { op += '='; ++p; }
                    else return false;
                } else if (p < end && *p == '=') {
                    op = "=";
                    ++p;
                } else {
                    return false;
                }

                p = skipWsCss(p, end);

                std::string val;
                if (p < end && (*p == '"' || *p == '\'')) {
                    char q = *p;
                    ++p;
                    while (p < end && *p != q) { val += *p; ++p; }
                    if (p < end) ++p;
                } else {
                    while (p < end && *p != ']' && !DataExtractor::SAXParser::isWhitespace(*p)) {
                        val += *p;
                        ++p;
                    }
                }

                p = skipWsCss(p, end);
                if (p >= end || *p != ']') return false;
                ++p;

                if (op == "=")       ss.type = SimpleSelector::ATTR_EQUALS;
                else if (op == "~=") ss.type = SimpleSelector::ATTR_CONTAINS_WORD;
                else if (op == "^=") ss.type = SimpleSelector::ATTR_BEGINS;
                else if (op == "$=") ss.type = SimpleSelector::ATTR_ENDS;
                else if (op == "*=") ss.type = SimpleSelector::ATTR_CONTAINS;
                else return false;

                ss.value = std::move(val);
                comp.simples.push_back(std::move(ss));

            } else if (c == ':') {
                ++p;
                const char* saved2 = p;
                while (p < end && isIdentCharCss(*p)) ++p;
                std::string pseudo(saved2, static_cast<size_t>(p - saved2));
                if (p < end && *p == '(') {
                    ++p;
                    const char* cs = p;
                    int paren = 1;
                    while (p < end && paren > 0) {
                        if (*p == '(') ++paren;
                        else if (*p == ')') --paren;
                        ++p;
                    }
                    std::string content(cs, static_cast<size_t>((p - 1) - cs));
                    if (iequal(pseudo, "nth-child")) {
                        SimpleSelector ss;
                        ss.type = SimpleSelector::NTH_CHILD;
                        ss.name = std::move(content);
                        comp.simples.push_back(std::move(ss));
                    }
                }

            } else {
                break;
            }
        }

        return true;
    };

    CompoundSelector first;
    parseCompound(first);
    if (first.simples.empty()) {
        SimpleSelector ss;
        ss.type = SimpleSelector::TAG;
        ss.name = "*";
        first.simples.push_back(std::move(ss));
    }

    CompiledSelector::Part first_part;
    first_part.combinator = DESCENDANT;
    first_part.compound = std::move(first);
    cs.parts.push_back(std::move(first_part));

    while (p < end) {
        p = skipWsCss(p, end);
        if (p >= end) break;

        Combinator comb = DESCENDANT;

        if (*p == '>') { comb = CHILD; ++p; }
        else if (*p == '+') { comb = ADJACENT_SIBLING; ++p; }
        else if (*p == '~') { comb = GENERAL_SIBLING; ++p; }
        else {
            if (*p == '*' || std::isalpha(static_cast<unsigned char>(*p)) ||
                *p == '#' || *p == '.' || *p == '[' || *p == ':')
            {
                comb = DESCENDANT;
            } else {
                break;
            }
        }

        p = skipWsCss(p, end);
        if (p >= end) break;

        CompoundSelector next_compound;
        if (!parseCompound(next_compound)) break;
        if (next_compound.simples.empty()) {
            SimpleSelector ss;
            ss.type = SimpleSelector::TAG;
            ss.name = "*";
            next_compound.simples.push_back(std::move(ss));
        }

        CompiledSelector::Part part;
        part.combinator = comb;
        part.compound = std::move(next_compound);
        cs.parts.push_back(std::move(part));
    }

    return cs;
}

// ── SelectorEngine::compile (rules) ─────────────────────────

CompiledSelectors DataExtractor::SelectorEngine::compile(
    const std::vector<ExtractionRule>& rules)
{
    CompiledSelectors result;
    result.reserve(rules.size());
    for (const auto& rule : rules) {
        if (rule.type == ExtractionRule::CSS_SELECTOR)
            result.push_back(compile(rule.pattern));
    }
    return result;
}

// ── SelectorEngine::select (single selector) ────────────────

std::vector<Match> DataExtractor::SelectorEngine::select(
    const std::vector<SAXToken>& tokens,
    const CompiledSelector& selector)
{
    std::vector<Match> matches;
    if (selector.parts.empty()) return matches;

    std::vector<ElemInfo> all_elems;
    std::vector<ElemInfo> stack;
    all_elems.reserve(tokens.size() / 4);
    stack.reserve(128);

    for (size_t i = 0; i < tokens.size(); ++i) {
        const SAXToken& tok = tokens[i];

        if (tok.type == SAXToken::TAG_OPEN) {
            size_t cur_depth = stack.size();
            ElemInfo elem = buildElemInfo(tok, cur_depth);
            elem.token_index = i;

            const auto& last_part = selector.parts.back();
            size_t sib_pos = countSiblingsAtDepth(all_elems, cur_depth) + 1;

            if (compoundMatches(elem, last_part.compound, sib_pos)) {
                bool chain_ok = true;

                if (selector.parts.size() > 1) {
                    struct RefElem {
                        const ElemInfo* info;
                        size_t depth;
                        int all_pos;
                    };

                    RefElem ref;
                    ref.info = &elem;
                    ref.depth = cur_depth;
                    ref.all_pos = -1;

                    for (int pi = static_cast<int>(selector.parts.size()) - 2;
                         pi >= 0 && chain_ok; --pi)
                    {
                        Combinator comb = selector.parts[static_cast<size_t>(pi) + 1].combinator;
                        const CompoundSelector& target =
                            selector.parts[static_cast<size_t>(pi)].compound;

                        bool found_match = false;

                        if (comb == CHILD) {
                            const ElemInfo* parent = nullptr;
                            if (ref.all_pos == -1) {
                                if (!stack.empty())
                                    parent = &stack.back();
                            } else {
                                int pi2 = findParentInAllElems(all_elems,
                                    static_cast<size_t>(ref.all_pos));
                                if (pi2 >= 0)
                                    parent = &all_elems[static_cast<size_t>(pi2)];
                            }

                            if (parent) {
                                size_t psib = 0;
                                int ppos = -1;
                                for (size_t ai = 0; ai < all_elems.size(); ++ai) {
                                    if (&all_elems[ai] == parent) {
                                        psib = countSiblingsBefore(all_elems, ai) + 1;
                                        ppos = static_cast<int>(ai);
                                        break;
                                    }
                                }
                                if (compoundMatches(*parent, target, psib)) {
                                    ref.info = parent;
                                    ref.depth = parent->depth;
                                    ref.all_pos = ppos;
                                    found_match = true;
                                }
                            }

                        } else if (comb == DESCENDANT) {
                            const ElemInfo* found = nullptr;
                            int found_pos = -1;

                            if (ref.all_pos == -1) {
                                for (size_t si = stack.size(); si > 0; --si) {
                                    const ElemInfo* anc = &stack[si - 1];
                                    size_t asib = 0;
                                    int apos = -1;
                                    for (size_t ai = 0; ai < all_elems.size(); ++ai) {
                                        if (&all_elems[ai] == anc) {
                                            asib = countSiblingsBefore(all_elems, ai) + 1;
                                            apos = static_cast<int>(ai);
                                            break;
                                        }
                                    }
                                    if (compoundMatches(*anc, target, asib)) {
                                        found = anc;
                                        found_pos = apos;
                                        break;
                                    }
                                }
                            } else {
                                size_t ridx = static_cast<size_t>(ref.all_pos);
                                for (size_t ai = ridx; ai > 0; --ai) {
                                    if (all_elems[ai - 1].depth < ref.depth) {
                                        size_t asib = countSiblingsBefore(all_elems, ai - 1) + 1;
                                        if (compoundMatches(all_elems[ai - 1], target, asib)) {
                                            found = &all_elems[ai - 1];
                                            found_pos = static_cast<int>(ai) - 1;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (found) {
                                ref.info = found;
                                ref.depth = found->depth;
                                ref.all_pos = found_pos;
                                found_match = true;
                            }

                        } else if (comb == ADJACENT_SIBLING) {
                            const ElemInfo* sib = nullptr;
                            int sib_pos2 = -1;

                            if (ref.all_pos == -1) {
                                size_t cd = cur_depth;
                                for (size_t ai = all_elems.size(); ai > 0; --ai) {
                                    if (all_elems[ai - 1].depth == cd) {
                                        size_t ss = countSiblingsBefore(all_elems, ai - 1) + 1;
                                        if (compoundMatches(all_elems[ai - 1], target, ss)) {
                                            sib = &all_elems[ai - 1];
                                            sib_pos2 = static_cast<int>(ai) - 1;
                                        }
                                        break;
                                    }
                                }
                            } else {
                                int psi = findPrevSiblingInAllElems(all_elems,
                                    static_cast<size_t>(ref.all_pos));
                                if (psi >= 0) {
                                    size_t ss = countSiblingsBefore(all_elems,
                                        static_cast<size_t>(psi)) + 1;
                                    if (compoundMatches(all_elems[static_cast<size_t>(psi)],
                                            target, ss)) {
                                        sib = &all_elems[static_cast<size_t>(psi)];
                                        sib_pos2 = psi;
                                    }
                                }
                            }

                            if (sib) {
                                ref.info = sib;
                                ref.depth = sib->depth;
                                ref.all_pos = sib_pos2;
                                found_match = true;
                            }

                        } else if (comb == GENERAL_SIBLING) {
                            const ElemInfo* sib = nullptr;
                            int sib_pos2 = -1;

                            if (ref.all_pos == -1) {
                                size_t cd = cur_depth;
                                for (size_t ai = all_elems.size(); ai > 0; --ai) {
                                    if (all_elems[ai - 1].depth == cd) {
                                        size_t ss = countSiblingsBefore(all_elems, ai - 1) + 1;
                                        if (compoundMatches(all_elems[ai - 1], target, ss)) {
                                            sib = &all_elems[ai - 1];
                                            sib_pos2 = static_cast<int>(ai) - 1;
                                            break;
                                        }
                                    }
                                }
                            } else {
                                size_t ridx = static_cast<size_t>(ref.all_pos);
                                for (size_t ai = ridx; ai > 0; --ai) {
                                    if (all_elems[ai - 1].depth == ref.depth) {
                                        size_t ss = countSiblingsBefore(all_elems, ai - 1) + 1;
                                        if (compoundMatches(all_elems[ai - 1], target, ss)) {
                                            sib = &all_elems[ai - 1];
                                            sib_pos2 = static_cast<int>(ai) - 1;
                                            break;
                                        }
                                    }
                                }
                            }

                            if (sib) {
                                ref.info = sib;
                                ref.depth = sib->depth;
                                ref.all_pos = sib_pos2;
                                found_match = true;
                            }
                        }

                        if (!found_match) chain_ok = false;
                    }
                }

                if (chain_ok) {
                    Match m;
                    m.token = &tokens[i];
                    m.selector_text = selector.original;
                    m.depth = cur_depth;
                    matches.push_back(m);
                }
            }

            // Push element after matching
            all_elems.push_back(elem);
            stack.push_back(std::move(elem));

        } else if (tok.type == SAXToken::TAG_CLOSE) {
            if (!stack.empty())
                stack.pop_back();
        }
    }

    return matches;
}

// ── SelectorEngine::select (multiple selectors) ─────────────

std::vector<Match> DataExtractor::SelectorEngine::select(
    const std::vector<SAXToken>& tokens,
    const CompiledSelectors& selectors)
{
    std::vector<Match> all_matches;
    for (const auto& sel : selectors) {
        auto m = select(tokens, sel);
        all_matches.insert(all_matches.end(), m.begin(), m.end());
    }
    return all_matches;
}
// ── File-local helpers ──────────────────────────────────────────────────

namespace {

static bool isJsonSpace(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static void putUTF8(std::string& s, uint32_t cp) {
    if (cp < 0x80) {
        s += static_cast<char>(cp);
    } else if (cp < 0x800) {
        s += static_cast<char>(0xC0 | (cp >> 6));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x10000) {
        s += static_cast<char>(0xE0 | (cp >> 12));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp < 0x110000) {
        s += static_cast<char>(0xF0 | (cp >> 18));
        s += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        s += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        s += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

static uint8_t hexVal(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(c - 'A' + 10);
    return 0xFF;
}

static JSONToken makeToken(JSONToken::Type t, std::string v, size_t off, size_t len) {
    JSONToken tk;
    tk.type   = t;
    tk.value  = std::move(v);
    tk.offset = off;
    tk.length = len;
    return tk;
}

static JSONToken makeError(const char* msg, size_t off) {
    return makeToken(JSONToken::ERROR, std::string(msg), off, 0);
}

// ── Number validation (JSON grammar) ────────────────────────────────────

static bool isValidNumber(std::string_view raw) {
    size_t i = 0;
    size_t n = raw.size();
    if (n == 0) return false;

    if (raw[i] == '-') {
        ++i;
        if (i >= n) return false;
    }

    if (raw[i] == '0') {
        ++i;
    } else if (raw[i] >= '1' && raw[i] <= '9') {
        ++i;
        while (i < n && raw[i] >= '0' && raw[i] <= '9') ++i;
    } else {
        return false;
    }

    if (i < n && raw[i] == '.') {
        ++i;
        if (i >= n || raw[i] < '0' || raw[i] > '9') return false;
        while (i < n && raw[i] >= '0' && raw[i] <= '9') ++i;
    }

    if (i < n && (raw[i] == 'e' || raw[i] == 'E')) {
        ++i;
        if (i < n && (raw[i] == '+' || raw[i] == '-')) ++i;
        if (i >= n || raw[i] < '0' || raw[i] > '9') return false;
        while (i < n && raw[i] >= '0' && raw[i] <= '9') ++i;
    }

    return i == n;
}

// ── Parse JSON string (handles escape sequences) ────────────────────────
// p is updated to point past the closing quote on success.
// Returns true on success, false on malformed input.

static bool parseString(const char*& p, const char* end, std::string& out) {
    out.clear();
    if (p >= end || *p != '"') return false;
    ++p; // skip opening quote

    while (p < end) {
        char c = *p;

        if (c == '"') {
            ++p;
            return true;
        }

        if (c == '\\') {
            ++p;
            if (p >= end) return false;
            // Each case below advances p to point past its own escape sequence.
            // Then we 'continue' to skip the normal ++p at the bottom of the loop.
            switch (*p) {

            case '"':  out += '"';  ++p; break;
            case '\\': out += '\\'; ++p; break;
            case '/':  out += '/';  ++p; break;
            case 'b':  out += '\b'; ++p; break;
            case 'f':  out += '\f'; ++p; break;
            case 'n':  out += '\n'; ++p; break;
            case 'r':  out += '\r'; ++p; break;
            case 't':  out += '\t'; ++p; break;

            case 'u': {
                ++p; // skip 'u', now at first hex digit
                if (end - p < 4) return false;

                uint32_t cp = 0;
                for (int k = 0; k < 4; ++k) {
                    uint8_t hv = hexVal(p[k]);
                    if (hv == 0xFF) return false;
                    cp = (cp << 4) | hv;
                }
                p += 4; // past hex digits

                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (end - p >= 6 && p[0] == '\\' && p[1] == 'u') {
                        uint32_t lo = 0;
                        bool lo_ok = true;
                        for (int k = 0; k < 4; ++k) {
                            uint8_t hv = hexVal(p[2 + k]);
                            if (hv == 0xFF) { lo_ok = false; break; }
                            lo = (lo << 4) | hv;
                        }
                        if (lo_ok && lo >= 0xDC00 && lo <= 0xDFFF) {
                            uint32_t codepoint = 0x10000
                                + (cp - 0xD800) * 0x400
                                + (lo - 0xDC00);
                            putUTF8(out, codepoint);
                            p += 6;
                            break;
                        }
                    }
                    putUTF8(out, 0xFFFD);
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    putUTF8(out, 0xFFFD);
                } else {
                    putUTF8(out, cp);
                }
                break;
            }

            default:
                out += *p;
                ++p;
                break;
            }

            continue;
        }

        if (static_cast<unsigned char>(c) < 0x20) return false;

        out += c;
        ++p;
    }

    return false; // unclosed string
}

// ── Split JSONPath pattern into parts ───────────────────────────────────

static std::vector<std::string> splitPattern(std::string_view pat) {
    std::vector<std::string> parts;
    if (pat.empty()) return parts;

    size_t pos = 0;

    if (pat[0] == '$') {
        parts.push_back("$");
        pos = 1;
        // skip single dot only if NOT followed by another dot (deep scan)
        if (pos < pat.size() && pat[pos] == '.'
            && (pos + 1 >= pat.size() || pat[pos + 1] != '.'))
            ++pos;
    }

    while (pos < pat.size()) {
        if (pos + 1 < pat.size() && pat[pos] == '.' && pat[pos + 1] == '.') {
            pos += 2;
            size_t start = pos;
            while (pos < pat.size() && pat[pos] != '.') ++pos;
            parts.push_back(std::string("..") + std::string(pat.substr(start, pos - start)));
            if (pos < pat.size() && pat[pos] == '.') ++pos;
            continue;
        }

        if (pat[pos] == '.') {
            ++pos;
            continue;
        }

        size_t start = pos;
        while (pos < pat.size() && pat[pos] != '.') ++pos;
        std::string seg(pat.substr(start, pos - start));
        if (seg.empty()) continue;

        if (seg[0] == '[') {
            parts.push_back(seg);
        } else {
            size_t br = seg.find('[');
            if (br != std::string::npos) {
                parts.push_back(seg.substr(0, br));
                parts.push_back(seg.substr(br));
            } else {
                parts.push_back(seg);
            }
        }

        if (pos < pat.size() && pat[pos] == '.') ++pos;
    }

    return parts;
}

// ── Path matching ───────────────────────────────────────────────────────

static bool pathMatches(const std::vector<std::string>& pat_parts,
                        const std::vector<std::string>& actual_parts) {
    size_t pi = 0, ai = 0;

    while (pi < pat_parts.size() && ai < actual_parts.size()) {
        const std::string& pat = pat_parts[pi];

        // deep scan (..key)
        if (pat.size() >= 2 && pat[0] == '.' && pat[1] == '.') {
            std::string target = pat.substr(2);
            if (target.empty()) {
                ++pi;
                continue;
            }
            bool found = false;
            while (ai < actual_parts.size()) {
                if (actual_parts[ai] == target) {
                    ++ai;
                    found = true;
                    break;
                }
                ++ai;
            }
            if (!found) return false;
            ++pi;
            continue;
        }

        // key wildcard (matches any string key)
        if (pat == "*") {
            if (actual_parts[ai].empty() || actual_parts[ai][0] == '[')
                return false;
            ++pi; ++ai;
            continue;
        }

        // array wildcard
        if (pat == "[*]") {
            if (actual_parts[ai].size() < 3 ||
                actual_parts[ai][0] != '[' ||
                actual_parts[ai].back() != ']')
                return false;
            ++pi; ++ai;
            continue;
        }

        if (pat != actual_parts[ai]) return false;
        ++pi; ++ai;
    }

    return pi == pat_parts.size() && ai == actual_parts.size();
}

} // anonymous namespace

// ── DataExtractor::JSONStreamer::tokenize ──────────────────────────────

std::vector<JSONToken> DataExtractor::JSONStreamer::tokenize(std::string_view json) {
    std::vector<JSONToken> tokens;
    const char* p  = json.data();
    const char* end = p + json.size();

    // context stack for KEY vs STRING disambiguation
    struct Ctx { bool isObj; bool expectKey; };
    std::vector<Ctx> ctxStack;

    while (p < end) {
        while (p < end && isJsonSpace(*p)) ++p;
        if (p >= end) break;

        size_t startOff = static_cast<size_t>(p - json.data());
        char c = *p;

        switch (c) {

        case '{':
            tokens.push_back(makeToken(JSONToken::OBJECT_START, {}, startOff, 1));
            ctxStack.push_back({true, true});
            ++p;
            break;

        case '}':
            tokens.push_back(makeToken(JSONToken::OBJECT_END, {}, startOff, 1));
            if (!ctxStack.empty()) ctxStack.pop_back();
            ++p;
            break;

        case '[':
            tokens.push_back(makeToken(JSONToken::ARRAY_START, {}, startOff, 1));
            ctxStack.push_back({false, false});
            ++p;
            break;

        case ']':
            tokens.push_back(makeToken(JSONToken::ARRAY_END, {}, startOff, 1));
            if (!ctxStack.empty()) ctxStack.pop_back();
            ++p;
            break;

        case ':':
            tokens.push_back(makeToken(JSONToken::COLON, {}, startOff, 1));
            if (!ctxStack.empty() && ctxStack.back().isObj)
                ctxStack.back().expectKey = false;
            ++p;
            break;

        case ',': {
            // comma is only valid after a value
            if (!tokens.empty()) {
                JSONToken::Type prev = tokens.back().type;
                if (prev == JSONToken::OBJECT_START ||
                    prev == JSONToken::ARRAY_START  ||
                    prev == JSONToken::COLON        ||
                    prev == JSONToken::COMMA        ||
                    prev == JSONToken::KEY) {
                    tokens.push_back(makeError("unexpected comma", startOff));
                    return tokens;
                }
            }
            tokens.push_back(makeToken(JSONToken::COMMA, {}, startOff, 1));
            if (!ctxStack.empty() && ctxStack.back().isObj)
                ctxStack.back().expectKey = true;
            ++p;
            break;
        }

        case '"': {
            std::string val;
            bool ok = parseString(p, end, val);
            size_t strLen = static_cast<size_t>(p - json.data()) - startOff;
            if (!ok) {
                tokens.push_back(makeError("unclosed string", startOff));
                return tokens;
            }
            bool isKey = !ctxStack.empty()
                      && ctxStack.back().isObj
                      && ctxStack.back().expectKey;
            if (isKey)
                ctxStack.back().expectKey = false;

            tokens.push_back(makeToken(
                isKey ? JSONToken::KEY : JSONToken::STRING,
                std::move(val), startOff, strLen));
            break;
        }

        case '-':
        case '0': case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9': {
            ++p;

            if (c == '-') {
                if (p >= end || (*p != '0' && (*p < '1' || *p > '9'))) {
                    // "-" alone or "-" followed by non-digit
                    std::string_view raw(json.data() + startOff, 1);
                    tokens.push_back(makeError("invalid number", startOff));
                    return tokens;
                }
                if (*p == '0') ++p;
                else {
                    while (p < end && *p >= '0' && *p <= '9') ++p;
                }
            } else if (c == '0') {
                // single 0
            } else {
                while (p < end && *p >= '0' && *p <= '9') ++p;
            }

            if (p < end && *p == '.') {
                ++p;
                if (p >= end || *p < '0' || *p > '9') {
                    tokens.push_back(makeError("invalid number", startOff));
                    return tokens;
                }
                while (p < end && *p >= '0' && *p <= '9') ++p;
            }

            if (p < end && (*p == 'e' || *p == 'E')) {
                ++p;
                if (p < end && (*p == '+' || *p == '-')) ++p;
                if (p >= end || *p < '0' || *p > '9') {
                    tokens.push_back(makeError("invalid number", startOff));
                    return tokens;
                }
                while (p < end && *p >= '0' && *p <= '9') ++p;
            }

            std::string_view raw(json.data() + startOff,
                                static_cast<size_t>(p - json.data()) - startOff);
            if (!isValidNumber(raw)) {
                tokens.push_back(makeError("invalid number", startOff));
                return tokens;
            }
            tokens.push_back(makeToken(JSONToken::NUMBER, std::string(raw),
                                       startOff, raw.size()));
            break;
        }

        case 't': {
            if (static_cast<size_t>(end - p) >= 4
                && p[1] == 'r' && p[2] == 'u' && p[3] == 'e') {
                tokens.push_back(makeToken(JSONToken::BOOLEAN, "true", startOff, 4));
                p += 4;
            } else {
                tokens.push_back(makeError("unexpected character", startOff));
                return tokens;
            }
            break;
        }

        case 'f': {
            if (static_cast<size_t>(end - p) >= 5
                && p[1] == 'a' && p[2] == 'l' && p[3] == 's' && p[4] == 'e') {
                tokens.push_back(makeToken(JSONToken::BOOLEAN, "false", startOff, 5));
                p += 5;
            } else {
                tokens.push_back(makeError("unexpected character", startOff));
                return tokens;
            }
            break;
        }

        case 'n': {
            if (static_cast<size_t>(end - p) >= 4
                && p[1] == 'u' && p[2] == 'l' && p[3] == 'l') {
                tokens.push_back(makeToken(JSONToken::NULL_, "null", startOff, 4));
                p += 4;
            } else {
                tokens.push_back(makeError("unexpected character", startOff));
                return tokens;
            }
            break;
        }

        default:
            tokens.push_back(makeError("unexpected character", startOff));
            return tokens;
        }
    }

    return tokens;
}

// ── DataExtractor::JSONStreamer::parse ─────────────────────────────────

void DataExtractor::JSONStreamer::parse(
    std::string_view json,
    const std::vector<std::string>& paths,
    JSONValueCallback cb)
{
    if (paths.empty()) return;

    std::vector<std::vector<std::string>> compiled;
    compiled.reserve(paths.size());
    for (const auto& p : paths)
        compiled.push_back(splitPattern(p));

    std::vector<JSONToken> tokens = tokenize(json);
    if (tokens.empty()) return;

    struct Frame { bool isObj; size_t arrIdx; };
    std::vector<Frame> stack;
    std::vector<std::string> pathParts;
    pathParts.push_back("$");

    for (size_t ti = 0; ti < tokens.size(); ++ti) {
        const JSONToken& tok = tokens[ti];

        switch (tok.type) {

        case JSONToken::KEY:
            if (!pathParts.empty())
                pathParts.back() = tok.value;
            break;

        case JSONToken::OBJECT_START:
            pathParts.push_back("");
            stack.push_back({true, 0});
            break;

        case JSONToken::OBJECT_END:
            if (!stack.empty()) stack.pop_back();
            if (!pathParts.empty()) pathParts.pop_back();
            break;

        case JSONToken::ARRAY_START:
            pathParts.push_back("[0]");
            stack.push_back({false, 0});
            break;

        case JSONToken::ARRAY_END:
            if (!stack.empty()) stack.pop_back();
            if (!pathParts.empty()) pathParts.pop_back();
            break;

        case JSONToken::COMMA:
            if (!stack.empty() && !stack.back().isObj) {
                ++stack.back().arrIdx;
                if (!pathParts.empty())
                    pathParts.back() = "["
                        + std::to_string(stack.back().arrIdx) + "]";
            }
            break;

        case JSONToken::STRING:
        case JSONToken::NUMBER:
        case JSONToken::BOOLEAN:
        case JSONToken::NULL_:
            for (const auto& pat : compiled) {
                if (pathMatches(pat, pathParts)) {
                    cb(pathParts, tok);
                    break;
                }
            }
            break;

        default:
            break;
        }
    }
}

// ── DataExtractor::dispatchContentType ────────────────────────

std::string DataExtractor::dispatchContentType(const std::string& ct) {
    std::string lower;
    lower.reserve(ct.size());
    for (char c : ct) {
        if (c == ';') break;
        lower += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    while (!lower.empty() && (lower.back() == ' ' || lower.back() == '\t'))
        lower.pop_back();

    if (lower == "text/html") return "html";
    if (lower == "application/json") return "json";
    if (lower == "text/json") return "json";
    if (lower == "application/xml" || lower == "text/xml") return "html";
    if (lower == "text/plain") return "heuristic";
    return "html";
}

// ── DataExtractor::extractHtml ─────────────────────────────────

ExtractionResult DataExtractor::extractHtml(const ExtractionPlan& plan,
                                             std::string_view data)
{
    ExtractionResult result;
    result.success = true;

    SAXParser parser;
    SelectorEngine engine;
    CompiledSelectors compiled = engine.compile(plan.rules);

    auto tokens = parser.parse(data);
    result.bytes_processed = data.size();

    auto matches = engine.select(tokens, compiled);

    for (const auto& rule : plan.rules) {
        if (rule.type != ExtractionRule::CSS_SELECTOR) continue;
        CompiledSelector cs = engine.compile(rule.pattern);

        std::vector<Match> rule_matches;
        for (const auto& m : matches) {
            if (m.selector_text == rule.pattern)
                rule_matches.push_back(m);
        }

        for (const auto& m : rule_matches) {
            std::string val;
            if (rule.attribute.empty() || rule.attribute == "text")
                val = m.textContent(tokens);
            else
                val = m.attribute(tokens, rule.attribute);
            if (!val.empty() || rule.multiple)
                result.fields[rule.output_name].push_back(val);
            if (!rule.multiple) break;
        }
    }

    return result;
}

// ── DataExtractor::extractJson ─────────────────────────────────

ExtractionResult DataExtractor::extractJson(const ExtractionPlan& plan,
                                             std::string_view data)
{
    ExtractionResult result;
    result.success = true;

    JSONStreamer streamer;
    std::vector<std::string> json_paths;
    for (const auto& rule : plan.rules)
        if (rule.type == ExtractionRule::JSON_PATH)
            json_paths.push_back(rule.pattern);

    auto cb = [&](const std::vector<std::string>& path, const JSONToken& value) {
        std::string full_path = "$";
        for (const auto& seg : path) {
            if (seg == "$") continue;
            if (seg[0] == '[') full_path += seg;
            else full_path += "." + seg;
        }
        for (const auto& rule : plan.rules) {
            if (rule.type != ExtractionRule::JSON_PATH) continue;
            if (full_path == rule.pattern || full_path.rfind(rule.pattern, 0) == 0) {
                result.fields[rule.output_name].push_back(value.value);
                if (!rule.multiple) break;
            }
        }
    };

    streamer.parse(data, json_paths, cb);
    result.bytes_processed = data.size();

    return result;
}

// ── DataExtractor::extractHeuristic ────────────────────────────

ExtractionResult DataExtractor::extractHeuristic(const ExtractionPlan& plan,
                                                  std::string_view data)
{
    ExtractionResult result;
    result.success = true;
    result.bytes_processed = data.size();
    (void)plan;

    HeuristicEngine he;
    auto patterns = he.discover(data);

    for (const auto& dp : patterns) {
        result.fields[dp.suggested_type].push_back(dp.sample);
        result.fields["_confidence"].push_back(
            std::to_string(dp.confidence));
    }

    return result;
}

// ── DataExtractor::extract ─────────────────────────────────────

ExtractionResult DataExtractor::extract(const ExtractionPlan& plan,
                                         std::string_view data,
                                         const std::string& content_type)
{
    ExtractionResult result;
    std::string route = dispatchContentType(content_type);

    auto start = std::chrono::steady_clock::now();

    if (route == "html") {
        result = extractHtml(plan, data);
    } else if (route == "json") {
        result = extractJson(plan, data);
    } else {
        result = extractHeuristic(plan, data);
    }

    auto end = std::chrono::steady_clock::now();
    result.elapsed_ms = std::chrono::duration<double, std::milli>(end - start).count();
    result.success = !result.fields.empty();

    return result;
}

// ── DataExtractor::HeuristicEngine::discover ──────────────────

std::vector<DiscoveredPattern> DataExtractor::HeuristicEngine::discover(
    std::string_view data)
{
    std::vector<DiscoveredPattern> results;
    if (data.empty()) return results;

    struct PatternDef {
        const char* regex_str;
        const char* type;
        double confidence_base;
    };

    static const PatternDef patterns[] = {
        {"https?://[^\\s<>\"'\\]]+", "url", 0.8},
        {"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}", "email", 0.7},
        {"\\$?\\d+(?:\\.\\d{2})?", "price", 0.5},
        {"\\d{4}-\\d{2}-\\d{2}", "date", 0.8},
        {"<h[1-6][^>]*>(.*?)</h[1-6]>", "heading", 0.3},
    };

    for (const auto& pd : patterns) {
        try {
            std::regex re(pd.regex_str);
            std::cmatch m;
            if (std::regex_search(data.data(), data.data() + data.size(), m, re)) {
                DiscoveredPattern dp;
                dp.regex_str = pd.regex_str;
                dp.sample = m[0].str();
                dp.confidence = pd.confidence_base;
                if (dp.sample.size() > 100)
                    dp.sample = dp.sample.substr(0, 100);
                dp.suggested_type = pd.type;
                results.push_back(std::move(dp));
            }
        } catch (...) {
            continue;
        }
    }

    return results;
}

// ── DataExtractor::detectCharset ──────────────────────────────

std::string DataExtractor::detectCharset(std::string_view data,
                                          const std::string& content_type)
{
    if (!content_type.empty()) {
        size_t cs = content_type.find("charset=");
        if (cs != std::string::npos) {
            size_t start = cs + 8;
            size_t end = content_type.find(';', start);
            if (end == std::string::npos) end = content_type.size();
            std::string charset(content_type.substr(start, end - start));
            while (!charset.empty() && (charset.front() == ' ' || charset.front() == '"'))
                charset.erase(0, 1);
            while (!charset.empty() && (charset.back() == ' ' || charset.back() == '"'))
                charset.pop_back();
            return charset;
        }
    }

    if (data.size() >= 3 &&
        static_cast<unsigned char>(data[0]) == 0xEF &&
        static_cast<unsigned char>(data[1]) == 0xBB &&
        static_cast<unsigned char>(data[2]) == 0xBF)
        return "utf-8";

    if (data.size() >= 2 &&
        static_cast<unsigned char>(data[0]) == 0xFE &&
        static_cast<unsigned char>(data[1]) == 0xFF)
        return "utf-16be";

    if (data.size() >= 2 &&
        static_cast<unsigned char>(data[0]) == 0xFF &&
        static_cast<unsigned char>(data[1]) == 0xFE)
        return "utf-16le";

    std::string_view sv(data.data(), data.size() < 2048 ? data.size() : 2048);
    for (size_t i = 0; i + 14 < sv.size(); ++i) {
        if ((sv[i] == '<' || sv[i] == '<') &&
            (i + 14 < sv.size()) &&
            std::tolower(static_cast<unsigned char>(sv[i+1])) == 'm' &&
            std::tolower(static_cast<unsigned char>(sv[i+2])) == 'e' &&
            std::tolower(static_cast<unsigned char>(sv[i+3])) == 't' &&
            std::tolower(static_cast<unsigned char>(sv[i+4])) == 'a')
        {
            std::string_view meta_section(sv.data() + i, sv.size() - i);
            size_t cs = meta_section.find("charset=");
            if (cs != std::string::npos) {
                cs += 8;
                size_t end = cs;
                while (end < meta_section.size() &&
                       meta_section[end] != '"' &&
                       meta_section[end] != '\'' &&
                       meta_section[end] != '>' &&
                       meta_section[end] != ';' &&
                       !DataExtractor::SAXParser::isWhitespace(meta_section[end]))
                    ++end;
                if (end > cs)
                    return std::string(meta_section.substr(cs, end - cs));
            }
        }
    }

    return "utf-8";
}

// ── DataExtractor::convertToUtf8 ─────────────────────────────

std::string DataExtractor::convertToUtf8(std::string_view data,
                                          const std::string& from_charset)
{
    if (from_charset == "utf-8" || from_charset == "UTF-8")
        return std::string(data);

#ifdef HAS_ICONV
    iconv_t cd = iconv_open("UTF-8", from_charset.c_str());
    if (cd == reinterpret_cast<iconv_t>(-1))
        return std::string(data);

    size_t in_bytes = data.size();
    size_t out_bytes = in_bytes * 4 + 4;
    std::string result(out_bytes, '\0');
    char* in_buf = const_cast<char*>(data.data());
    char* out_buf = &result[0];
    size_t rc = iconv(cd, &in_buf, &in_bytes, &out_buf, &out_bytes);
    iconv_close(cd);

    if (rc == static_cast<size_t>(-1))
        return std::string(data);

    result.resize(result.size() - out_bytes);
    return result;
#else
    (void)from_charset;
    std::string result;
    result.reserve(data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        char c = data[i];
        if (static_cast<unsigned char>(c) < 0x80) {
            result += c;
        } else {
            result += static_cast<char>(0xC0 | (static_cast<unsigned char>(c) >> 6));
            result += static_cast<char>(0x80 | (static_cast<unsigned char>(c) & 0x3F));
        }
    }
    return result;
#endif
}
