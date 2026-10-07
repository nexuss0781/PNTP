#include "pntp/http1_parser.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <sstream>

// ─── Constructor / Destructor ────────────────────────────────────────

Http1Parser::Http1Parser() = default;
Http1Parser::~Http1Parser() = default;

// ─── Reset ───────────────────────────────────────────────────────────

void Http1Parser::reset() {
    state_ = H1_STATE_REQUEST_LINE;
    is_request_ = true;
    buffer_.clear();
    line_buffer_.clear();
    request_ = Http1Request{};
    response_ = Http1Response{};
    headers_.clear();
    body_.clear();
    content_length_ = 0;
    body_bytes_read_ = 0;
    has_content_length_ = false;
    has_transfer_encoding_chunked_ = false;
    chunk_size_remaining_ = 0;
    chunk_crlf_remaining_ = 0;
    chunk_line_buffer_.clear();
    connection_close_ = false;
    connection_keep_alive_ = false;
    upgrade_info_ = Http1UpgradeInfo{};
    expect_continue_ = false;
}

// ─── Feed ────────────────────────────────────────────────────────────

size_t Http1Parser::feed(const uint8_t* data, size_t len) {
    if (state_ == H1_STATE_COMPLETE || state_ == H1_STATE_ERROR) return 0;
    if (!data || len == 0) return 0;

    size_t consumed = 0;

    while (consumed < len && state_ != H1_STATE_COMPLETE &&
           state_ != H1_STATE_ERROR) {

        switch (state_) {

        // ── Request Line ───────────────────────────────────────────
        case H1_STATE_REQUEST_LINE: {
            size_t line_end = findLineEnd(data + consumed, len - consumed);
            if (line_end == std::string::npos) {
                line_buffer_.append(reinterpret_cast<const char*>(data + consumed),
                                    len - consumed);
                if (line_buffer_.size() > MAX_LINE_SIZE) {
                    state_ = H1_STATE_ERROR;
                    return consumed;
                }
                consumed = len;
                // \r\n may straddle the feed boundary; check after appending
                if (line_buffer_.size() >= 2 &&
                    line_buffer_[line_buffer_.size() - 2] == '\r' &&
                    line_buffer_.back() == '\n') {
                    std::string line = line_buffer_.substr(0, line_buffer_.size() - 2);
                    line_buffer_.clear();
                    if (line.rfind("HTTP/", 0) == 0) {
                        if (!parseResponseLine(line)) {
                            state_ = H1_STATE_ERROR;
                            return consumed;
                        }
                        is_request_ = false;
                    } else {
                        if (!parseRequestLine(line)) {
                            state_ = H1_STATE_ERROR;
                            return consumed;
                        }
                        is_request_ = true;
                    }
                    state_ = H1_STATE_HEADERS;
                }
                break;
            }
            line_buffer_.append(reinterpret_cast<const char*>(data + consumed),
                                line_end);
            consumed += line_end + 2; // skip \r\n

            // Auto-detect responses: a line starting with "HTTP/" is a status line
            if (line_buffer_.rfind("HTTP/", 0) == 0) {
                if (!parseResponseLine(line_buffer_)) {
                    state_ = H1_STATE_ERROR;
                    return consumed;
                }
                is_request_ = false;
            } else {
                if (!parseRequestLine(line_buffer_)) {
                    state_ = H1_STATE_ERROR;
                    return consumed;
                }
                is_request_ = true;
            }
            line_buffer_.clear();
            state_ = H1_STATE_HEADERS;
            break;
        }

        // ── Response Line ──────────────────────────────────────────
        case H1_STATE_RESPONSE_LINE: {
            size_t line_end = findLineEnd(data + consumed, len - consumed);
            if (line_end == std::string::npos) {
                line_buffer_.append(reinterpret_cast<const char*>(data + consumed),
                                    len - consumed);
                if (line_buffer_.size() > MAX_LINE_SIZE) {
                    state_ = H1_STATE_ERROR;
                    return consumed;
                }
                consumed = len;
                // \r\n may straddle the feed boundary; check after appending
                if (line_buffer_.size() >= 2 &&
                    line_buffer_[line_buffer_.size() - 2] == '\r' &&
                    line_buffer_.back() == '\n') {
                    std::string line = line_buffer_.substr(0, line_buffer_.size() - 2);
                    line_buffer_.clear();
                    if (!parseResponseLine(line)) {
                        state_ = H1_STATE_ERROR;
                        return consumed;
                    }
                    is_request_ = false;
                    state_ = H1_STATE_HEADERS;
                }
                break;
            }
            line_buffer_.append(reinterpret_cast<const char*>(data + consumed),
                                line_end);
            consumed += line_end + 2;

            if (!parseResponseLine(line_buffer_)) {
                state_ = H1_STATE_ERROR;
                return consumed;
            }
            line_buffer_.clear();
            is_request_ = false;
            state_ = H1_STATE_HEADERS;
            break;
        }

        // ── Headers ────────────────────────────────────────────────
        case H1_STATE_HEADERS: {
            size_t line_end = findLineEnd(data + consumed, len - consumed);
            if (line_end == std::string::npos) {
                line_buffer_.append(reinterpret_cast<const char*>(data + consumed),
                                    len - consumed);
                if (line_buffer_.size() > MAX_HEADER_SIZE) {
                    state_ = H1_STATE_ERROR;
                    return consumed;
                }
                consumed = len;
                // \r\n may straddle the feed boundary; check after appending
                if (line_buffer_.size() >= 2 &&
                    line_buffer_[line_buffer_.size() - 2] == '\r' &&
                    line_buffer_.back() == '\n') {
                    std::string line = line_buffer_.substr(0, line_buffer_.size() - 2);
                    line_buffer_.clear();

                    // Empty line = end of headers
                    if (line.empty()) {
                        processSpecialHeaders();
                        determineBodyState();
                        break;
                    }

                    // Handle obs-fold (line starts with space or tab)
                    if ((!line.empty() && (line[0] == ' ' || line[0] == '\t')) &&
                        !headers_.empty()) {
                        headers_.back().value += line;
                        break;
                    }

                    if (!parseHeaderLine(line)) {
                        state_ = H1_STATE_ERROR;
                        return consumed;
                    }
                }
                break;
            }

            line_buffer_.append(reinterpret_cast<const char*>(data + consumed),
                                line_end);
            std::string line = line_buffer_;
            line_buffer_.clear();
            consumed += line_end + 2;

            // Reject oversized complete header lines (RFC 7230 safety)
            if (line.size() > MAX_HEADER_SIZE) {
                state_ = H1_STATE_ERROR;
                return consumed;
            }

            // Empty line = end of headers
            if (line.empty()) {
                processSpecialHeaders();
                determineBodyState();
                break;
            }

            // Handle obs-fold (line starts with space or tab)
            if ((!line.empty() && (line[0] == ' ' || line[0] == '\t')) &&
                !headers_.empty()) {
                headers_.back().value += line;
                break;
            }

            if (!parseHeaderLine(line)) {
                state_ = H1_STATE_ERROR;
                return consumed;
            }
            break;
        }

        // ── Body: Content-Length ───────────────────────────────────
        case H1_STATE_BODY_CONTENT_LENGTH: {
            size_t n = readContentLengthBody(data + consumed, len - consumed);
            consumed += n;
            break;
        }

        // ── Body: Chunked ──────────────────────────────────────────
        case H1_STATE_BODY_CHUNKED:
        case H1_STATE_BODY_CHUNK_SIZE: {
            size_t n = processChunkSize(data + consumed, len - consumed);
            consumed += n;
            break;
        }

        case H1_STATE_BODY_CHUNK_DATA: {
            size_t n = processChunkData(data + consumed, len - consumed);
            consumed += n;
            break;
        }

        case H1_STATE_BODY_CHUNK_TRAILER: {
            size_t n = processChunkTrailer(data + consumed, len - consumed);
            consumed += n;
            break;
        }

        // ── Body: Close-Delimited ──────────────────────────────────
        case H1_STATE_BODY_CLOSE_DELIMITED: {
            size_t n = readCloseDelimitedBody(data + consumed, len - consumed);
            consumed += n;
            break;
        }

        default:
            return consumed;
        }
    }

    // A close-delimited message is complete once all currently
    // available bytes have been consumed (REST-style single-shot reads)
    if (state_ == H1_STATE_BODY_CLOSE_DELIMITED && consumed == len) {
        state_ = H1_STATE_COMPLETE;
    }

    return consumed;
}

// ─── Line End Detection ──────────────────────────────────────────────

size_t Http1Parser::findLineEnd(const uint8_t* data, size_t len) const {
    for (size_t i = 0; i + 1 < len; ++i) {
        if (data[i] == '\r' && data[i + 1] == '\n') return i;
    }
    return std::string::npos;
}

// ─── Request Line Parser ─────────────────────────────────────────────

bool Http1Parser::parseRequestLine(const std::string& line) {
    // METHOD SP path SP HTTP/version CRLF
    size_t pos = 0;

    // Skip leading whitespace
    while (pos < line.size() && line[pos] == ' ') ++pos;

    // Extract method
    size_t sp1 = line.find(' ', pos);
    if (sp1 == std::string::npos) return false;
    request_.method_str = line.substr(pos, sp1 - pos);
    request_.method = parseMethod(request_.method_str);
    pos = sp1 + 1;

    // Skip spaces
    while (pos < line.size() && line[pos] == ' ') ++pos;

    // Extract path (including query string)
    size_t sp2 = line.find(' ', pos);
    if (sp2 == std::string::npos) return false;
    std::string uri = line.substr(pos, sp2 - pos);
    size_t qpos = uri.find('?');
    if (qpos != std::string::npos) {
        request_.path = uri.substr(0, qpos);
        request_.query = uri.substr(qpos + 1);
    } else {
        request_.path = uri;
    }
    pos = sp2 + 1;

    // Extract version
    std::string ver = line.substr(pos);
    if (ver == "HTTP/1.1") {
        request_.version = H1_VER_1_1;
    } else if (ver == "HTTP/1.0") {
        request_.version = H1_VER_1_0;
    } else {
        request_.version = H1_VER_UNKNOWN;
    }

    return true;
}

// ─── Response Line Parser ────────────────────────────────────────────

bool Http1Parser::parseResponseLine(const std::string& line) {
    // HTTP/version SP status SP reason CRLF
    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) return false;

    std::string ver = line.substr(0, sp1);
    if (ver == "HTTP/1.1") {
        response_.version = H1_VER_1_1;
    } else if (ver == "HTTP/1.0") {
        response_.version = H1_VER_1_0;
    } else {
        response_.version = H1_VER_UNKNOWN;
    }

    size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return false;

    std::string status_str = line.substr(sp1 + 1, sp2 - sp1 - 1);
    char* end = nullptr;
    long code = std::strtol(status_str.c_str(), &end, 10);
    if (*end != '\0' || code < 100 || code > 599) return false;
    response_.status_code = static_cast<uint16_t>(code);

    response_.reason = line.substr(sp2 + 1);

    return true;
}

// ─── Header Line Parser ──────────────────────────────────────────────

bool Http1Parser::parseHeaderLine(const std::string& line) {
    size_t colon = line.find(':');
    if (colon == std::string::npos) return false;

    std::string name = line.substr(0, colon);

    // Validate field name (token per RFC 7230 §3.2.6)
    for (char c : name) {
        if (c <= 32 || c > 126 || c == ':' || c == '(' || c == ')' ||
            c == '<' || c == '>' || c == '@' || c == ',' || c == ';' ||
            c == '\\' || c == '"' || c == '/' || c == '[' || c == ']' ||
            c == '?' || c == '=' || c == '{' || c == '}' || c == ' ') {
            return false;
        }
    }

    std::string value;
    size_t vpos = colon + 1;
    // Skip leading OWS
    while (vpos < line.size() && (line[vpos] == ' ' || line[vpos] == '\t')) {
        ++vpos;
    }
    value = line.substr(vpos);

    // Normalize name to lowercase
    for (char& c : name) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }

    addHeader(name, value);
    return true;
}

// ─── Add Header ──────────────────────────────────────────────────────

void Http1Parser::addHeader(const std::string& name, const std::string& value) {
    // Check if header already exists; for most headers we append comma-separated
    // Set-Cookie is special (multiple headers, each separate)
    if (name == "set-cookie") {
        headers_.push_back({name, value});
        return;
    }
    // For cookie, we also keep separate
    if (name == "cookie") {
        headers_.push_back({name, value});
        return;
    }
    // For other headers, find existing and append
    for (auto& h : headers_) {
        if (h.name == name) {
            h.value += ", " + value;
            return;
        }
    }
    headers_.push_back({name, value});
}

// ─── Process Special Headers ─────────────────────────────────────────

void Http1Parser::processSpecialHeaders() {
    connection_close_ = false;
    connection_keep_alive_ = false;
    has_content_length_ = false;
    has_transfer_encoding_chunked_ = false;
    expect_continue_ = false;
    upgrade_info_ = Http1UpgradeInfo{};

    bool saw_connection_header = false;

    for (const auto& h : headers_) {
        if (h.name == "connection") {
            saw_connection_header = true;
            // Parse connection options
            std::string lc_value = h.value;
            for (char& c : lc_value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            if (lc_value.find("close") != std::string::npos) {
                connection_close_ = true;
            }
            if (lc_value.find("keep-alive") != std::string::npos ||
                lc_value.find("keepalive") != std::string::npos) {
                connection_keep_alive_ = true;
            }
            if (lc_value.find("upgrade") != std::string::npos) {
                detectUpgrade();
            }
        } else if (h.name == "content-length") {
            char* end = nullptr;
            unsigned long long cl = std::strtoull(h.value.c_str(), &end, 10);
            if (*end == '\0' || *end == ' ') {
                content_length_ = static_cast<size_t>(cl);
                has_content_length_ = true;
            }
        } else if (h.name == "transfer-encoding") {
            std::string lc_value = h.value;
            for (char& c : lc_value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

            // Check for chunked (last encoding per RFC 7230 §3.3.1)
            if (lc_value.find("chunked") != std::string::npos) {
                has_transfer_encoding_chunked_ = true;
            }
        } else if (h.name == "upgrade") {
            detectUpgrade();
        } else if (h.name == "expect") {
            std::string lc_value = h.value;
            for (char& c : lc_value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lc_value.find("100-continue") != std::string::npos) {
                expect_continue_ = true;
            }
        }
    }

    // RFC 7230 §6.3: HTTP/1.1 defaults to persistent connections
    // unless "Connection: close"; HTTP/1.0 defaults to close.
    if (!saw_connection_header) {
        Http1Version ver = is_request_ ? request_.version : response_.version;
        if (ver == H1_VER_1_0) {
            connection_close_ = true;
        } else {
            connection_keep_alive_ = true;
        }
    }
}

// ─── Detect Upgrade ──────────────────────────────────────────────────

void Http1Parser::detectUpgrade() {
    for (const auto& h : headers_) {
        if (h.name == "upgrade") {
            std::string lc_value = h.value;
            for (char& c : lc_value) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lc_value.find("h2c") != std::string::npos) {
                upgrade_info_.type = H1_UPGRADE_H2C;
                // Look for HTTP2-Settings header
                for (const auto& h2 : headers_) {
                    if (h2.name == "http2-settings") {
                        // Base64url encoded; store raw for caller to decode
                        upgrade_info_.http2_settings.assign(
                            h2.value.begin(), h2.value.end());
                    }
                }
                return;
            }
            if (lc_value.find("websocket") != std::string::npos) {
                upgrade_info_.type = H1_UPGRADE_WEBSOCKET;
                return;
            }
            upgrade_info_.type = H1_UPGRADE_OTHER;
        }
    }
}

// ─── Determine Body State ────────────────────────────────────────────

void Http1Parser::determineBodyState() {
    // HEAD requests have no body unless a body is explicitly framed
    if (is_request_ && request_.method == H1_HEAD &&
        !has_content_length_ && !has_transfer_encoding_chunked_) {
        body_bytes_read_ = 0;
        state_ = H1_STATE_COMPLETE;
        return;
    }

    // 1xx, 204 No Content, 304 Not Modified have no body
    if (!is_request_) {
        if (response_.status_code / 100 == 1 ||
            response_.status_code == 204 ||
            response_.status_code == 304) {
            state_ = H1_STATE_COMPLETE;
            return;
        }
    }

    // Transfer-Encoding: chunked takes precedence
    if (has_transfer_encoding_chunked_) {
        state_ = H1_STATE_BODY_CHUNK_SIZE;
        return;
    }

    // Content-Length
    if (has_content_length_) {
        if (content_length_ == 0) {
            state_ = H1_STATE_COMPLETE;
            return;
        }
        state_ = H1_STATE_BODY_CONTENT_LENGTH;
        return;
    }

    // Requests without a body and without CL/TE complete immediately
    // (RFC 7230 §3.3.3: no Content-Length/Transfer-Encoding means no body)
    if (is_request_) {
        state_ = H1_STATE_COMPLETE;
        return;
    }

    // Responses: close-delimited when the connection will close
    if (connection_close_ ||
        (response_.version == H1_VER_1_0 && !connection_keep_alive_)) {
        state_ = H1_STATE_BODY_CLOSE_DELIMITED;
        return;
    }

    // For HTTP/1.1 responses without content-length or chunked,
    // assume no body (e.g., 204, 304 were handled above)
    state_ = H1_STATE_COMPLETE;
}

// ─── Content-Length Body Reader ──────────────────────────────────────

size_t Http1Parser::readContentLengthBody(const uint8_t* data, size_t len) {
    size_t remaining = content_length_ - body_bytes_read_;
    size_t to_read = std::min(len, remaining);

    body_.insert(body_.end(), data, data + to_read);
    body_bytes_read_ += to_read;

    if (body_bytes_read_ >= content_length_) {
        state_ = H1_STATE_COMPLETE;
    }

    return to_read;
}

// ─── Chunked Transfer Decoding ───────────────────────────────────────

size_t Http1Parser::processChunkSize(const uint8_t* data, size_t len) {
    size_t consumed = 0;

    // Consume the CRLF that terminates the previous chunk-data before
    // parsing the next chunk-size line (RFC 7230 §4.1)
    while (chunk_crlf_remaining_ > 0 && consumed < len) {
        char expect = (chunk_crlf_remaining_ == 2) ? '\r' : '\n';
        if (data[consumed] != static_cast<uint8_t>(expect)) {
            state_ = H1_STATE_ERROR;
            return consumed;
        }
        --chunk_crlf_remaining_;
        ++consumed;
    }
    if (chunk_crlf_remaining_ > 0) return consumed; // need more bytes

    if (!chunk_line_buffer_.empty()) {
        // We have buffered partial line data
        size_t needed = chunk_line_buffer_.size();
        size_t avail = std::min(len, MAX_LINE_SIZE - needed);
        chunk_line_buffer_.append(reinterpret_cast<const char*>(data), avail);
        consumed = avail;

        // Try to find line end in the accumulated buffer
        size_t line_end = findLineEnd(
            reinterpret_cast<const uint8_t*>(chunk_line_buffer_.data()),
            chunk_line_buffer_.size());

        if (line_end == std::string::npos) {
            if (chunk_line_buffer_.size() >= MAX_LINE_SIZE) {
                state_ = H1_STATE_ERROR;
            }
            return consumed;
        }

        std::string line = chunk_line_buffer_.substr(0, line_end);
        chunk_line_buffer_.clear();

        // Parse chunk size (hex) ignoring chunk-extensions
        size_t semicolon = line.find(';');
        std::string size_str = (semicolon != std::string::npos)
                                   ? line.substr(0, semicolon)
                                   : line;
        char* end = nullptr;
        unsigned long long cs = std::strtoull(size_str.c_str(), &end, 16);
        if (*end != '\0' && *end != '\r') {
            state_ = H1_STATE_ERROR;
            return consumed;
        }
        if (cs > MAX_CHUNK_SIZE) {
            state_ = H1_STATE_ERROR;
            return consumed;
        }
        chunk_size_remaining_ = static_cast<size_t>(cs);

        if (chunk_size_remaining_ == 0) {
            state_ = H1_STATE_BODY_CHUNK_TRAILER;
        } else {
            state_ = H1_STATE_BODY_CHUNK_DATA;
        }
        return consumed;
    }

    // Find line end in the fresh data
    size_t line_end = findLineEnd(data + consumed, len - consumed);
    if (line_end == std::string::npos) {
        chunk_line_buffer_.append(reinterpret_cast<const char*>(data + consumed),
                                  len - consumed);
        return len;
    }

    std::string line(reinterpret_cast<const char*>(data + consumed), line_end);
    consumed += line_end + 2;

    size_t semicolon = line.find(';');
    std::string size_str = (semicolon != std::string::npos)
                               ? line.substr(0, semicolon)
                               : line;
    char* end = nullptr;
    unsigned long long cs = std::strtoull(size_str.c_str(), &end, 16);
    if (*end != '\0' && *end != '\r') {
        state_ = H1_STATE_ERROR;
        return consumed;
    }
    if (cs > MAX_CHUNK_SIZE) {
        state_ = H1_STATE_ERROR;
        return consumed;
    }
    chunk_size_remaining_ = static_cast<size_t>(cs);

    if (chunk_size_remaining_ == 0) {
        state_ = H1_STATE_BODY_CHUNK_TRAILER;
    } else {
        state_ = H1_STATE_BODY_CHUNK_DATA;
    }

    return consumed;
}

size_t Http1Parser::processChunkData(const uint8_t* data, size_t len) {
    size_t to_read = std::min(len, chunk_size_remaining_);

    body_.insert(body_.end(), data, data + to_read);
    chunk_size_remaining_ -= to_read;
    body_bytes_read_ += to_read;

    if (chunk_size_remaining_ == 0) {
        // RFC 7230 §4.1: chunk-data is terminated by CRLF
        chunk_crlf_remaining_ = 2;
        state_ = H1_STATE_BODY_CHUNK_SIZE;
    }

    return to_read;
}

size_t Http1Parser::processChunkTrailer(const uint8_t* data, size_t len) {
    size_t consumed = 0;

    while (consumed < len) {
        size_t line_end = findLineEnd(data + consumed, len - consumed);
        if (line_end == std::string::npos) {
            chunk_line_buffer_.append(
                reinterpret_cast<const char*>(data + consumed),
                len - consumed);
            consumed = len;
            break;
        }

        std::string line(reinterpret_cast<const char*>(data + consumed), line_end);
        consumed += line_end + 2;

        if (line.empty()) {
            // Empty line marks end of trailers
            state_ = H1_STATE_COMPLETE;
            break;
        }

        // Parse trailer header
        // (We don't currently store trailers, but we could extend)
    }

    return consumed;
}

// ─── Close-Delimited Body Reader ─────────────────────────────────────

size_t Http1Parser::readCloseDelimitedBody(const uint8_t* data, size_t len) {
    body_.insert(body_.end(), data, data + len);
    body_bytes_read_ += len;
    return len; // Will complete when connection closes
}

// ─── Get Single Header ───────────────────────────────────────────────

std::string Http1Parser::getHeader(const std::string& name) const {
    std::string lc_name = name;
    for (char& c : lc_name) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }
    for (const auto& h : headers_) {
        if (h.name == lc_name) return h.value;
    }
    return {};
}

// ─── Get Header Values ───────────────────────────────────────────────

std::vector<std::string> Http1Parser::getHeaderValues(const std::string& name) const {
    std::string lc_name = name;
    for (char& c : lc_name) {
        if (c >= 'A' && c <= 'Z') c += 32;
    }
    std::vector<std::string> values;
    for (const auto& h : headers_) {
        if (h.name == lc_name) values.push_back(h.value);
    }
    return values;
}

// ─── Method Parsing ──────────────────────────────────────────────────

Http1Method Http1Parser::parseMethod(const std::string& m) {
    if (m == "GET") return H1_GET;
    if (m == "POST") return H1_POST;
    if (m == "PUT") return H1_PUT;
    if (m == "DELETE") return H1_DELETE;
    if (m == "HEAD") return H1_HEAD;
    if (m == "OPTIONS") return H1_OPTIONS;
    if (m == "PATCH") return H1_PATCH;
    if (m == "CONNECT") return H1_CONNECT;
    if (m == "TRACE") return H1_TRACE;
    return H1_UNKNOWN_METHOD;
}

std::string Http1Parser::methodToString(Http1Method m) {
    switch (m) {
        case H1_GET: return "GET";
        case H1_POST: return "POST";
        case H1_PUT: return "PUT";
        case H1_DELETE: return "DELETE";
        case H1_HEAD: return "HEAD";
        case H1_OPTIONS: return "OPTIONS";
        case H1_PATCH: return "PATCH";
        case H1_CONNECT: return "CONNECT";
        case H1_TRACE: return "TRACE";
        default: return "UNKNOWN";
    }
}

std::string Http1Parser::versionToString(Http1Version v) {
    switch (v) {
        case H1_VER_1_0: return "HTTP/1.0";
        case H1_VER_1_1: return "HTTP/1.1";
        default: return "HTTP/?.?";
    }
}

// ─── Request Serialization ───────────────────────────────────────────

std::vector<uint8_t> Http1Parser::serializeRequest(
    const Http1Request& req, const std::vector<Http1Header>& headers,
    const uint8_t* body, size_t body_len) {

    std::string wire = req.path.empty() ? "/" : req.path;
    if (!req.query.empty()) wire += "?" + req.query;

    std::string method = methodToString(req.method);
    std::string ver = versionToString(req.version);

    std::ostringstream oss;
    oss << method << " " << wire << " " << ver << "\r\n";

    for (const auto& h : headers) {
        oss << h.name << ": " << h.value << "\r\n";
    }

    if (body_len > 0) {
        // Add Content-Length if not present
        bool has_cl = false;
        for (const auto& h : headers) {
            std::string lc = h.name;
            for (char& c : lc) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lc == "content-length") { has_cl = true; break; }
        }
        if (!has_cl) {
            oss << "Content-Length: " << body_len << "\r\n";
        }
    } else {
        oss << "Content-Length: 0\r\n";
    }

    oss << "\r\n";

    std::string header_part = oss.str();
    std::vector<uint8_t> result(header_part.begin(), header_part.end());
    if (body && body_len > 0) {
        result.insert(result.end(), body, body + body_len);
    }
    return result;
}

// ─── Get Default Reason Phrase ───────────────────────────────────────

static const char* getDefaultReason(uint16_t status) {
    switch (status) {
        case 100: return "Continue";
        case 101: return "Switching Protocols";
        case 200: return "OK";
        case 201: return "Created";
        case 204: return "No Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 304: return "Not Modified";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 408: return "Request Timeout";
        case 413: return "Payload Too Large";
        case 414: return "URI Too Long";
        case 429: return "Too Many Requests";
        case 500: return "Internal Server Error";
        case 502: return "Bad Gateway";
        case 503: return "Service Unavailable";
        default: return "";
    }
}

// ─── Response Serialization ──────────────────────────────────────────

std::vector<uint8_t> Http1Parser::serializeResponse(
    const Http1Response& resp, const std::vector<Http1Header>& headers,
    const uint8_t* body, size_t body_len) {

    std::string ver = versionToString(resp.version);

    std::ostringstream oss;
    oss << ver << " " << resp.status_code << " "
        << (resp.reason.empty() ? getDefaultReason(resp.status_code) : resp.reason)
        << "\r\n";

    for (const auto& h : headers) {
        oss << h.name << ": " << h.value << "\r\n";
    }

    if (body_len > 0) {
        bool has_cl = false;
        for (const auto& h : headers) {
            std::string lc = h.name;
            for (char& c : lc) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lc == "content-length") { has_cl = true; break; }
        }
        if (!has_cl) {
            oss << "Content-Length: " << body_len << "\r\n";
        }
    }

    oss << "\r\n";

    std::string header_part = oss.str();
    std::vector<uint8_t> result(header_part.begin(), header_part.end());
    if (body && body_len > 0) {
        result.insert(result.end(), body, body + body_len);
    }
    return result;
}

// ─── 100 Continue Serialization ──────────────────────────────────────

std::vector<uint8_t> Http1Parser::serializeContinue() {
    std::string resp = "HTTP/1.1 100 Continue\r\n\r\n";
    return std::vector<uint8_t>(resp.begin(), resp.end());
}

// ─── Chunk Serialization ─────────────────────────────────────────────

std::vector<uint8_t> Http1Parser::serializeChunk(const uint8_t* data, size_t len) {
    // chunk-size CRLF chunk-data CRLF
    std::ostringstream oss;
    oss << std::hex << len << "\r\n";
    std::string header = oss.str();

    std::vector<uint8_t> result(header.begin(), header.end());
    if (data && len > 0) {
        result.insert(result.end(), data, data + len);
    }
    std::string trailer = "\r\n";
    result.insert(result.end(), trailer.begin(), trailer.end());
    return result;
}

std::vector<uint8_t> Http1Parser::serializeChunkEnd() {
    std::string end = "0\r\n\r\n";
    return std::vector<uint8_t>(end.begin(), end.end());
}


