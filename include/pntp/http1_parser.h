#ifndef HTTP1_PARSER_H
#define HTTP1_PARSER_H

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include <unordered_map>

// ─── HTTP/1.1 Types (RFC 7230/7231) ──────────────────────────────────

enum Http1Method : uint8_t {
    H1_GET = 0,
    H1_POST,
    H1_PUT,
    H1_DELETE,
    H1_HEAD,
    H1_OPTIONS,
    H1_PATCH,
    H1_CONNECT,
    H1_TRACE,
    H1_UNKNOWN_METHOD
};

enum Http1Version : uint8_t {
    H1_VER_1_0 = 0,
    H1_VER_1_1,
    H1_VER_UNKNOWN
};

enum Http1ParseState : uint8_t {
    H1_STATE_REQUEST_LINE = 0,
    H1_STATE_RESPONSE_LINE,
    H1_STATE_HEADERS,
    H1_STATE_BODY_CONTENT_LENGTH,
    H1_STATE_BODY_CHUNKED,
    H1_STATE_BODY_CHUNK_SIZE,
    H1_STATE_BODY_CHUNK_DATA,
    H1_STATE_BODY_CHUNK_TRAILER,
    H1_STATE_BODY_CLOSE_DELIMITED,
    H1_STATE_COMPLETE,
    H1_STATE_ERROR
};

enum Http1UpgradeType : uint8_t {
    H1_UPGRADE_NONE = 0,
    H1_UPGRADE_H2C,
    H1_UPGRADE_WEBSOCKET,
    H1_UPGRADE_OTHER
};

// ─── Core Data Structures ────────────────────────────────────────────

struct Http1Request {
    Http1Method method = H1_UNKNOWN_METHOD;
    std::string method_str;
    std::string path;
    std::string query;
    Http1Version version = H1_VER_1_1;
};

struct Http1Response {
    Http1Version version = H1_VER_1_1;
    uint16_t status_code = 0;
    std::string reason;
};

struct Http1Header {
    std::string name;
    std::string value;
};

struct Http1UpgradeInfo {
    Http1UpgradeType type = H1_UPGRADE_NONE;
    std::vector<uint8_t> http2_settings;
};

// ─── HTTP/1.1 Parser ─────────────────────────────────────────────────

class Http1Parser {
public:
    Http1Parser();
    ~Http1Parser();

    Http1Parser(const Http1Parser&) = delete;
    Http1Parser& operator=(const Http1Parser&) = delete;

    // ── Main API ───────────────────────────────────────────────────
    // Feed raw bytes, returns bytes consumed
    size_t feed(const uint8_t* data, size_t len);

    bool isComplete() const { return state_ == H1_STATE_COMPLETE; }
    bool hasError() const { return state_ == H1_STATE_ERROR; }
    void reset();

    // ── Getters ────────────────────────────────────────────────────
    const Http1Request& getRequest() const { return request_; }
    const Http1Response& getResponse() const { return response_; }
    const std::vector<Http1Header>& getHeaders() const { return headers_; }
    const std::vector<uint8_t>& getBody() const { return body_; }

    // Find single header value (case-insensitive)
    std::string getHeader(const std::string& name) const;
    // Get all values for a header (for multi-value headers)
    std::vector<std::string> getHeaderValues(const std::string& name) const;

    // ── Connection State ───────────────────────────────────────────
    bool shouldClose() const { return connection_close_; }
    bool upgradeDetected() const { return upgrade_info_.type != H1_UPGRADE_NONE; }
    Http1UpgradeInfo getUpgradeInfo() const { return upgrade_info_; }
    bool expectContinue() const { return expect_continue_; }

    // ── Parse State ────────────────────────────────────────────────
    Http1ParseState getState() const { return state_; }
    bool isRequest() const { return is_request_; }
    bool isResponse() const { return !is_request_; }

    // ── Serialization (static) ─────────────────────────────────────
    static std::vector<uint8_t> serializeRequest(
        const Http1Request& req, const std::vector<Http1Header>& headers,
        const uint8_t* body, size_t body_len);

    static std::vector<uint8_t> serializeResponse(
        const Http1Response& resp, const std::vector<Http1Header>& headers,
        const uint8_t* body, size_t body_len);

    static std::vector<uint8_t> serializeContinue();

    static std::vector<uint8_t> serializeChunk(const uint8_t* data, size_t len);
    static std::vector<uint8_t> serializeChunkEnd();

private:
    // ── Line Parsing ───────────────────────────────────────────────
    bool parseRequestLine(const std::string& line);
    bool parseResponseLine(const std::string& line);
    bool parseHeaderLine(const std::string& line);
    size_t findLineEnd(const uint8_t* data, size_t len) const;

    // ── Body Reading ───────────────────────────────────────────────
    size_t readContentLengthBody(const uint8_t* data, size_t len);
    size_t readChunkedBody(const uint8_t* data, size_t len);
    size_t readCloseDelimitedBody(const uint8_t* data, size_t len);

    // ── Chunked Encoding ───────────────────────────────────────────
    size_t processChunkSize(const uint8_t* data, size_t len);
    size_t processChunkData(const uint8_t* data, size_t len);
    size_t processChunkTrailer(const uint8_t* data, size_t len);

    // ── Header Processing ─────────────────────────────────────────
    void processSpecialHeaders();
    void detectUpgrade();
    void addHeader(const std::string& name, const std::string& value);

    // ── Helpers ────────────────────────────────────────────────────
    static Http1Method parseMethod(const std::string& m);
    static std::string methodToString(Http1Method m);
    static std::string versionToString(Http1Version v);

    // ── State ──────────────────────────────────────────────────────
    Http1ParseState state_ = H1_STATE_REQUEST_LINE;
    bool is_request_ = true;

    // ── Buffering ──────────────────────────────────────────────────
    std::vector<uint8_t> buffer_;
    std::string line_buffer_;

    // ── Parsed Data ────────────────────────────────────────────────
    Http1Request request_;
    Http1Response response_;
    std::vector<Http1Header> headers_;
    std::vector<uint8_t> body_;

    // ── Body Tracking ──────────────────────────────────────────────
    size_t content_length_ = 0;
    size_t body_bytes_read_ = 0;
    bool has_content_length_ = false;
    bool has_transfer_encoding_chunked_ = false;

    // ── Chunked State ──────────────────────────────────────────────
    size_t chunk_size_remaining_ = 0;
    std::string chunk_line_buffer_;

    // ── Connection State ───────────────────────────────────────────
    bool connection_close_ = false;
    bool connection_keep_alive_ = false;
    Http1UpgradeInfo upgrade_info_;
    bool expect_continue_ = false;

    // ── Limits ─────────────────────────────────────────────────────
    static constexpr size_t MAX_HEADER_SIZE = 8192;
    static constexpr size_t MAX_LINE_SIZE = 8192;
    static constexpr size_t MAX_CHUNK_SIZE = 16 * 1024 * 1024;
};

#endif // HTTP1_PARSER_H
