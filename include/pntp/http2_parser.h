#ifndef HTTP2_PARSER_H
#define HTTP2_PARSER_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

// ─── HPACK Types ─────────────────────────────────────────────────────

struct HpackHeaderField {
    std::string name;
    std::string value;
};

// ─── Frame Types (RFC 7540) ──────────────────────────────────────────

enum Http2FrameType : uint8_t {
    H2_DATA = 0x00,
    H2_HEADERS = 0x01,
    H2_PRIORITY = 0x02,
    H2_RST_STREAM = 0x03,
    H2_SETTINGS = 0x04,
    H2_PUSH_PROMISE = 0x05,
    H2_PING = 0x06,
    H2_GOAWAY = 0x07,
    H2_WINDOW_UPDATE = 0x08,
    H2_CONTINUATION = 0x09
};

enum Http2Flags : uint8_t {
    H2_FLAG_END_STREAM = 0x01,
    H2_FLAG_ACK = 0x01,
    H2_FLAG_END_HEADERS = 0x04,
    H2_FLAG_PADDED = 0x08,
    H2_FLAG_PRIORITY = 0x20
};

enum Http2Error : uint32_t {
    H2_NO_ERROR = 0x00,
    H2_PROTOCOL_ERROR = 0x01,
    H2_INTERNAL_ERROR = 0x02,
    H2_FLOW_CONTROL_ERROR = 0x03,
    H2_SETTINGS_TIMEOUT = 0x04,
    H2_STREAM_CLOSED = 0x05,
    H2_FRAME_SIZE_ERROR = 0x06,
    H2_REFUSED_STREAM = 0x07,
    H2_CANCEL = 0x08,
    H2_COMPRESSION_ERROR = 0x09,
    H2_CONNECT_ERROR = 0x0A,
    H2_ENHANCE_YOUR_CALM = 0x0B,
    H2_INADEQUATE_SECURITY = 0x0C,
    H2_HTTP_1_1_REQUIRED = 0x0D
};

enum Http2SettingsId : uint16_t {
    H2_SETTINGS_HEADER_TABLE_SIZE = 0x01,
    H2_SETTINGS_ENABLE_PUSH = 0x02,
    H2_SETTINGS_MAX_CONCURRENT_STREAMS = 0x03,
    H2_SETTINGS_INITIAL_WINDOW_SIZE = 0x04,
    H2_SETTINGS_MAX_FRAME_SIZE = 0x05,
    H2_SETTINGS_MAX_HEADER_LIST_SIZE = 0x06
};

// ─── Stream State Machine (RFC 7540 Table 4) ─────────────────────────

enum StreamState : uint8_t {
    SS_IDLE = 0,
    SS_RESERVED_LOCAL,
    SS_RESERVED_REMOTE,
    SS_OPEN,
    SS_HALF_CLOSED_LOCAL,
    SS_HALF_CLOSED_REMOTE,
    SS_CLOSED,
    SS_INVALID = 255
};

enum StreamEvent : uint8_t {
    SE_SEND_HEADERS = 0,
    SE_RECV_HEADERS,
    SE_SEND_DATA,
    SE_RECV_DATA,
    SE_SEND_END_STREAM,
    SE_RECV_END_STREAM,
    SE_SEND_RST_STREAM,
    SE_RECV_RST_STREAM,
    SE_SEND_PUSH_PROMISE,
    SE_RECV_PUSH_PROMISE
};

// ─── Priority Tree ───────────────────────────────────────────────────

struct PriorityNode {
    uint32_t stream_id;
    uint32_t parent_id;
    int32_t weight;  // 1-256
    bool exclusive;
    std::vector<uint32_t> children;
};

// ─── Frame Header Utility ────────────────────────────────────────────

struct Http2FrameHeader {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
};

// ─── Stream Data ─────────────────────────────────────────────────────

struct StreamData {
    StreamState state = SS_IDLE;
    uint32_t recv_window = 65535;
    uint32_t send_window = 65535;
    uint32_t recv_window_delta = 0;
    uint32_t send_window_delta = 0;
    // HEADERS/CONTINUATION reassembly
    std::vector<uint8_t> header_fragment;
    bool headers_started = false;
    bool headers_complete = false;
    std::vector<HpackHeaderField> decoded_headers;
    bool half_closed_local = false;
    bool half_closed_remote = false;
    uint32_t recv_data_total = 0;
};

// ─── HPACK Static Table ──────────────────────────────────────────────

class HpackStaticTable {
public:
    static const HpackHeaderField& get(size_t index);
    static size_t findName(const std::string& name);
    static constexpr size_t SIZE = 61;
};

// ─── HPACK Dynamic Table ─────────────────────────────────────────────

class HpackDynamicTable {
public:
    HpackDynamicTable();
    void add(const HpackHeaderField& entry);
    const HpackHeaderField* get(size_t index) const;
    size_t findName(const std::string& name) const;
    void setMaxSize(size_t max_size);
    size_t size() const { return entries_.size(); }
    size_t currentSize() const { return current_size_; }
    size_t maxSize() const { return max_size_; }
    void clear();

private:
    std::vector<HpackHeaderField> entries_;
    size_t current_size_ = 0;
    size_t max_size_ = 4096;
    size_t entrySize(const HpackHeaderField& e) const;
    void evict();
};

// ─── HPACK Huffman Codec ─────────────────────────────────────────────

class HpackHuffman {
public:
    static std::vector<uint8_t> encode(const std::string& input);
    static std::string decode(const uint8_t* data, size_t len);
};

// ─── HPACK Encoder ──────────────────────────────────────────────────

class HpackEncoder {
public:
    HpackEncoder();
    std::vector<uint8_t> encode(const std::vector<HpackHeaderField>& headers, bool& error);
    HpackDynamicTable& dynamicTable() { return dynamic_table_; }
    const HpackDynamicTable& dynamicTable() const { return dynamic_table_; }
    void setTableSize(size_t size);
    void clearDynamicTable();

private:
    HpackDynamicTable dynamic_table_;
    bool table_size_sent_ = false;
    void encodeInteger(std::vector<uint8_t>& out, uint64_t value, uint8_t nbits);
    void encodeString(std::vector<uint8_t>& out, const std::string& str);
    void encodeIndexed(std::vector<uint8_t>& out, size_t index);
    void encodeLiteral(std::vector<uint8_t>& out, const std::string& name,
                       const std::string& value, bool incremental);
};

// ─── HPACK Decoder ──────────────────────────────────────────────────

class HpackDecoder {
public:
    HpackDecoder();
    std::vector<HpackHeaderField> decode(const uint8_t* data, size_t len, bool& error);
    HpackDynamicTable& dynamicTable() { return dynamic_table_; }
    void setTableSize(size_t size);

private:
    HpackDynamicTable dynamic_table_;
    uint64_t decodeInteger(const uint8_t*& pos, const uint8_t* end, uint8_t nbits);
    std::string decodeString(const uint8_t*& pos, const uint8_t* end, bool& error);
};

// ─── Main HTTP/2 Parser ──────────────────────────────────────────────

using H2OnHeaders = std::function<void(uint32_t stream_id,
    const std::vector<HpackHeaderField>& headers, bool end_stream)>;
using H2OnData = std::function<void(uint32_t stream_id,
    const uint8_t* data, size_t len, bool end_stream)>;
using H2OnGoaway = std::function<void(uint32_t last_stream_id,
    Http2Error error_code, const std::vector<uint8_t>& debug_data)>;
using H2OnStreamReset = std::function<void(uint32_t stream_id,
    Http2Error error_code)>;
using H2OnSettings = std::function<void(
    const std::map<uint16_t, uint32_t>& settings)>;
using H2OnFrameError = std::function<void(const std::string& error)>;

class Http2Parser {
public:
    Http2Parser();
    ~Http2Parser();

    // ── Feed raw bytes (from TLS decrypt or TCP) ─────────────────
    // Returns number of bytes consumed
    size_t feed(const uint8_t* data, size_t len);

    // ── Connection Management ────────────────────────────────────
    void sendPreface();
    bool isConnected() const;
    bool goawayReceived() const { return goaway_received_; }
    uint32_t goawayLastStreamId() const { return goaway_last_stream_id_; }

    // ── Stream Management ────────────────────────────────────────
    uint32_t openStream();
    bool closeStream(uint32_t stream_id);
    StreamState getStreamState(uint32_t stream_id) const;
    size_t activeStreamCount() const;

    // ── Serialization Helpers ────────────────────────────────────
    static std::vector<uint8_t> makeFrameHeader(
        uint32_t length, uint8_t type, uint8_t flags, uint32_t stream_id);

    std::vector<uint8_t> serializeHeaders(uint32_t stream_id,
        const std::vector<HpackHeaderField>& headers, bool end_stream);
    std::vector<uint8_t> serializeData(uint32_t stream_id,
        const uint8_t* data, size_t len, bool end_stream);
    std::vector<uint8_t> serializeRstStream(uint32_t stream_id, Http2Error error);
    std::vector<uint8_t> serializeSettings(
        const std::map<uint16_t, uint32_t>& settings);
    std::vector<uint8_t> serializeSettingsAck();
    std::vector<uint8_t> serializePing(const uint8_t data[8]);
    std::vector<uint8_t> serializePingAck(const uint8_t data[8]);
    std::vector<uint8_t> serializeGoaway(uint32_t last_stream_id, Http2Error error);
    std::vector<uint8_t> serializeWindowUpdate(uint32_t stream_id,
        uint32_t increment);
    std::vector<uint8_t> serializePriority(uint32_t stream_id,
        uint32_t parent_id, int32_t weight, bool exclusive);

    // ── Callbacks ────────────────────────────────────────────────
    void setOnHeaders(H2OnHeaders cb) { on_headers_ = std::move(cb); }
    void setOnData(H2OnData cb) { on_data_ = std::move(cb); }
    void setOnGoaway(H2OnGoaway cb) { on_goaway_ = std::move(cb); }
    void setOnStreamReset(H2OnStreamReset cb) { on_stream_reset_ = std::move(cb); }
    void setOnSettings(H2OnSettings cb) { on_settings_ = std::move(cb); }
    void setOnFrameError(H2OnFrameError cb) { on_frame_error_ = std::move(cb); }

    // ── Flow Control ─────────────────────────────────────────────
    void setBdpEstimate(uint32_t bdp_bytes);
    uint32_t connectionWindow() const { return connection_window_; }
    uint32_t streamWindow(uint32_t stream_id) const;
    uint32_t initialWindowSize() const { return initial_window_size_; }

    // ── Accessors ────────────────────────────────────────────────
    const HpackEncoder& encoder() const { return encoder_; }
    const HpackDecoder& decoder() const { return decoder_; }
    std::map<uint16_t, uint32_t> remoteSettings() const { return remote_settings_; }

    // ── Non-copyable ─────────────────────────────────────────────
    Http2Parser(const Http2Parser&) = delete;
    Http2Parser& operator=(const Http2Parser&) = delete;

private:
    // ── Frame Processing ─────────────────────────────────────────
    bool processFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processDataFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processHeadersFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processPriorityFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processRstStreamFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processSettingsFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processPushPromiseFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processPingFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processGoawayFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processWindowUpdateFrame(const Http2FrameHeader& hdr, const uint8_t* payload);
    bool processContinuationFrame(const Http2FrameHeader& hdr, const uint8_t* payload);

    // ── Header Validation ────────────────────────────────────────
    bool validateRequestHeaders(const std::vector<HpackHeaderField>& headers);
    bool validateResponseHeaders(const std::vector<HpackHeaderField>& headers);
    bool isConnectionSpecific(const std::string& name);

    // ── Stream State Machine ─────────────────────────────────────
    StreamState transitionState(StreamState current, StreamEvent event);
    bool transitionStream(uint32_t stream_id, StreamEvent event);

    // ── Flow Control Helpers ─────────────────────────────────────
    bool consumeConnectionWindow(uint32_t size);
    bool consumeStreamWindow(uint32_t stream_id, uint32_t size);
    void updateConnectionWindow(uint32_t increment);
    void updateStreamWindow(uint32_t stream_id, uint32_t increment);

    // ── Priority Tree ────────────────────────────────────────────
    PriorityNode* findPriorityNode(uint32_t stream_id);
    void addPriorityNode(uint32_t stream_id, uint32_t parent_id,
                         int32_t weight, bool exclusive);
    void removePriorityNode(uint32_t stream_id);

    // ── Buffering ────────────────────────────────────────────────
    std::vector<uint8_t> buffer_;
    bool preface_sent_ = false;
    bool preface_received_ = false;

    // ── Settings ─────────────────────────────────────────────────
    std::map<uint16_t, uint32_t> local_settings_;
    std::map<uint16_t, uint32_t> remote_settings_;
    uint32_t remote_max_frame_size_ = 16384;
    uint32_t initial_window_size_ = 65535;
    uint32_t remote_max_concurrent_streams_ = 100;

    // ── Stream State ─────────────────────────────────────────────
    std::unordered_map<uint32_t, StreamData> streams_;
    uint32_t next_stream_id_ = 1;
    uint32_t last_processed_stream_id_ = 0;

    // ── Flow Control ─────────────────────────────────────────────
    uint32_t connection_window_ = 65535;
    uint32_t connection_window_delta_ = 0;
    uint32_t bdp_estimate_ = 0;
    bool bdp_autotune_enabled_ = false;

    // ── GOAWAY ───────────────────────────────────────────────────
    bool goaway_sent_ = false;
    bool goaway_received_ = false;
    uint32_t goaway_last_stream_id_ = 0;

    // ── Priority Tree ────────────────────────────────────────────
    std::unordered_map<uint32_t, PriorityNode> priority_nodes_;
    static constexpr uint32_t ROOT_STREAM_ID = 0;

    // ── HPACK ────────────────────────────────────────────────────
    HpackEncoder encoder_;
    HpackDecoder decoder_;

    // ── Callbacks ────────────────────────────────────────────────
    H2OnHeaders on_headers_;
    H2OnData on_data_;
    H2OnGoaway on_goaway_;
    H2OnStreamReset on_stream_reset_;
    H2OnSettings on_settings_;
    H2OnFrameError on_frame_error_;

    // ── Error Helper ─────────────────────────────────────────────
    void emitFrameError(const std::string& msg);
};

#endif // HTTP2_PARSER_H
