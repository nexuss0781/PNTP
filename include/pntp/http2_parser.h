#ifndef HTTP2_PARSER_H
#define HTTP2_PARSER_H

#include <vector>
#include <cstdint>
#include <string>
#include <map>

// Conceptual representation of an HTTP/2 frame
struct Http2Frame {
    uint32_t length;
    uint8_t type;
    uint8_t flags;
    uint32_t stream_id;
    std::vector<unsigned char> payload;
};

class Http2Parser {
public:
    Http2Parser();
    ~Http2Parser();

    // Conceptual method to parse raw network data into HTTP/2 frames
    std::vector<Http2Frame> parseData(const std::vector<unsigned char>& raw_data);

    // Conceptual method to serialize HTTP/2 frames back into raw data
    std::vector<unsigned char> serializeFrames(const std::vector<Http2Frame>& frames);

    // Conceptual method to manipulate HTTP/2 headers (e.g., HPACK decoding/encoding)
    std::map<std::string, std::string> decodeHeaders(const std::vector<unsigned char>& header_block);
    std::vector<unsigned char> encodeHeaders(const std::map<std::string, std::string>& headers);

    // Placeholder for stream management and flow control
    void handleStream(uint32_t stream_id, const Http2Frame& frame);

private:
    // Internal state for HPACK context, stream states, etc.
};

#endif // HTTP2_PARSER_H
