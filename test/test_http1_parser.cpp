#include <gtest/gtest.h>
#include "pntp/http1_parser.h"

#include <algorithm>
#include <random>
#include <sstream>
#include <string>
#include <vector>

// ══════════════════════════════════════════════════════════════════════
// P7-001: Request Line Parser
// ══════════════════════════════════════════════════════════════════════

TEST(RequestLineParseTest, SimpleGET) {
    Http1Parser parser;
    std::string req = "GET /index.html HTTP/1.1\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    ASSERT_TRUE(parser.isRequest());
    EXPECT_EQ(parser.getRequest().method, H1_GET);
    EXPECT_EQ(parser.getRequest().path, "/index.html");
    EXPECT_EQ(parser.getRequest().query, "");
    EXPECT_EQ(parser.getRequest().version, H1_VER_1_1);
}

TEST(RequestLineParseTest, POSTWithBody) {
    Http1Parser parser;
    std::string req = "POST /api/data HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().method, H1_POST);
    EXPECT_EQ(parser.getRequest().path, "/api/data");
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "hello");
}

TEST(RequestLineParseTest, PathWithQuery) {
    Http1Parser parser;
    std::string req = "GET /search?q=hello&page=1 HTTP/1.1\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().path, "/search");
    EXPECT_EQ(parser.getRequest().query, "q=hello&page=1");
}

TEST(RequestLineParseTest, HTTP10) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().version, H1_VER_1_0);
}

TEST(RequestLineParseTest, UnknownMethod) {
    Http1Parser parser;
    std::string req = "BOGUS / HTTP/1.1\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().method, H1_UNKNOWN_METHOD);
}

TEST(RequestLineParseTest, MalformedRequest) {
    Http1Parser parser;
    std::string req = "GET\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_TRUE(parser.hasError());
}

TEST(RequestLineParseTest, MultipleMethods) {
    auto test_method = [](const std::string& method_str, Http1Method expected) {
        Http1Parser parser;
        std::string req = method_str + " / HTTP/1.1\r\n\r\n";
        parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
        EXPECT_TRUE(parser.isComplete()) << "Failed for method: " << method_str;
        EXPECT_EQ(parser.getRequest().method, expected);
    };
    test_method("GET", H1_GET);
    test_method("POST", H1_POST);
    test_method("PUT", H1_PUT);
    test_method("DELETE", H1_DELETE);
    test_method("HEAD", H1_HEAD);
    test_method("OPTIONS", H1_OPTIONS);
    test_method("PATCH", H1_PATCH);
    test_method("CONNECT", H1_CONNECT);
    test_method("TRACE", H1_TRACE);
}

// ══════════════════════════════════════════════════════════════════════
// P7-002: Response Line Parser
// ══════════════════════════════════════════════════════════════════════

TEST(ResponseLineParseTest, Simple200) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    ASSERT_TRUE(parser.isResponse());
    EXPECT_EQ(parser.getResponse().status_code, 200);
    EXPECT_EQ(parser.getResponse().reason, "OK");
    EXPECT_EQ(parser.getResponse().version, H1_VER_1_1);
}

TEST(ResponseLineParseTest, Status404) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getResponse().status_code, 404);
    EXPECT_EQ(parser.getResponse().reason, "Not Found");
}

TEST(ResponseLineParseTest, Status500) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getResponse().status_code, 500);
}

TEST(ResponseLineParseTest, Status101Switching) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getResponse().status_code, 101);
    EXPECT_TRUE(parser.upgradeDetected());
}

TEST(ResponseLineParseTest, InvalidStatus) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 999 Unknown\r\nContent-Length: 0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    EXPECT_TRUE(parser.hasError());
}

TEST(ResponseLineParseTest, HTTP10Response) {
    Http1Parser parser;
    std::string resp = "HTTP/1.0 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getResponse().version, H1_VER_1_0);
}

// ══════════════════════════════════════════════════════════════════════
// P7-003: Header Parser
// ══════════════════════════════════════════════════════════════════════

TEST(HeaderParseTest, SingleHeader) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getHeader("host"), "example.com");
}

TEST(HeaderParseTest, MultipleHeaders) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nHost: a.com\r\nUser-Agent: test\r\nAccept: */*\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getHeader("host"), "a.com");
    EXPECT_EQ(parser.getHeader("user-agent"), "test");
    EXPECT_EQ(parser.getHeader("accept"), "*/*");
}

TEST(HeaderParseTest, DuplicateHeaders) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nAccept: text/html\r\nAccept: application/json\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getHeader("accept"), "text/html, application/json");
}

TEST(HeaderParseTest, ObsFoldSupport) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nX-Long-Header: line one\r\n line two\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getHeader("x-long-header"), "line one line two");
}

TEST(HeaderParseTest, EmptyValue) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nX-Empty:\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getHeader("x-empty"), "");
}

TEST(HeaderParseTest, CaseInsensitivity) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nHOST: example.com\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getHeader("Host"), "example.com");
    EXPECT_EQ(parser.getHeader("host"), "example.com");
}

TEST(HeaderParseTest, InvalidHeaderName) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nBad@Header: value\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_TRUE(parser.hasError());
}

TEST(HeaderParseTest, LargeHeaderRejection) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nX-Large: " + std::string(9000, 'a') + "\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    EXPECT_TRUE(parser.hasError());
}

// ══════════════════════════════════════════════════════════════════════
// P7-004: Chunked Transfer Decoding
// ══════════════════════════════════════════════════════════════════════

TEST(ChunkedBodyTest, SingleChunk) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "hello");
}

TEST(ChunkedBodyTest, MultipleChunks) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                       "6\r\nhello \r\n"
                       "6\r\nworld!\r\n"
                       "0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "hello world!");
}

TEST(ChunkedBodyTest, ZeroLengthChunk) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.getBody().empty());
}

TEST(ChunkedBodyTest, ChunkExtension) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                       "5;ext=1\r\nhello\r\n"
                       "0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "hello");
}

TEST(ChunkedBodyTest, TrailerSection) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                       "5\r\nhello\r\n"
                       "0\r\nX-Trailer: val\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "hello");
}

TEST(ChunkedBodyTest, LargeChunkRejection) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                       "2000000\r\n" + std::string(0x2000000, 'x') + "\r\n0\r\n\r\n";
    // This should trigger the MAX_CHUNK_SIZE limit (16MB)
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), 100);
    EXPECT_TRUE(parser.hasError());
}

// ══════════════════════════════════════════════════════════════════════
// P7-005: Content-Length Body Reader
// ══════════════════════════════════════════════════════════════════════

TEST(ContentLengthBodyTest, ExactLength) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "hello");
}

TEST(ContentLengthBodyTest, ZeroLength) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.getBody().empty());
}

TEST(ContentLengthBodyTest, PartialFeed) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabc";
    size_t n = parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    EXPECT_FALSE(parser.isComplete()); // Not done yet
    EXPECT_EQ(parser.getBody().size(), 3);

    // Feed remaining
    std::string rest = "defghij";
    n = parser.feed(reinterpret_cast<const uint8_t*>(rest.data()), rest.size());
    // After first feed, we're in BODY_CONTENT_LENGTH state.
    // The feed returned 0 because the headers are already processed.
    // Actually, the second feed should work because buffer_ tracks position.
    // Let's verify it completes:
    EXPECT_TRUE(parser.isComplete()) << "Should be complete after all bytes";
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "abcdefghij");
}

TEST(ContentLengthBodyTest, LongerThanContentLength) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabcdef";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    auto body = parser.getBody();
    EXPECT_EQ(body.size(), 3);
    EXPECT_EQ(std::string(body.begin(), body.end()), "abc");
}

// ══════════════════════════════════════════════════════════════════════
// P7-006: Connection: keep-alive vs close
// ══════════════════════════════════════════════════════════════════════

TEST(KeepAliveTest, HTTP11DefaultKeepAlive) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\na";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_FALSE(parser.shouldClose());
}

TEST(KeepAliveTest, ConnectionClose) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1\r\n\r\na";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.shouldClose());
}

TEST(KeepAliveTest, HTTP10DefaultClose) {
    Http1Parser parser;
    std::string resp = "HTTP/1.0 200 OK\r\nContent-Length: 1\r\n\r\na";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.shouldClose());
}

TEST(KeepAliveTest, HTTP10ExplicitKeepAlive) {
    Http1Parser parser;
    std::string resp = "HTTP/1.0 200 OK\r\nConnection: keep-alive\r\nContent-Length: 1\r\n\r\na";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_FALSE(parser.shouldClose());
}

// ══════════════════════════════════════════════════════════════════════
// P7-007: Upgrade: h2c Detection
// ══════════════════════════════════════════════════════════════════════

TEST(UpgradeH2CTest, DetectH2CUpgrade) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Upgrade: h2c\r\n"
                      "HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA\r\n"
                      "Connection: Upgrade, HTTP2-Settings\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.upgradeDetected());
    EXPECT_EQ(parser.getUpgradeInfo().type, H1_UPGRADE_H2C);
    EXPECT_FALSE(parser.getUpgradeInfo().http2_settings.empty());
}

TEST(UpgradeH2CTest, NoUpgradeWithoutHeader) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_FALSE(parser.upgradeDetected());
}

TEST(UpgradeH2CTest, WebsocketUpgrade) {
    Http1Parser parser;
    std::string req = "GET /chat HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Upgrade: websocket\r\n"
                      "Connection: Upgrade\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.upgradeDetected());
    EXPECT_EQ(parser.getUpgradeInfo().type, H1_UPGRADE_WEBSOCKET);
}

// ══════════════════════════════════════════════════════════════════════
// P7-008: 100 Continue Handling
// ══════════════════════════════════════════════════════════════════════

TEST(Continue100Test, ExpectContinueDetected) {
    Http1Parser parser;
    std::string req = "POST / HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Expect: 100-continue\r\n"
                      "Content-Length: 5\r\n\r\nhello";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.expectContinue());
}

TEST(Continue100Test, NoExpectWithoutHeader) {
    Http1Parser parser;
    std::string req = "POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\n\r\nhello";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_FALSE(parser.expectContinue());
}

TEST(Continue100Test, SerializeContinue) {
    auto cont = Http1Parser::serializeContinue();
    std::string s(reinterpret_cast<const char*>(cont.data()), cont.size());
    EXPECT_EQ(s, "HTTP/1.1 100 Continue\r\n\r\n");
}

TEST(Continue100Test, GETNoExpect) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nHost: example.com\r\nExpect: 100-continue\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    // GET with Expect: 100-continue — should still detect it
    EXPECT_TRUE(parser.expectContinue());
}

// ══════════════════════════════════════════════════════════════════════
// P7-009: Request Serialization
// ══════════════════════════════════════════════════════════════════════

TEST(SerializeTest, RequestRoundTrip) {
    Http1Request req;
    req.method = H1_GET;
    req.path = "/test";
    req.version = H1_VER_1_1;

    std::vector<Http1Header> headers = {{"Host", "example.com"}};
    auto wire = Http1Parser::serializeRequest(req, headers, nullptr, 0);

    // Parse it back
    Http1Parser parser;
    parser.feed(wire.data(), wire.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.isRequest());
    EXPECT_EQ(parser.getRequest().method, H1_GET);
    EXPECT_EQ(parser.getRequest().path, "/test");
    EXPECT_EQ(parser.getHeader("host"), "example.com");
}

TEST(SerializeTest, RequestWithBody) {
    Http1Request req;
    req.method = H1_POST;
    req.path = "/api";
    req.version = H1_VER_1_1;

    std::vector<Http1Header> headers = {{"Host", "example.com"}, {"Content-Type", "text/plain"}};
    std::string body = "hello";
    auto wire = Http1Parser::serializeRequest(
        req, headers,
        reinterpret_cast<const uint8_t*>(body.data()), body.size());

    Http1Parser parser;
    parser.feed(wire.data(), wire.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().method, H1_POST);
    EXPECT_EQ(std::string(parser.getBody().begin(), parser.getBody().end()), "hello");
}

// ══════════════════════════════════════════════════════════════════════
// P7-010: Response Serialization
// ══════════════════════════════════════════════════════════════════════

TEST(SerializeTest, ResponseRoundTrip) {
    Http1Response resp;
    resp.status_code = 200;
    resp.reason = "OK";
    resp.version = H1_VER_1_1;

    std::vector<Http1Header> headers = {{"Content-Type", "text/html"}};
    std::string body = "<html></html>";
    auto wire = Http1Parser::serializeResponse(
        resp, headers,
        reinterpret_cast<const uint8_t*>(body.data()), body.size());

    Http1Parser parser;
    parser.feed(wire.data(), wire.size());
    ASSERT_TRUE(parser.isComplete());
    ASSERT_TRUE(parser.isResponse());
    EXPECT_EQ(parser.getResponse().status_code, 200);
    EXPECT_EQ(std::string(parser.getBody().begin(), parser.getBody().end()), "<html></html>");
}

TEST(SerializeTest, ResponseNoBody) {
    Http1Response resp;
    resp.status_code = 204;
    resp.reason = "No Content";
    resp.version = H1_VER_1_1;

    auto wire = Http1Parser::serializeResponse(resp, {}, nullptr, 0);
    Http1Parser parser;
    parser.feed(wire.data(), wire.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getResponse().status_code, 204);
    EXPECT_TRUE(parser.getBody().empty());
}

TEST(SerializeTest, ChunkSerializeRoundTrip) {
    // Serialize a chunk and verify it
    std::string data = "hello";
    auto chunk = Http1Parser::serializeChunk(
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
    std::string s(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    EXPECT_EQ(s, "5\r\nhello\r\n");

    auto end = Http1Parser::serializeChunkEnd();
    s = std::string(reinterpret_cast<const char*>(end.data()), end.size());
    EXPECT_EQ(s, "0\r\n\r\n");
}

// ══════════════════════════════════════════════════════════════════════
// Edge Cases
// ══════════════════════════════════════════════════════════════════════

TEST(EdgeCaseTest, EmptyInput) {
    Http1Parser parser;
    size_t n = parser.feed(nullptr, 0);
    EXPECT_EQ(n, 0);
    EXPECT_FALSE(parser.isComplete());
    EXPECT_FALSE(parser.hasError());
}

TEST(EdgeCaseTest, ResetReuse) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());

    parser.reset();
    EXPECT_FALSE(parser.isComplete());
    EXPECT_FALSE(parser.hasError());

    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    ASSERT_TRUE(parser.isResponse());
    EXPECT_EQ(parser.getResponse().status_code, 200);
}

TEST(EdgeCaseTest, HEADRequestNoBody) {
    Http1Parser parser;
    std::string req = "HEAD / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.getBody().empty());
}

TEST(EdgeCaseTest, StreamingPartialFeed) {
    Http1Parser parser;
    std::string chunk1 = "HTTP/1.1 200 OK\r\nContent";
    std::string chunk2 = "-Length: 5\r\n\r\nhello";

    parser.feed(reinterpret_cast<const uint8_t*>(chunk1.data()), chunk1.size());
    EXPECT_FALSE(parser.isComplete());
    EXPECT_FALSE(parser.hasError());

    parser.feed(reinterpret_cast<const uint8_t*>(chunk2.data()), chunk2.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(std::string(parser.getBody().begin(), parser.getBody().end()), "hello");
}

TEST(EdgeCaseTest, StreamingByteByByte) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

    for (size_t i = 0; i < resp.size(); ++i) {
        parser.feed(reinterpret_cast<const uint8_t*>(resp.data() + i), 1);
    }
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(std::string(parser.getBody().begin(), parser.getBody().end()), "hello");
}

TEST(EdgeCaseTest, GetHeaderValuesMultiCookie) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\n"
                      "Host: a.com\r\n"
                      "Cookie: x=1\r\n"
                      "Cookie: y=2\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    auto vals = parser.getHeaderValues("cookie");
    ASSERT_EQ(vals.size(), 2);
    EXPECT_EQ(vals[0], "x=1");
    EXPECT_EQ(vals[1], "y=2");
}

TEST(EdgeCaseTest, ContentLengthThenChunkedConflict) {
    // RFC 7230 §3.3.3: Transfer-Encoding takes precedence
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\n"
                       "Content-Length: 100\r\n"
                       "Transfer-Encoding: chunked\r\n\r\n"
                       "5\r\nhello\r\n0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    // Should have used chunked, not content-length
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "hello");
}

// ══════════════════════════════════════════════════════════════════════
// Feed Round-Trip (Full Request/Response Cycles)
// ══════════════════════════════════════════════════════════════════════

TEST(FeedRoundTripTest, FullRequestResponse) {
    // Simple GET request
    Http1Parser req_parser;
    std::string req = "GET /index.html HTTP/1.1\r\n"
                      "Host: www.example.com\r\n"
                      "User-Agent: test\r\n"
                      "Accept: text/html\r\n\r\n";
    req_parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(req_parser.isComplete());
    EXPECT_EQ(req_parser.getRequest().method, H1_GET);
    EXPECT_EQ(req_parser.getRequest().path, "/index.html");
    EXPECT_EQ(req_parser.getHeader("host"), "www.example.com");

    // Serialize response
    Http1Response resp;
    resp.status_code = 200;
    resp.reason = "OK";
    resp.version = H1_VER_1_1;
    std::vector<Http1Header> resp_headers = {
        {"Content-Type", "text/html"},
        {"Server", "PNTP/4.0"}
    };
    std::string body = "<html><body>Hello</body></html>";
    auto resp_wire = Http1Parser::serializeResponse(
        resp, resp_headers,
        reinterpret_cast<const uint8_t*>(body.data()), body.size());

    // Parse response
    Http1Parser resp_parser;
    resp_parser.feed(resp_wire.data(), resp_wire.size());
    ASSERT_TRUE(resp_parser.isComplete());
    ASSERT_TRUE(resp_parser.isResponse());
    EXPECT_EQ(resp_parser.getResponse().status_code, 200);
    EXPECT_EQ(resp_parser.getHeader("content-type"), "text/html");
    EXPECT_EQ(resp_parser.getHeader("server"), "PNTP/4.0");
    EXPECT_EQ(std::string(resp_parser.getBody().begin(), resp_parser.getBody().end()), body);
}

TEST(FeedRoundTripTest, PostRequestWithChunkedBody) {
    // POST with chunked
    Http1Parser parser;
    std::string req = "POST /api/data HTTP/1.1\r\n"
                      "Host: example.com\r\n"
                      "Transfer-Encoding: chunked\r\n\r\n"
                      "5\r\nhello\r\n"
                      "0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().method, H1_POST);
    EXPECT_EQ(std::string(parser.getBody().begin(), parser.getBody().end()), "hello");
}

TEST(FeedRoundTripTest, ResponseWithConnectionClose) {
    // HTTP/1.1 with Connection: close
    std::string resp = "HTTP/1.1 200 OK\r\n"
                       "Connection: close\r\n"
                       "Content-Type: text/plain\r\n\r\n"
                       "This is a body that ends with connection close";
    Http1Parser parser;
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.shouldClose());
    EXPECT_EQ(parser.getResponse().status_code, 200);
    auto body = parser.getBody();
    EXPECT_EQ(std::string(body.begin(), body.end()), "This is a body that ends with connection close");
}

// ══════════════════════════════════════════════════════════════════════
// P7-011: Mass Parse Test — 1000 Random HTTP Messages
// ══════════════════════════════════════════════════════════════════════

static std::string randomString(size_t len) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.";
    static std::mt19937 rng(42);
    std::uniform_int_distribution<size_t> dist(0, sizeof(chars) - 2);
    std::string s;
    for (size_t i = 0; i < len; ++i) s += chars[dist(rng)];
    return s;
}

TEST(MassParseTest, Parse1000RandomRequests) {
    std::vector<std::string> methods = {"GET", "POST", "PUT", "DELETE", "HEAD", "PATCH"};
    std::vector<std::string> paths = {"/", "/index.html", "/api/data", "/search?q=hello"};
    std::vector<std::string> headers = {"Host", "User-Agent", "Accept", "Content-Type",
                                         "X-Custom", "Authorization", "Cache-Control"};

    std::mt19937 rng(12345);
    std::uniform_int_distribution<size_t> method_dist(0, methods.size() - 1);
    std::uniform_int_distribution<size_t> path_dist(0, paths.size() - 1);
    std::uniform_int_distribution<size_t> header_dist(0, headers.size() - 1);
    std::uniform_int_distribution<size_t> num_headers_dist(1, 8);
    std::uniform_int_distribution<size_t> body_len_dist(0, 1000);

    for (int i = 0; i < 1000; ++i) {
        std::ostringstream oss;
        oss << methods[method_dist(rng)] << " "
            << paths[path_dist(rng)] << " HTTP/1.1\r\n";

        size_t nh = num_headers_dist(rng);
        for (size_t h = 0; h < nh; ++h) {
            oss << headers[header_dist(rng)] << ": "
                << randomString(5 + rng() % 50) << "\r\n";
        }

        size_t bl = body_len_dist(rng);
        if (bl > 0) {
            oss << "Content-Length: " << bl << "\r\n\r\n";
            oss << randomString(bl);
        } else {
            oss << "\r\n";
        }

        std::string message = oss.str();
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(message.data()), message.size());
        EXPECT_TRUE(parser.isComplete()) << "Failed on message " << i;
        EXPECT_FALSE(parser.hasError()) << "Error on message " << i;

        if (bl > 0) {
            EXPECT_EQ(parser.getBody().size(), bl)
                << "Body size mismatch on message " << i;
        }
    }
}

TEST(MassParseTest, Parse1000RandomResponses) {
    std::vector<uint16_t> statuses = {200, 201, 204, 301, 302, 304,
                                      400, 401, 403, 404, 413, 429, 500, 502, 503};
    std::vector<std::string> reasons = {"OK", "Created", "No Content", "Moved",
                                         "Found", "Not Modified", "Bad Request",
                                         "Unauthorized", "Forbidden", "Not Found",
                                         "Not Acceptable", "Conflict", "Gone",
                                         "Too Many Requests", "Internal Server Error",
                                         "Bad Gateway", "Service Unavailable"};

    std::mt19937 rng(54321);
    std::uniform_int_distribution<size_t> status_dist(0, statuses.size() - 1);
    std::uniform_int_distribution<size_t> reason_dist(0, reasons.size() - 1);
    std::uniform_int_distribution<size_t> num_headers_dist(1, 10);
    std::uniform_int_distribution<size_t> body_len_dist(0, 2000);

    for (int i = 0; i < 1000; ++i) {
        std::ostringstream oss;
        uint16_t code = statuses[status_dist(rng)];
        oss << "HTTP/1.1 " << code << " "
            << reasons[reason_dist(rng)] << "\r\n";

        size_t nh = num_headers_dist(rng);
        for (size_t h = 0; h < nh; ++h) {
            oss << "X-Header-" << h << ": " << randomString(10 + rng() % 40) << "\r\n";
        }

        if (code / 100 != 1 && code != 204 && code != 304) {
            size_t bl = body_len_dist(rng);
            oss << "Content-Length: " << bl << "\r\n\r\n";
            if (bl > 0) oss << randomString(bl);
        } else {
            oss << "Content-Length: 0\r\n\r\n";
        }

        std::string message = oss.str();
        Http1Parser parser;
        parser.feed(reinterpret_cast<const uint8_t*>(message.data()), message.size());
        EXPECT_TRUE(parser.isComplete()) << "Failed on response " << i << " code " << code;
        EXPECT_FALSE(parser.hasError()) << "Error on response " << i << " code " << code;
        EXPECT_EQ(parser.getResponse().status_code, code)
            << "Status mismatch on response " << i;
    }
}

// ══════════════════════════════════════════════════════════════════════
// P7-012: Goal Validation Tests
// ══════════════════════════════════════════════════════════════════════

TEST(GoalValidationTest, RequestLineParserWorks) {
    Http1Parser parser;
    std::string req = "GET /path HTTP/1.1\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().method, H1_GET);
    EXPECT_EQ(parser.getRequest().path, "/path");
}

TEST(GoalValidationTest, ResponseLineParserWorks) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getResponse().status_code, 200);
}

TEST(GoalValidationTest, HeaderParserWorks) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nHost: test.com\r\nUser-Agent: x\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getHeader("host"), "test.com");
    EXPECT_EQ(parser.getHeader("user-agent"), "x");
}

TEST(GoalValidationTest, ChunkedDecodingWorks) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                       "A\r\n0123456789\r\n"
                       "0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(std::string(parser.getBody().begin(), parser.getBody().end()), "0123456789");
}

TEST(GoalValidationTest, ContentLengthBodyWorks) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(std::string(parser.getBody().begin(), parser.getBody().end()), "abc");
}

TEST(GoalValidationTest, ConnectionCloseTracking) {
    Http1Parser parser;
    std::string resp = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 1\r\n\r\nx";
    parser.feed(reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.shouldClose());
}

TEST(GoalValidationTest, UpgradeH2CDetection) {
    Http1Parser parser;
    std::string req = "GET / HTTP/1.1\r\nUpgrade: h2c\r\nConnection: Upgrade\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.upgradeDetected());
    EXPECT_EQ(parser.getUpgradeInfo().type, H1_UPGRADE_H2C);
}

TEST(GoalValidationTest, ExpectContinueDetection) {
    Http1Parser parser;
    std::string req = "POST / HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 0\r\n\r\n";
    parser.feed(reinterpret_cast<const uint8_t*>(req.data()), req.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_TRUE(parser.expectContinue());
}

TEST(GoalValidationTest, RequestSerializationWorks) {
    Http1Request req;
    req.method = H1_GET;
    req.path = "/";
    req.version = H1_VER_1_1;
    auto wire = Http1Parser::serializeRequest(req, {{"Host", "a.com"}}, nullptr, 0);
    Http1Parser parser;
    parser.feed(wire.data(), wire.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().method, H1_GET);
}

TEST(GoalValidationTest, ResponseSerializationWorks) {
    Http1Response resp;
    resp.status_code = 200;
    resp.reason = "OK";
    auto wire = Http1Parser::serializeResponse(resp, {}, nullptr, 0);
    Http1Parser parser;
    parser.feed(wire.data(), wire.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getResponse().status_code, 200);
}

// ══════════════════════════════════════════════════════════════════════
// Serialize + Chunked Encoding
// ══════════════════════════════════════════════════════════════════════

TEST(SerializeTest, RequestWithQueryString) {
    Http1Request req;
    req.method = H1_GET;
    req.path = "/search";
    req.query = "q=hello&page=1";
    req.version = H1_VER_1_1;

    auto wire = Http1Parser::serializeRequest(req, {{"Host", "example.com"}}, nullptr, 0);
    std::string s(reinterpret_cast<const char*>(wire.data()), wire.size());
    EXPECT_TRUE(s.find("GET /search?q=hello&page=1 HTTP/1.1") != std::string::npos);

    // Parse it back
    Http1Parser parser;
    parser.feed(wire.data(), wire.size());
    ASSERT_TRUE(parser.isComplete());
    EXPECT_EQ(parser.getRequest().method, H1_GET);
    EXPECT_EQ(parser.getRequest().path, "/search");
    EXPECT_EQ(parser.getRequest().query, "q=hello&page=1");
}

// ══════════════════════════════════════════════════════════════════════
// Main
// ══════════════════════════════════════════════════════════════════════
