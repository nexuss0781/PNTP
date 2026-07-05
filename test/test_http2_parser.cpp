#include "pntp/http2_parser.h"
#include <gtest/gtest.h>
#include <cstring>

class Http2ParserTest : public ::testing::Test {
protected:
    Http2Parser parser;
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(Http2ParserTest, ParseEmptyData_ReturnsNoFrames) {
    std::vector<unsigned char> empty;
    auto frames = parser.parseData(empty);
    EXPECT_EQ(frames.size(), 0);
}

TEST_F(Http2ParserTest, ParseSingleFrame_RoundTrip) {
    Http2Frame original;
    original.length = 4;
    original.type = 1;          // HEADERS
    original.flags = 0x04;      // END_HEADERS
    original.stream_id = 1;
    original.payload = {0x00, 0x01, 0x02, 0x03};

    auto wire = parser.serializeFrames({original});
    auto parsed = parser.parseData(wire);

    ASSERT_EQ(parsed.size(), 1);
    EXPECT_EQ(parsed[0].length, original.length);
    EXPECT_EQ(parsed[0].type, original.type);
    EXPECT_EQ(parsed[0].flags, original.flags);
    EXPECT_EQ(parsed[0].stream_id, original.stream_id);
    EXPECT_EQ(parsed[0].payload, original.payload);
}

TEST_F(Http2ParserTest, ParseMultipleFrames) {
    Http2Frame f1, f2;
    f1.length = 0; f1.type = 4; f1.flags = 0; f1.stream_id = 0;  // SETTINGS
    f2.length = 5; f2.type = 1; f2.flags = 0x04; f2.stream_id = 3;
    f2.payload = {'h', 'e', 'l', 'l', 'o'};

    auto wire = parser.serializeFrames({f1, f2});
    auto parsed = parser.parseData(wire);

    ASSERT_EQ(parsed.size(), 2);
    EXPECT_EQ(parsed[0].type, 4);
    EXPECT_EQ(parsed[1].type, 1);
    EXPECT_EQ(parsed[1].stream_id, 3u);
}

TEST_F(Http2ParserTest, ParseIncompleteFrame_ReturnsPartial) {
    std::vector<unsigned char> incomplete = {0x00, 0x00, 0x05, 0x01, 0x00,
                                              0x00, 0x00, 0x00, 0x01,
                                              0x01, 0x02};  // only 2/5 payload bytes
    auto frames = parser.parseData(incomplete);
    EXPECT_EQ(frames.size(), 0);  // should detect incomplete and break
}

TEST_F(Http2ParserTest, SerializeAndParse_LargePayload) {
    Http2Frame frame;
    frame.length = 256;
    frame.type = 0;  // DATA
    frame.flags = 1; // END_STREAM
    frame.stream_id = 5;
    frame.payload.resize(256);
    for (int i = 0; i < 256; ++i) frame.payload[i] = static_cast<unsigned char>(i);

    auto wire = parser.serializeFrames({frame});
    auto parsed = parser.parseData(wire);

    ASSERT_EQ(parsed.size(), 1);
    EXPECT_EQ(parsed[0].length, 256u);
    EXPECT_EQ(parsed[0].type, 0);
    EXPECT_EQ(parsed[0].stream_id, 5u);
    ASSERT_EQ(parsed[0].payload.size(), 256);
    EXPECT_EQ(parsed[0].payload[0], 0);
    EXPECT_EQ(parsed[0].payload[255], 255);
}
