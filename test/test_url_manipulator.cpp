#include "pntp/url_manipulator.h"
#include <gtest/gtest.h>

class UrlManipulatorTest : public ::testing::Test {
protected:
    UrlManipulator manipulator;
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(UrlManipulatorTest, RewriteUrl_ReturnsOriginal) {
    std::string url = "https://learn.udacity.com/course";
    std::string result = manipulator.rewriteUrl(url);
    EXPECT_EQ(result, url);
}

TEST_F(UrlManipulatorTest, ModifyRequestHeaders_AddsUserAgent) {
    std::map<std::string, std::string> headers;
    auto modified = manipulator.modifyRequestHeaders("https://example.com", headers);
    EXPECT_EQ(modified["User-Agent"], "PNTP-Transcendent-Browser/4.0");
}

TEST_F(UrlManipulatorTest, ModifyRequestHeaders_WithAuthToken) {
    manipulator.setAuthenticationToken("test_token_123");
    std::map<std::string, std::string> headers;
    auto modified = manipulator.modifyRequestHeaders("https://example.com", headers);
    EXPECT_EQ(modified["Authorization"], "Bearer test_token_123");
}

TEST_F(UrlManipulatorTest, SetAndGetAuthToken) {
    manipulator.setAuthenticationToken("secret");
    EXPECT_EQ(manipulator.getAuthenticationToken(), "secret");
}

TEST_F(UrlManipulatorTest, ShouldIntercept_ReturnsTrueForHttps) {
    EXPECT_TRUE(manipulator.shouldIntercept("https://example.com"));
}

TEST_F(UrlManipulatorTest, ShouldIntercept_ReturnsFalseForHttp) {
    EXPECT_FALSE(manipulator.shouldIntercept("http://example.com"));
}

TEST_F(UrlManipulatorTest, AuthTokenRoundTrip) {
    manipulator.setAuthenticationToken("round_trip_test");
    auto headers = manipulator.modifyRequestHeaders("https://test.com", {});
    EXPECT_EQ(headers["Authorization"], "Bearer round_trip_test");
    EXPECT_EQ(manipulator.getAuthenticationToken(), "round_trip_test");
}
