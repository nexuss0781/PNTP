#include "pntp/data_extractor.h"
#include <gtest/gtest.h>

class DataExtractorTest : public ::testing::Test {
protected:
    DataExtractor extractor;
    void SetUp() override {}
    void TearDown() override {}
};

TEST_F(DataExtractorTest, ExtractHtmlTitle) {
    std::string html = "<html><head><title>Test Course</title></head></html>";
    auto data = extractor.extractData("text/html", html);
    EXPECT_EQ(data["page_title"], "Test Course");
}

TEST_F(DataExtractorTest, ExtractEmptyHtml) {
    std::string html = "";
    auto data = extractor.extractData("text/html", html);
    EXPECT_TRUE(data.empty());
}

TEST_F(DataExtractorTest, FindYoutubeUrl) {
    std::string html = R"(<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ"></iframe>)";
    auto urls = extractor.findVideoUrls(html);
    ASSERT_EQ(urls.size(), 1);
    EXPECT_EQ(urls[0], "https://www.youtube.com/embed/dQw4w9WgXcQ");
}

TEST_F(DataExtractorTest, FindMultipleYoutubeUrls) {
    std::string html = R"(
        <iframe src="https://www.youtube.com/embed/abc123"></iframe>
        <iframe src="https://www.youtube.com/embed/xyz789"></iframe>
    )";
    auto urls = extractor.findVideoUrls(html);
    EXPECT_EQ(urls.size(), 2);
}

TEST_F(DataExtractorTest, ExtractJsonCourseName) {
    std::string json = R"({"courseName": "Self Driving Cars"})";
    auto data = extractor.extractData("application/json", json);
    EXPECT_EQ(data["json_course_name"], "Self Driving Cars");
}

TEST_F(DataExtractorTest, ExtractUnknownContentType) {
    std::string data = "some binary data";
    auto result = extractor.extractData("application/octet-stream", data);
    EXPECT_TRUE(result.empty());
}

TEST_F(DataExtractorTest, ParseHtmlForElement_ReturnsEmpty) {
    std::string result = extractor.parseHtmlForElement("<div>test</div>", "div", "class");
    EXPECT_TRUE(result.empty());
}
