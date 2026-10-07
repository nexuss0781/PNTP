#include "pntp/data_extractor.h"
#include <gtest/gtest.h>
#include <string>
#include <vector>
#include <map>

// ─── Fixture ──────────────────────────────────────────────────────────────

class DataExtractorTest : public ::testing::Test {
protected:
    DataExtractor extractor;

    void SetUp() override {}
    void TearDown() override {}
};

// ─── Helpers to avoid repetition in every test ──────────────────────────

// ─── SAX HTML Tokenizer Tests (25+) ──────────────────────────────────────

TEST_F(DataExtractorTest, SaxBasicElement) {
    auto tokens = DataExtractor::SAXParser().parse("<div>hello</div>");
    ASSERT_GE(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "div");
    EXPECT_EQ(tokens[1].type, SAXToken::TEXT);
    EXPECT_EQ(tokens[1].content, "hello");
    EXPECT_EQ(tokens[2].type, SAXToken::TAG_CLOSE);
    EXPECT_EQ(tokens[2].name, "div");
    EXPECT_EQ(tokens.back().type, SAXToken::EOF_);
}

TEST_F(DataExtractorTest, SaxWithAttributes) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<img src="a.jpg" alt="b">)");
    ASSERT_GE(tokens.size(), 2);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "img");
    ASSERT_EQ(tokens[0].attributes.size(), 2);
    EXPECT_EQ(tokens[0].attributes[0].name, "src");
    EXPECT_EQ(tokens[0].attributes[0].value, "a.jpg");
    EXPECT_TRUE(tokens[0].attributes[0].quoted);
    EXPECT_EQ(tokens[0].attributes[1].name, "alt");
    EXPECT_EQ(tokens[0].attributes[1].value, "b");
    EXPECT_TRUE(tokens[0].attributes[1].quoted);
}

TEST_F(DataExtractorTest, SaxSelfClosing) {
    auto tokens = DataExtractor::SAXParser().parse("<br/>");
    ASSERT_GE(tokens.size(), 2);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "br");
    EXPECT_EQ(tokens.back().type, SAXToken::EOF_);
}

TEST_F(DataExtractorTest, SaxMultipleElementsNested) {
    auto tokens = DataExtractor::SAXParser().parse("<ul><li>a</li><li>b</li></ul>");
    ASSERT_GE(tokens.size(), 5);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "ul");
    EXPECT_EQ(tokens[1].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[1].name, "li");
    EXPECT_EQ(tokens[2].type, SAXToken::TEXT);
    EXPECT_EQ(tokens[2].content, "a");
    EXPECT_EQ(tokens[3].type, SAXToken::TAG_CLOSE);
    EXPECT_EQ(tokens[3].name, "li");
}

TEST_F(DataExtractorTest, SaxComment) {
    auto tokens = DataExtractor::SAXParser().parse("<!-- comment --><div>x</div>");
    ASSERT_GE(tokens.size(), 4);
    EXPECT_EQ(tokens[0].type, SAXToken::COMMENT);
    EXPECT_EQ(tokens[0].content, " comment ");
    EXPECT_EQ(tokens[1].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[1].name, "div");
}

TEST_F(DataExtractorTest, SaxCDATA) {
    auto tokens = DataExtractor::SAXParser().parse("<![CDATA[data]]><div>x</div>");
    ASSERT_GE(tokens.size(), 4);
    EXPECT_EQ(tokens[0].type, SAXToken::CDATA);
    EXPECT_EQ(tokens[0].content, "data");
}

TEST_F(DataExtractorTest, SaxDOCTYPE) {
    auto tokens = DataExtractor::SAXParser().parse("<!DOCTYPE html><div>x</div>");
    ASSERT_GE(tokens.size(), 4);
    EXPECT_EQ(tokens[0].type, SAXToken::DOCTYPE);
    EXPECT_EQ(tokens[0].content, " html");
}

TEST_F(DataExtractorTest, SaxScriptContent) {
    auto tokens = DataExtractor::SAXParser().parse("<script>var x = 1;</script>");
    ASSERT_GE(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "script");
    EXPECT_EQ(tokens[1].type, SAXToken::SCRIPT);
    EXPECT_EQ(tokens[1].content, "var x = 1;");
    EXPECT_EQ(tokens[2].type, SAXToken::TAG_CLOSE);
    EXPECT_EQ(tokens[2].name, "script");
}

TEST_F(DataExtractorTest, SaxStyleContent) {
    auto tokens = DataExtractor::SAXParser().parse("<style>body{}</style>");
    ASSERT_GE(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "style");
    EXPECT_EQ(tokens[1].type, SAXToken::STYLE);
    EXPECT_EQ(tokens[1].content, "body{}");
    EXPECT_EQ(tokens[2].type, SAXToken::TAG_CLOSE);
    EXPECT_EQ(tokens[2].name, "style");
}

TEST_F(DataExtractorTest, SaxAttributeSingleQuotes) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<div class='foo'>text</div>)");
    ASSERT_GE(tokens.size(), 3);
    ASSERT_EQ(tokens[0].attributes.size(), 1);
    EXPECT_EQ(tokens[0].attributes[0].name, "class");
    EXPECT_EQ(tokens[0].attributes[0].value, "foo");
    EXPECT_TRUE(tokens[0].attributes[0].quoted);
}

TEST_F(DataExtractorTest, SaxAttributeUnquoted) {
    auto tokens = DataExtractor::SAXParser().parse("<div class=foo>text</div>");
    ASSERT_GE(tokens.size(), 3);
    ASSERT_EQ(tokens[0].attributes.size(), 1);
    EXPECT_EQ(tokens[0].attributes[0].name, "class");
    EXPECT_EQ(tokens[0].attributes[0].value, "foo");
    EXPECT_FALSE(tokens[0].attributes[0].quoted);
}

TEST_F(DataExtractorTest, SaxBooleanAttribute) {
    auto tokens = DataExtractor::SAXParser().parse("<input disabled>");
    ASSERT_GE(tokens.size(), 2);
    ASSERT_EQ(tokens[0].attributes.size(), 1);
    EXPECT_EQ(tokens[0].attributes[0].name, "disabled");
    EXPECT_TRUE(tokens[0].attributes[0].value.empty());
}

TEST_F(DataExtractorTest, SaxEmptyInput) {
    auto tokens = DataExtractor::SAXParser().parse("");
    ASSERT_EQ(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, SAXToken::EOF_);
}

TEST_F(DataExtractorTest, SaxMultipleTextNodes) {
    auto tokens = DataExtractor::SAXParser().parse("a<div>b</div>c");
    ASSERT_GE(tokens.size(), 5);
    EXPECT_EQ(tokens[0].type, SAXToken::TEXT);
    EXPECT_EQ(tokens[0].content, "a");
    EXPECT_EQ(tokens[1].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[1].name, "div");
    EXPECT_EQ(tokens[2].type, SAXToken::TEXT);
    EXPECT_EQ(tokens[2].content, "b");
    EXPECT_EQ(tokens[3].type, SAXToken::TAG_CLOSE);
    EXPECT_EQ(tokens[3].name, "div");
    EXPECT_EQ(tokens[4].type, SAXToken::TEXT);
    EXPECT_EQ(tokens[4].content, "c");
}

TEST_F(DataExtractorTest, SaxNestedDeep) {
    auto tokens = DataExtractor::SAXParser().parse("<div><p><span>deep</span></p></div>");
    ASSERT_GE(tokens.size(), 7);
    EXPECT_EQ(tokens[0].name, "div");
    EXPECT_EQ(tokens[1].name, "p");
    EXPECT_EQ(tokens[2].name, "span");
    EXPECT_EQ(tokens[3].type, SAXToken::TEXT);
    EXPECT_EQ(tokens[3].content, "deep");
    EXPECT_EQ(tokens[4].name, "span");
    EXPECT_EQ(tokens[4].type, SAXToken::TAG_CLOSE);
    EXPECT_EQ(tokens[5].name, "p");
    EXPECT_EQ(tokens[5].type, SAXToken::TAG_CLOSE);
    EXPECT_EQ(tokens[6].name, "div");
    EXPECT_EQ(tokens[6].type, SAXToken::TAG_CLOSE);
}

TEST_F(DataExtractorTest, SaxVoidElementsAutoClose) {
    auto tokens = DataExtractor::SAXParser().parse("<br><br>");
    ASSERT_GE(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "br");
    EXPECT_EQ(tokens[1].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[1].name, "br");
    EXPECT_EQ(tokens[2].type, SAXToken::EOF_);
}

TEST_F(DataExtractorTest, SaxTagNameCaseInsensitivity) {
    auto tokens = DataExtractor::SAXParser().parse("<DIV>Hello</DIV>");
    ASSERT_GE(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "DIV");
    EXPECT_EQ(tokens[2].type, SAXToken::TAG_CLOSE);
    EXPECT_EQ(tokens[2].name, "DIV");
}

TEST_F(DataExtractorTest, SaxTokenOffsetPopulated) {
    auto tokens = DataExtractor::SAXParser().parse("<div>text</div>");
    EXPECT_EQ(tokens[0].offset, 0);
    EXPECT_GT(tokens[0].length, 0);
    EXPECT_GT(tokens[1].offset, 0);
    EXPECT_GT(tokens[1].length, 0);
    EXPECT_GT(tokens[2].offset, 0);
    EXPECT_GT(tokens[2].length, 0);
}

TEST_F(DataExtractorTest, SaxCallbackVersion) {
    std::vector<SAXToken> cb_tokens;
    DataExtractor::SAXParser().parse("<div>hello</div>",
        [&](const SAXToken& t) -> bool { cb_tokens.push_back(t); return true; });
    auto vec_tokens = DataExtractor::SAXParser().parse("<div>hello</div>");
    ASSERT_EQ(cb_tokens.size(), vec_tokens.size());
    for (size_t i = 0; i < cb_tokens.size(); ++i) {
        EXPECT_EQ(cb_tokens[i].type, vec_tokens[i].type);
        EXPECT_EQ(cb_tokens[i].name, vec_tokens[i].name);
        EXPECT_EQ(cb_tokens[i].content, vec_tokens[i].content);
    }
}

TEST_F(DataExtractorTest, SaxIsVoidElement) {
    EXPECT_TRUE(DataExtractor::SAXParser::isVoidElement("br"));
    EXPECT_TRUE(DataExtractor::SAXParser::isVoidElement("img"));
    EXPECT_TRUE(DataExtractor::SAXParser::isVoidElement("input"));
    EXPECT_TRUE(DataExtractor::SAXParser::isVoidElement("hr"));
    EXPECT_TRUE(DataExtractor::SAXParser::isVoidElement("BR"));
    EXPECT_FALSE(DataExtractor::SAXParser::isVoidElement("div"));
    EXPECT_FALSE(DataExtractor::SAXParser::isVoidElement("span"));
}

TEST_F(DataExtractorTest, SaxIsRawTextElement) {
    EXPECT_TRUE(DataExtractor::SAXParser::isRawTextElement("script"));
    EXPECT_TRUE(DataExtractor::SAXParser::isRawTextElement("style"));
    EXPECT_TRUE(DataExtractor::SAXParser::isRawTextElement("textarea"));
    EXPECT_TRUE(DataExtractor::SAXParser::isRawTextElement("title"));
    EXPECT_FALSE(DataExtractor::SAXParser::isRawTextElement("div"));
}

TEST_F(DataExtractorTest, HtmlEntityDecodeAmp) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&amp;"), "&");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeLt) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&lt;"), "<");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeGt) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&gt;"), ">");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeQuot) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&quot;"), "\"");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeNumeric) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&#65;"), "A");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeHex) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&#x41;"), "A");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeUnknownPassThrough) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&unknown;"), "&unknown;");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeApos) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&apos;"), "'");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeNoEntity) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("no entities here"), "no entities here");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeMultiple) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&lt;div&gt;"), "<div>");
}

TEST_F(DataExtractorTest, HtmlEntityDecodeMixed) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("a&lt;b&gt;c&amp;d&quot;e"),
              "a<b>c&d\"e");
}

TEST_F(DataExtractorTest, SaxScriptWithHtmlInside) {
    auto tokens = DataExtractor::SAXParser().parse(
        "<script>if (a < b) {}</script>");
    ASSERT_GE(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "script");
    EXPECT_EQ(tokens[1].type, SAXToken::SCRIPT);
    EXPECT_EQ(tokens[1].content, "if (a < b) {}");
}

// ─── CSS Selector Engine Tests (20+) ─────────────────────────────────────

TEST_F(DataExtractorTest, CssCompileTag) {
    auto cs = DataExtractor::SelectorEngine().compile("h1");
    ASSERT_EQ(cs.parts.size(), 1);
    ASSERT_EQ(cs.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::TAG);
    EXPECT_EQ(cs.parts[0].compound.simples[0].name, "h1");
}

TEST_F(DataExtractorTest, CssCompileClass) {
    auto cs = DataExtractor::SelectorEngine().compile(".cls");
    ASSERT_GE(cs.parts.size(), 1);
    ASSERT_GE(cs.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::CLASS);
    EXPECT_EQ(cs.parts[0].compound.simples[0].name, "cls");
}

TEST_F(DataExtractorTest, CssCompileId) {
    auto cs = DataExtractor::SelectorEngine().compile("#myid");
    ASSERT_GE(cs.parts.size(), 1);
    ASSERT_GE(cs.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::ID);
    EXPECT_EQ(cs.parts[0].compound.simples[0].name, "myid");
}

TEST_F(DataExtractorTest, CssCompileCompound) {
    auto cs = DataExtractor::SelectorEngine().compile("div#id.cls");
    ASSERT_GE(cs.parts[0].compound.simples.size(), 3);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::TAG);
    EXPECT_EQ(cs.parts[0].compound.simples[0].name, "div");
    EXPECT_EQ(cs.parts[0].compound.simples[1].type, SimpleSelector::ID);
    EXPECT_EQ(cs.parts[0].compound.simples[1].name, "id");
    EXPECT_EQ(cs.parts[0].compound.simples[2].type, SimpleSelector::CLASS);
    EXPECT_EQ(cs.parts[0].compound.simples[2].name, "cls");
}

TEST_F(DataExtractorTest, CssCompileAttrPresence) {
    auto cs = DataExtractor::SelectorEngine().compile("[data-x]");
    ASSERT_GE(cs.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::ATTR_PRESENCE);
    EXPECT_EQ(cs.parts[0].compound.simples[0].name, "data-x");
}

TEST_F(DataExtractorTest, CssCompileAttrEquals) {
    auto cs = DataExtractor::SelectorEngine().compile("[type=text]");
    ASSERT_GE(cs.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::ATTR_EQUALS);
    EXPECT_EQ(cs.parts[0].compound.simples[0].name, "type");
    EXPECT_EQ(cs.parts[0].compound.simples[0].value, "text");
}

TEST_F(DataExtractorTest, CssCompileChildCombinator) {
    auto cs = DataExtractor::SelectorEngine().compile("div > p");
    ASSERT_EQ(cs.parts.size(), 2);
    EXPECT_EQ(cs.parts[1].combinator, CHILD);
    EXPECT_EQ(cs.parts[1].compound.simples[0].name, "p");
}

TEST_F(DataExtractorTest, CssCompileDescendantCombinator) {
    auto cs = DataExtractor::SelectorEngine().compile("div p");
    ASSERT_EQ(cs.parts.size(), 2);
    EXPECT_EQ(cs.parts[1].combinator, DESCENDANT);
    EXPECT_EQ(cs.parts[1].compound.simples[0].name, "p");
}

TEST_F(DataExtractorTest, CssCompileAdjacentSibling) {
    auto cs = DataExtractor::SelectorEngine().compile("h1 + p");
    ASSERT_EQ(cs.parts.size(), 2);
    EXPECT_EQ(cs.parts[1].combinator, ADJACENT_SIBLING);
}

TEST_F(DataExtractorTest, CssCompileGeneralSibling) {
    auto cs = DataExtractor::SelectorEngine().compile("h1 ~ p");
    ASSERT_EQ(cs.parts.size(), 2);
    EXPECT_EQ(cs.parts[1].combinator, GENERAL_SIBLING);
}

TEST_F(DataExtractorTest, CssCompileNthChild) {
    auto cs = DataExtractor::SelectorEngine().compile(":nth-child(2)");
    ASSERT_GE(cs.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::NTH_CHILD);
    EXPECT_EQ(cs.parts[0].compound.simples[0].name, "2");
}

TEST_F(DataExtractorTest, CssSelectTag) {
    auto tokens = DataExtractor::SAXParser().parse("<h1>Title</h1>");
    auto cs = DataExtractor::SelectorEngine().compile("h1");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectClass) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<div class="item">x</div>)");
    auto cs = DataExtractor::SelectorEngine().compile(".item");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectDescendant) {
    auto tokens = DataExtractor::SAXParser().parse("<div><span>nested</span></div>");
    auto cs = DataExtractor::SelectorEngine().compile("div span");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectChild) {
    auto tokens = DataExtractor::SAXParser().parse("<ul><li>a</li><li>b</li></ul>");
    auto cs = DataExtractor::SelectorEngine().compile("ul > li");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 2);
}

TEST_F(DataExtractorTest, CssSelectById) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<div id="main">content</div>)");
    auto cs = DataExtractor::SelectorEngine().compile("#main");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectClassNoFalsePositive) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<div class="wrong">x</div>)");
    auto cs = DataExtractor::SelectorEngine().compile(".item");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 0);
}

TEST_F(DataExtractorTest, CssSelectNthChild) {
    auto tokens = DataExtractor::SAXParser().parse("<ul><li>a</li><li>b</li><li>c</li></ul>");
    auto cs = DataExtractor::SelectorEngine().compile(":nth-child(2)");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_GE(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectAttrPresence) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<div data-x="val">x</div>)");
    auto cs = DataExtractor::SelectorEngine().compile("[data-x]");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectAttrEquals) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<input type="text">)");
    auto cs = DataExtractor::SelectorEngine().compile("[type=text]");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectAttrBegins) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<a href="https://x.com">link</a>)");
    auto cs = DataExtractor::SelectorEngine().compile("[href^=https]");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectAttrEnds) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<a href="file.pdf">pdf</a>)");
    auto cs = DataExtractor::SelectorEngine().compile("[href$=.pdf]");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssSelectAttrContains) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<a href="example.com/page">link</a>)");
    auto cs = DataExtractor::SelectorEngine().compile("[href*=page]");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, CssMatchTextContent) {
    auto tokens = DataExtractor::SAXParser().parse("<p>hello world</p>");
    auto cs = DataExtractor::SelectorEngine().compile("p");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0].textContent(tokens), "hello world");
}

TEST_F(DataExtractorTest, CssMatchAttribute) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<a href="http://x.com">link</a>)");
    auto cs = DataExtractor::SelectorEngine().compile("a");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
    EXPECT_EQ(matches[0].attribute(tokens, "href"), "http://x.com");
}

TEST_F(DataExtractorTest, CssEmptySelector) {
    auto tokens = DataExtractor::SAXParser().parse("<div>text</div>");
    auto cs = DataExtractor::SelectorEngine().compile("");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 0);
}

TEST_F(DataExtractorTest, CssWildcardSelector) {
    auto tokens = DataExtractor::SAXParser().parse("<div><span>text</span></div>");
    auto cs = DataExtractor::SelectorEngine().compile("*");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 2);
}

TEST_F(DataExtractorTest, CssCompileRules) {
    std::vector<ExtractionRule> rules;
    rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "title", "", false});
    rules.push_back({ExtractionRule::CSS_SELECTOR, ".item", "item", "", false});
    auto compiled = DataExtractor::SelectorEngine().compile(rules);
    ASSERT_EQ(compiled.size(), 2);
}

TEST_F(DataExtractorTest, CssSelectMultipleRules) {
    auto tokens = DataExtractor::SAXParser().parse(
        "<h1>Title</h1><div class=\"item\">x</div>");
    std::vector<ExtractionRule> rules;
    rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "title", "", false});
    rules.push_back({ExtractionRule::CSS_SELECTOR, ".item", "item", "", false});
    auto compiled = DataExtractor::SelectorEngine().compile(rules);
    auto matches = DataExtractor::SelectorEngine().select(tokens, compiled);
    ASSERT_EQ(matches.size(), 2);
}

// ─── JSON Tokenizer Tests (15+) ──────────────────────────────────────────

TEST_F(DataExtractorTest, JsonTokenizeObject) {
    auto tokens = DataExtractor::JSONStreamer().tokenize(R"({"a":1})");
    ASSERT_GE(tokens.size(), 5);
    EXPECT_EQ(tokens[0].type, JSONToken::OBJECT_START);
    EXPECT_EQ(tokens[1].type, JSONToken::KEY);
    EXPECT_EQ(tokens[1].value, "a");
    EXPECT_EQ(tokens[2].type, JSONToken::COLON);
    EXPECT_EQ(tokens[3].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[3].value, "1");
    EXPECT_EQ(tokens[4].type, JSONToken::OBJECT_END);
}

TEST_F(DataExtractorTest, JsonTokenizeArray) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("[1,2,3]");
    ASSERT_GE(tokens.size(), 7);
    EXPECT_EQ(tokens[0].type, JSONToken::ARRAY_START);
    EXPECT_EQ(tokens[1].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[1].value, "1");
    EXPECT_EQ(tokens[2].type, JSONToken::COMMA);
    EXPECT_EQ(tokens[3].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[3].value, "2");
    EXPECT_EQ(tokens[4].type, JSONToken::COMMA);
    EXPECT_EQ(tokens[5].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[5].value, "3");
    EXPECT_EQ(tokens[6].type, JSONToken::ARRAY_END);
}

TEST_F(DataExtractorTest, JsonTokenizeStringWithEscapes) {
    auto tokens = DataExtractor::JSONStreamer().tokenize(R"("hello\nworld")");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::STRING);
    EXPECT_EQ(tokens[0].value, "hello\nworld");
}

TEST_F(DataExtractorTest, JsonTokenizeBooleanTrue) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("true");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::BOOLEAN);
    EXPECT_EQ(tokens[0].value, "true");
}

TEST_F(DataExtractorTest, JsonTokenizeBooleanFalse) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("false");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::BOOLEAN);
    EXPECT_EQ(tokens[0].value, "false");
}

TEST_F(DataExtractorTest, JsonTokenizeNull) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("null");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::NULL_);
    EXPECT_EQ(tokens[0].value, "null");
}

TEST_F(DataExtractorTest, JsonTokenizeNestedObjects) {
    auto tokens = DataExtractor::JSONStreamer().tokenize(R"({"a":{"b":2}})");
    ASSERT_GE(tokens.size(), 9);
    EXPECT_EQ(tokens[0].type, JSONToken::OBJECT_START);
    EXPECT_EQ(tokens[1].type, JSONToken::KEY);
    EXPECT_EQ(tokens[1].value, "a");
    EXPECT_EQ(tokens[2].type, JSONToken::COLON);
    EXPECT_EQ(tokens[3].type, JSONToken::OBJECT_START);
    EXPECT_EQ(tokens[4].type, JSONToken::KEY);
    EXPECT_EQ(tokens[4].value, "b");
    EXPECT_EQ(tokens[5].type, JSONToken::COLON);
    EXPECT_EQ(tokens[6].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[6].value, "2");
    EXPECT_EQ(tokens[7].type, JSONToken::OBJECT_END);
    EXPECT_EQ(tokens[8].type, JSONToken::OBJECT_END);
}

TEST_F(DataExtractorTest, JsonTokenizeNegativeNumber) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("-42");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[0].value, "-42");
}

TEST_F(DataExtractorTest, JsonTokenizeFloat) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("3.14");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[0].value, "3.14");
}

TEST_F(DataExtractorTest, JsonTokenizeScientific) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("1e10");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[0].value, "1e10");
}

TEST_F(DataExtractorTest, JsonTokenizeUnclosedString) {
    auto tokens = DataExtractor::JSONStreamer().tokenize(R"("unclosed)");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::ERROR);
}

TEST_F(DataExtractorTest, JsonTokenizeUnexpectedComma) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("[,]");
    ASSERT_GE(tokens.size(), 2);
    EXPECT_EQ(tokens[0].type, JSONToken::ARRAY_START);
    EXPECT_EQ(tokens[1].type, JSONToken::ERROR);
}

TEST_F(DataExtractorTest, JsonTokenizeInvalidNumber) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("-");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::ERROR);
}

TEST_F(DataExtractorTest, JsonTokenizeUnicodeEscape) {
    auto tokens = DataExtractor::JSONStreamer().tokenize(R"("\u0048")");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::STRING);
    EXPECT_EQ(tokens[0].value, "H");
}

TEST_F(DataExtractorTest, JsonTokenizeSurrogatePair) {
    auto tokens = DataExtractor::JSONStreamer().tokenize(R"("\uD83D\uDE00")");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::STRING);
    EXPECT_FALSE(tokens[0].value.empty());
}

TEST_F(DataExtractorTest, JsonTokenizeEmptyObject) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("{}");
    ASSERT_EQ(tokens.size(), 2);
    EXPECT_EQ(tokens[0].type, JSONToken::OBJECT_START);
    EXPECT_EQ(tokens[1].type, JSONToken::OBJECT_END);
}

TEST_F(DataExtractorTest, JsonTokenizeEmptyArray) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("[]");
    ASSERT_EQ(tokens.size(), 2);
    EXPECT_EQ(tokens[0].type, JSONToken::ARRAY_START);
    EXPECT_EQ(tokens[1].type, JSONToken::ARRAY_END);
}

// ─── JSON Path Matcher Tests (10+) ───────────────────────────────────────

TEST_F(DataExtractorTest, JsonPathSimple) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"a":1})",
        {"$.a"},
        [&](const std::vector<std::string>& path, const JSONToken& val) {
            (void)path;
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 1);
    EXPECT_EQ(matched[0], "1");
}

TEST_F(DataExtractorTest, JsonPathNested) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"a":{"b":2}})",
        {"$.a.b"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 1);
    EXPECT_EQ(matched[0], "2");
}

TEST_F(DataExtractorTest, JsonPathArrayIndex) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"([10,20,30])",
        {"$[0]"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 1);
    EXPECT_EQ(matched[0], "10");
}

TEST_F(DataExtractorTest, JsonPathWildcardArray) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"([1,2,3])",
        {"$[*]"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 3);
}

TEST_F(DataExtractorTest, JsonPathWildcardObject) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"a":1,"b":2})",
        {"$.*"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 2);
}

TEST_F(DataExtractorTest, JsonPathNoMatch) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"a":1})",
        {"$.b"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 0);
}

TEST_F(DataExtractorTest, JsonPathDeepScan) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"a":{"b":{"title":"hello"}}})",
        {"$..title"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 1);
    EXPECT_EQ(matched[0], "hello");
}

TEST_F(DataExtractorTest, JsonPathEmptyPaths) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"a":1})",
        {},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 0);
}

TEST_F(DataExtractorTest, JsonPathMultiplePaths) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"a":1,"b":2})",
        {"$.a", "$.b"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 2);
}

TEST_F(DataExtractorTest, JsonPathNestedArray) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"items":[{"id":1},{"id":2}]})",
        {"$.items[0].id"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 1);
    EXPECT_EQ(matched[0], "1");
}

// ─── ExtractionPlan & High-Level Tests (15+) ────────────────────────────

TEST_F(DataExtractorTest, PlanCssExtract) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "title", "", false});
    auto result = extractor.extract(plan, "<h1>Hello</h1>", "text/html");
    EXPECT_TRUE(result.success);
    ASSERT_EQ(result.fields.count("title"), 1);
    ASSERT_GE(result.fields["title"].size(), 1);
    EXPECT_EQ(result.fields["title"][0], "Hello");
}

TEST_F(DataExtractorTest, PlanJsonExtract) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::JSON_PATH, "$.name", "name", "", false});
    auto result = extractor.extract(plan, R"({"name":"Alice"})", "application/json");
    EXPECT_TRUE(result.success);
    ASSERT_EQ(result.fields.count("name"), 1);
    ASSERT_GE(result.fields["name"].size(), 1);
    EXPECT_EQ(result.fields["name"][0], "Alice");
}

TEST_F(DataExtractorTest, PlanMultipleCssRules) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "title", "", false});
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, ".desc", "desc", "", false});
    auto result = extractor.extract(plan,
        "<h1>Title</h1><p class=\"desc\">Description</p>", "text/html");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["title"].size(), 1);
    EXPECT_EQ(result.fields["title"][0], "Title");
    ASSERT_GE(result.fields["desc"].size(), 1);
    EXPECT_EQ(result.fields["desc"][0], "Description");
}

TEST_F(DataExtractorTest, PlanMultipleJsonRules) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::JSON_PATH, "$.a", "a", "", false});
    plan.rules.push_back({ExtractionRule::JSON_PATH, "$.b", "b", "", false});
    auto result = extractor.extract(plan, R"({"a":1,"b":2})", "application/json");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["a"].size(), 1);
    EXPECT_EQ(result.fields["a"][0], "1");
    ASSERT_GE(result.fields["b"].size(), 1);
    EXPECT_EQ(result.fields["b"][0], "2");
}

TEST_F(DataExtractorTest, PlanMixedCssJson) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "title", "", false});
    plan.rules.push_back({ExtractionRule::JSON_PATH, "$.name", "name", "", false});

    auto html_result = extractor.extract(plan, "<h1>Hi</h1>", "text/html");
    EXPECT_TRUE(html_result.success);
    ASSERT_GE(html_result.fields["title"].size(), 1);

    auto json_result = extractor.extract(plan, R"({"name":"Bob"})", "application/json");
    EXPECT_TRUE(json_result.success);
    ASSERT_GE(json_result.fields["name"].size(), 1);
}

TEST_F(DataExtractorTest, PlanSingleFalseReturnsFirstOnly) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "li", "items", "", false});
    auto result = extractor.extract(plan, "<ul><li>A</li><li>B</li></ul>", "text/html");
    ASSERT_EQ(result.fields["items"].size(), 1);
    EXPECT_EQ(result.fields["items"][0], "A");
}

TEST_F(DataExtractorTest, PlanMultipleTrueReturnsAll) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "li", "items", "", true});
    auto result = extractor.extract(plan, "<ul><li>A</li><li>B</li></ul>", "text/html");
    ASSERT_EQ(result.fields["items"].size(), 2);
    EXPECT_EQ(result.fields["items"][0], "A");
    EXPECT_EQ(result.fields["items"][1], "B");
}

TEST_F(DataExtractorTest, PlanAttributeExtraction) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "a", "link", "href", false});
    auto result = extractor.extract(plan,
        R"(<a href="http://example.com">link</a>)", "text/html");
    ASSERT_GE(result.fields["link"].size(), 1);
    EXPECT_EQ(result.fields["link"][0], "http://example.com");
}

TEST_F(DataExtractorTest, PlanEmptyPlan) {
    ExtractionPlan plan;
    auto result = extractor.extract(plan, "<h1>Hello</h1>", "text/html");
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.fields.empty());
}

TEST_F(DataExtractorTest, PlanEmptyData) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "title", "", false});
    auto result = extractor.extract(plan, "", "text/html");
    EXPECT_FALSE(result.success);
}

TEST_F(DataExtractorTest, PlanContentTypeHtml) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "title", "", false});
    auto result = extractor.extract(plan, "<h1>X</h1>", "text/html");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["title"].size(), 1);
}

TEST_F(DataExtractorTest, PlanContentTypeJson) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::JSON_PATH, "$.x", "x", "", false});
    auto result = extractor.extract(plan, R"({"x":1})", "application/json");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["x"].size(), 1);
}

TEST_F(DataExtractorTest, PlanContentTypePlain) {
    ExtractionPlan plan;
    auto result = extractor.extract(plan, "hello https://example.com world", "text/plain");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["url"].size(), 1);
    EXPECT_EQ(result.fields["url"][0], "https://example.com");
}

TEST_F(DataExtractorTest, PlanContentTypeXmlTreatedAsHtml) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "title", "t", "", false});
    auto result = extractor.extract(plan, "<title>XML</title>", "application/xml");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["t"].size(), 1);
    EXPECT_EQ(result.fields["t"][0], "XML");
}

TEST_F(DataExtractorTest, PlanBytesProcessed) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "t", "", false});
    auto result = extractor.extract(plan, "<h1>X</h1>", "text/html");
    EXPECT_GT(result.bytes_processed, 0);
}

TEST_F(DataExtractorTest, PlanElapsedMs) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "h1", "t", "", false});
    auto result = extractor.extract(plan, "<h1>X</h1>", "text/html");
    EXPECT_GE(result.elapsed_ms, 0.0);
}

// ─── Heuristic Engine Tests (5+) ────────────────────────────────────────

TEST_F(DataExtractorTest, HeuristicDiscoverUrl) {
    auto patterns = DataExtractor::HeuristicEngine().discover("visit https://example.com");
    ASSERT_GE(patterns.size(), 1);
    bool found_url = false;
    for (const auto& p : patterns) {
        if (p.suggested_type == "url") {
            found_url = true;
            EXPECT_EQ(p.sample, "https://example.com");
            break;
        }
    }
    EXPECT_TRUE(found_url);
}

TEST_F(DataExtractorTest, HeuristicDiscoverEmail) {
    auto patterns = DataExtractor::HeuristicEngine().discover("contact user@example.com");
    ASSERT_GE(patterns.size(), 1);
    bool found_email = false;
    for (const auto& p : patterns) {
        if (p.suggested_type == "email") {
            found_email = true;
            EXPECT_EQ(p.sample, "user@example.com");
            break;
        }
    }
    EXPECT_TRUE(found_email);
}

TEST_F(DataExtractorTest, HeuristicEmptyInput) {
    auto patterns = DataExtractor::HeuristicEngine().discover("");
    ASSERT_EQ(patterns.size(), 0);
}

TEST_F(DataExtractorTest, HeuristicNoPatterns) {
    auto patterns = DataExtractor::HeuristicEngine().discover("just random text without patterns");
    ASSERT_EQ(patterns.size(), 0);
}

TEST_F(DataExtractorTest, HeuristicMultiplePatterns) {
    auto patterns = DataExtractor::HeuristicEngine().discover(
        "site https://example.com email user@test.com");
    ASSERT_GE(patterns.size(), 2);
}

TEST_F(DataExtractorTest, HeuristicDiscoverPrice) {
    auto patterns = DataExtractor::HeuristicEngine().discover("price $19.99");
    ASSERT_GE(patterns.size(), 1);
    bool found = false;
    for (const auto& p : patterns) {
        if (p.suggested_type == "price") {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

TEST_F(DataExtractorTest, HeuristicDiscoverDate) {
    auto patterns = DataExtractor::HeuristicEngine().discover("date: 2024-01-15");
    ASSERT_GE(patterns.size(), 1);
    bool found = false;
    for (const auto& p : patterns) {
        if (p.suggested_type == "date") {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

// ─── Charset Detection Tests (5+) ───────────────────────────────────────

TEST_F(DataExtractorTest, CharsetDetectFromContentType) {
    auto cs = DataExtractor::detectCharset("", "text/html; charset=iso-8859-1");
    EXPECT_EQ(cs, "iso-8859-1");
}

TEST_F(DataExtractorTest, CharsetDetectUtf8Bom) {
    std::string data;
    data += static_cast<char>(0xEF);
    data += static_cast<char>(0xBB);
    data += static_cast<char>(0xBF);
    data += "hello";
    auto cs = DataExtractor::detectCharset(data, "");
    EXPECT_EQ(cs, "utf-8");
}

TEST_F(DataExtractorTest, CharsetDetectFromMeta) {
    auto cs = DataExtractor::detectCharset(
        R"(<html><head><meta charset=shift-jis></head></html>)", "");
    EXPECT_EQ(cs, "shift-jis");
}

TEST_F(DataExtractorTest, CharsetDetectDefault) {
    auto cs = DataExtractor::detectCharset("no charset info", "");
    EXPECT_EQ(cs, "utf-8");
}

TEST_F(DataExtractorTest, CharsetDetectUtf16Be) {
    std::string data;
    data += static_cast<char>(0xFE);
    data += static_cast<char>(0xFF);
    data += "hello";
    auto cs = DataExtractor::detectCharset(data, "");
    EXPECT_EQ(cs, "utf-16be");
}

TEST_F(DataExtractorTest, CharsetDetectUtf16Le) {
    std::string data;
    data += static_cast<char>(0xFF);
    data += static_cast<char>(0xFE);
    data += "hello";
    auto cs = DataExtractor::detectCharset(data, "");
    EXPECT_EQ(cs, "utf-16le");
}

TEST_F(DataExtractorTest, ConvertToUtf8Passthrough) {
    std::string result = DataExtractor::convertToUtf8("hello", "utf-8");
    EXPECT_EQ(result, "hello");
}

TEST_F(DataExtractorTest, CharsetContentTypeQuoted) {
    auto cs = DataExtractor::detectCharset("", R"(text/html; charset="utf-16")");
    EXPECT_EQ(cs, "utf-16");
}

// ─── Edge Case Tests (10+) ─────────────────────────────────────────────

TEST_F(DataExtractorTest, EdgeVeryLargeHtml) {
    std::string big;
    big.append(10000, 'x');
    big.insert(0, "<div>");
    big.append("</div>");
    auto tokens = DataExtractor::SAXParser().parse(big);
    ASSERT_GE(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, SAXToken::TAG_OPEN);
    EXPECT_EQ(tokens[0].name, "div");
    EXPECT_EQ(tokens[1].type, SAXToken::TEXT);
    EXPECT_EQ(tokens[1].content.size(), 10000);
}

TEST_F(DataExtractorTest, EdgeDeeplyNestedHtml) {
    std::string html;
    for (int i = 0; i < 100; ++i)
        html += "<div>";
    html += "deep";
    for (int i = 0; i < 100; ++i)
        html += "</div>";
    auto tokens = DataExtractor::SAXParser().parse(html);
    EXPECT_GT(tokens.size(), 200);
}

TEST_F(DataExtractorTest, EdgeManyAttributes) {
    std::string html = "<div";
    for (int i = 0; i < 50; ++i)
        html += " attr" + std::to_string(i) + R"(="val)" + std::to_string(i) + "\"";
    html += ">text</div>";
    auto tokens = DataExtractor::SAXParser().parse(html);
    ASSERT_GE(tokens.size(), 2);
    ASSERT_EQ(tokens[0].attributes.size(), 50);
    EXPECT_EQ(tokens[0].attributes[0].name, "attr0");
    EXPECT_EQ(tokens[0].attributes[49].name, "attr49");
}

TEST_F(DataExtractorTest, EdgeCssNthChildOddEven) {
    auto cs_odd = DataExtractor::SelectorEngine().compile(":nth-child(odd)");
    auto cs_even = DataExtractor::SelectorEngine().compile(":nth-child(even)");
    ASSERT_GE(cs_odd.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs_odd.parts[0].compound.simples[0].name, "odd");
    ASSERT_GE(cs_even.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs_even.parts[0].compound.simples[0].name, "even");
}

TEST_F(DataExtractorTest, EdgeCssNthChildFormula) {
    auto cs = DataExtractor::SelectorEngine().compile(":nth-child(2n+1)");
    ASSERT_GE(cs.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::NTH_CHILD);
    EXPECT_EQ(cs.parts[0].compound.simples[0].name, "2n+1");
}

TEST_F(DataExtractorTest, EdgeCssAttrValueWithQuotes) {
    auto cs = DataExtractor::SelectorEngine().compile(R"([data-val="hello world"])");
    ASSERT_GE(cs.parts[0].compound.simples.size(), 1);
    EXPECT_EQ(cs.parts[0].compound.simples[0].type, SimpleSelector::ATTR_EQUALS);
    EXPECT_EQ(cs.parts[0].compound.simples[0].value, "hello world");
}

TEST_F(DataExtractorTest, EdgeJsonDeeplyNested) {
    std::string json = "{\"a\":" + std::string(50, '{') + "\"x\":1" + std::string(50, '}') + "}";
    auto tokens = DataExtractor::JSONStreamer().tokenize(json);
    EXPECT_GT(tokens.size(), 100);
    EXPECT_EQ(tokens.back().type, JSONToken::OBJECT_END);
}

TEST_F(DataExtractorTest, EdgeJsonManyArrayElements) {
    std::string json = "[";
    for (int i = 0; i < 1000; ++i) {
        if (i > 0) json += ",";
        json += std::to_string(i);
    }
    json += "]";
    auto tokens = DataExtractor::JSONStreamer().tokenize(json);
    EXPECT_GT(tokens.size(), 1000);
}

TEST_F(DataExtractorTest, EdgeInvalidCssSelectorNoCrash) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "<<<invalid>>>", "x", "", false});
    // Must not crash — success depends on how the invalid selector is handled
    EXPECT_NO_THROW(extractor.extract(plan, "<div>test</div>", "text/html"));
}

TEST_F(DataExtractorTest, EdgeMissingAttribute) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "div", "x", "nonexistent", false});
    auto result = extractor.extract(plan, "<div>text</div>", "text/html");
    EXPECT_FALSE(result.success);
}

TEST_F(DataExtractorTest, EdgeHtmlEntityDecodeEmpty) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode(""), "");
}

TEST_F(DataExtractorTest, EdgeHtmlEntityDecodeNumericLarge) {
    std::string decoded = DataExtractor::htmlEntityDecode("&#128169;");
    EXPECT_FALSE(decoded.empty());
}

TEST_F(DataExtractorTest, EdgeHtmlEntityDecodeHexLowercase) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&#x41;"), "A");
}

TEST_F(DataExtractorTest, EdgeHtmlEntityDecodeAposEntity) {
    EXPECT_EQ(DataExtractor::htmlEntityDecode("&apos;"), "'");
}

TEST_F(DataExtractorTest, EdgeXmlTreatedAsHtml) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "item", "i", "", false});
    auto result = extractor.extract(plan, "<root><item>x</item></root>", "text/xml");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["i"].size(), 1);
    EXPECT_EQ(result.fields["i"][0], "x");
}

TEST_F(DataExtractorTest, EdgeCssAttrBeginsWithQuote) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<a href="https://x.com">link</a>)");
    auto cs = DataExtractor::SelectorEngine().compile(R"([href^="https"])");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, EdgeCssAttrEndsWithQuote) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<img src="photo.jpg">)");
    auto cs = DataExtractor::SelectorEngine().compile(R"([src$=".jpg"])");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, EdgeCssAttrContainsWithQuote) {
    auto tokens = DataExtractor::SAXParser().parse(R"(<a href="https://example.com/page">link</a>)");
    auto cs = DataExtractor::SelectorEngine().compile(R"([href*="example"])");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, EdgeCssUniversalSelector) {
    auto tokens = DataExtractor::SAXParser().parse("<div><p><span>text</span></p></div>");
    auto cs = DataExtractor::SelectorEngine().compile("*");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 3);
}

TEST_F(DataExtractorTest, EdgeCssNthChildSelectsCorrectElement) {
    auto tokens = DataExtractor::SAXParser().parse("<ul><li>A</li><li>B</li><li>C</li></ul>");
    auto cs = DataExtractor::SelectorEngine().compile(":nth-child(2)");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_GE(matches.size(), 1);
    EXPECT_EQ(matches[0].textContent(tokens), "B");
}

TEST_F(DataExtractorTest, EdgeSaxCallbackReceivesAllTokens) {
    int count = 0;
    DataExtractor::SAXParser().parse("<div><p>text</p></div>",
        [&](const SAXToken&) -> bool {
            ++count;
            return true;
        });
    EXPECT_GT(count, 3);
}

TEST_F(DataExtractorTest, EdgeJsonPathParseNoMatch) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"({"a":1})",
        {"$.x.y.z"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 0);
}

TEST_F(DataExtractorTest, EdgeJsonPathArrayWildcardMultiple) {
    std::vector<std::string> matched;
    DataExtractor::JSONStreamer().parse(
        R"([{"id":1},{"id":2}])",
        {"$[*].id"},
        [&](const std::vector<std::string>&, const JSONToken& val) {
            matched.push_back(val.value);
        });
    ASSERT_EQ(matched.size(), 2);
}

TEST_F(DataExtractorTest, EdgeLargeDataThroughput) {
    std::string html = "<html>";
    for (int i = 0; i < 500; ++i)
        html += "<p>item" + std::to_string(i) + "</p>";
    html += "</html>";

    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "p", "items", "", true});
    auto result = extractor.extract(plan, html, "text/html");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["items"].size(), 500);
}

TEST_F(DataExtractorTest, EdgeSaxWhitespaceOnly) {
    auto tokens = DataExtractor::SAXParser().parse("   ");
    ASSERT_GE(tokens.size(), 2);
    EXPECT_EQ(tokens[0].type, SAXToken::TEXT);
    EXPECT_EQ(tokens.back().type, SAXToken::EOF_);
}

TEST_F(DataExtractorTest, EdgeSaxMultipleVoidElements) {
    auto tokens = DataExtractor::SAXParser().parse("<br><hr><img src=\"x.jpg\">");
    ASSERT_GE(tokens.size(), 4);
    EXPECT_EQ(tokens[0].name, "br");
    EXPECT_EQ(tokens[1].name, "hr");
    EXPECT_EQ(tokens[2].name, "img");
}

TEST_F(DataExtractorTest, EdgeJsonTokenizeScientificNegative) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("-1.5e-3");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[0].value, "-1.5e-3");
}

TEST_F(DataExtractorTest, EdgeJsonTokenizeStringWithQuoteEscaped) {
    auto tokens = DataExtractor::JSONStreamer().tokenize(R"("hello\"world")");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::STRING);
    EXPECT_EQ(tokens[0].value, "hello\"world");
}

TEST_F(DataExtractorTest, EdgeJsonTokenizeStringWithBackslashEscaped) {
    auto tokens = DataExtractor::JSONStreamer().tokenize(R"("path\\to\\file")");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::STRING);
    EXPECT_EQ(tokens[0].value, "path\\to\\file");
}

TEST_F(DataExtractorTest, EdgeHeuristicPatternSampleTruncated) {
    std::string long_url = "https://" + std::string(200, 'x') + ".com";
    auto patterns = DataExtractor::HeuristicEngine().discover(long_url);
    ASSERT_GE(patterns.size(), 1);
    EXPECT_LE(patterns[0].sample.size(), 100);
}

TEST_F(DataExtractorTest, EdgeCharsetContentTypeWithExtraParams) {
    auto cs = DataExtractor::detectCharset("",
        "text/html; charset=windows-1252; boundary=xyz");
    EXPECT_EQ(cs, "windows-1252");
}

TEST_F(DataExtractorTest, EdgeCssSelectorWithMultipleClasses) {
    auto tokens = DataExtractor::SAXParser().parse(
        R"(<div class="foo bar">text</div>)");
    auto cs = DataExtractor::SelectorEngine().compile(".foo");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, EdgeCssAttrContainsWord) {
    auto tokens = DataExtractor::SAXParser().parse(
        R"(<div class="hello world">text</div>)");
    auto cs = DataExtractor::SelectorEngine().compile("[class~=world]");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 1);
}

TEST_F(DataExtractorTest, EdgeCssSelectorTokenCount) {
    auto tokens = DataExtractor::SAXParser().parse("<div><p>a</p><p>b</p></div>");
    auto cs = DataExtractor::SelectorEngine().compile("div > p");
    auto matches = DataExtractor::SelectorEngine().select(tokens, cs);
    ASSERT_EQ(matches.size(), 2);
}

TEST_F(DataExtractorTest, EdgeJsonTokenizeLeadingZeroStopsAtFirstDigit) {
    auto tokens = DataExtractor::JSONStreamer().tokenize("0123");
    ASSERT_GE(tokens.size(), 1);
    EXPECT_EQ(tokens[0].type, JSONToken::NUMBER);
    EXPECT_EQ(tokens[0].value, "0");
}

// ─── Legacy compatibility tests (adapted from original 7 tests) ────────

TEST_F(DataExtractorTest, LegacyExtractHtmlTitle) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "title", "page_title", "", false});
    auto result = extractor.extract(plan,
        "<html><head><title>Test Course</title></head></html>", "text/html");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["page_title"].size(), 1);
    EXPECT_EQ(result.fields["page_title"][0], "Test Course");
}

TEST_F(DataExtractorTest, LegacyExtractEmptyHtml) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "title", "page_title", "", false});
    auto result = extractor.extract(plan, "", "text/html");
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.fields.empty());
}

TEST_F(DataExtractorTest, LegacyFindYoutubeUrl) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, R"(iframe[src*="youtube"])",
                          "video_url", "src", false});
    auto result = extractor.extract(plan,
        R"(<iframe src="https://www.youtube.com/embed/dQw4w9WgXcQ"></iframe>)",
        "text/html");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["video_url"].size(), 1);
    std::string url = result.fields["video_url"][0];
    EXPECT_TRUE(url.find("youtube.com") != std::string::npos);
}

TEST_F(DataExtractorTest, LegacyFindMultipleYoutubeUrls) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, R"(iframe[src*="youtube"])",
                          "video_url", "src", true});
    auto result = extractor.extract(plan,
        R"(<iframe src="https://www.youtube.com/embed/abc123"></iframe>
           <iframe src="https://www.youtube.com/embed/xyz789"></iframe>)",
        "text/html");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["video_url"].size(), 2);
}

TEST_F(DataExtractorTest, LegacyExtractJsonCourseName) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::JSON_PATH, "$.courseName",
                          "json_course_name", "", false});
    auto result = extractor.extract(plan,
        R"({"courseName": "Self Driving Cars"})", "application/json");
    EXPECT_TRUE(result.success);
    ASSERT_GE(result.fields["json_course_name"].size(), 1);
    EXPECT_EQ(result.fields["json_course_name"][0], "Self Driving Cars");
}

TEST_F(DataExtractorTest, LegacyExtractUnknownContentType) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "div", "x", "", false});
    auto result = extractor.extract(plan, "some binary data", "application/octet-stream");
    EXPECT_FALSE(result.success);
}

TEST_F(DataExtractorTest, LegacyParseHtmlForElementReplaced) {
    ExtractionPlan plan;
    plan.rules.push_back({ExtractionRule::CSS_SELECTOR, "div", "result", "class", false});
    auto result = extractor.extract(plan, "<div>test</div>", "text/html");
    ASSERT_GE(result.fields["result"].size(), 0);
}
