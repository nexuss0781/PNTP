#ifndef PNTP_DATA_EXTRACTOR_H
#define PNTP_DATA_EXTRACTOR_H

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <string>
#include <string_view>
#include <vector>

// ── SAX Token Types ──────────────────────────────────────────

struct Attribute {
    std::string name;
    std::string value;
    bool quoted;
};

struct SAXToken {
    enum Type : uint8_t {
        TAG_OPEN,
        TAG_CLOSE,
        TEXT,
        COMMENT,
        DOCTYPE,
        CDATA,
        SCRIPT,
        STYLE,
        ERROR_,
        EOF_
    };
    Type type;
    std::string name;
    std::string content;
    std::vector<Attribute> attributes;
    size_t offset;
    size_t length;
};

// ── CSS Selector Types ───────────────────────────────────────

struct SimpleSelector {
    enum Type : uint8_t {
        TAG,
        ID,
        CLASS,
        ATTR_PRESENCE,
        ATTR_EQUALS,
        ATTR_CONTAINS_WORD,
        ATTR_BEGINS,
        ATTR_ENDS,
        ATTR_CONTAINS,
        NTH_CHILD
    };
    Type type;
    std::string name;
    std::string value;
};

struct CompoundSelector {
    std::vector<SimpleSelector> simples;
};

enum Combinator : uint8_t {
    DESCENDANT,
    CHILD,
    ADJACENT_SIBLING,
    GENERAL_SIBLING
};

struct CompiledSelector {
    struct Part {
        Combinator combinator;
        CompoundSelector compound;
    };
    std::vector<Part> parts;
    std::string original;
};

using CompiledSelectors = std::vector<CompiledSelector>;

// ── JSON Types ────────────────────────────────────────────────

struct JSONToken {
    enum Type : uint8_t {
        OBJECT_START,
        OBJECT_END,
        ARRAY_START,
        ARRAY_END,
        STRING,
        NUMBER,
        BOOLEAN,
        NULL_,
        COLON,
        COMMA,
        KEY,
        ERROR
    };
    Type type;
    std::string value;
    size_t offset;
    size_t length;
};

// ── Extraction Types ──────────────────────────────────────────

struct ExtractionRule {
    enum Type : uint8_t { CSS_SELECTOR, JSON_PATH, REGEX, HEURISTIC };
    Type type;
    std::string pattern;
    std::string output_name;
    std::string attribute;
    bool multiple;
};

struct ExtractionPlan {
    std::vector<ExtractionRule> rules;
};

struct ExtractionResult {
    std::map<std::string, std::vector<std::string>> fields;
    double elapsed_ms;
    size_t bytes_processed;
    bool success;
    std::string error;
};

struct DiscoveredPattern {
    std::string regex_str;
    std::string sample;
    double confidence;
    std::string suggested_type;
};

struct Match {
    const SAXToken* token;
    std::string selector_text;
    size_t depth;

    std::string textContent(const std::vector<SAXToken>& tokens) const;
    std::string attribute(const std::vector<SAXToken>& tokens,
                          const std::string& attr_name) const;
};

// ── Main Class ────────────────────────────────────────────────

class DataExtractor {
public:
    DataExtractor();

    using TokenCallback = std::function<bool(const SAXToken&)>;
    using JSONValueCallback = std::function<void(
        const std::vector<std::string>& path, const JSONToken& value)>;

    // ── High-level extraction ──
    ExtractionResult extract(const ExtractionPlan& plan,
                             std::string_view data,
                             const std::string& content_type);

    // ── SAX HTML Parser ──
    struct SAXParser {
        void parse(std::string_view html, TokenCallback cb);
        std::vector<SAXToken> parse(std::string_view html);
        static bool isVoidElement(std::string_view tag);
        static bool isRawTextElement(std::string_view tag);
        static bool isWhitespace(char c);
    };

    // ── CSS Selector Engine ──
    struct SelectorEngine {
        CompiledSelector compile(const std::string& selector);
        CompiledSelectors compile(const std::vector<ExtractionRule>& rules);
        std::vector<Match> select(const std::vector<SAXToken>& tokens,
                                  const CompiledSelector& selector);
        std::vector<Match> select(const std::vector<SAXToken>& tokens,
                                  const CompiledSelectors& selectors);
    };

    // ── JSON Streaming Parser ──
    struct JSONStreamer {
        std::vector<JSONToken> tokenize(std::string_view json);
        void parse(std::string_view json,
                   const std::vector<std::string>& paths,
                   JSONValueCallback cb);
    };

    // ── Heuristic Engine ──
    struct HeuristicEngine {
        std::vector<DiscoveredPattern> discover(std::string_view data);
    };

    // ── Charset Handling ──
    static std::string detectCharset(std::string_view data,
                                     const std::string& content_type);
    static std::string convertToUtf8(std::string_view data,
                                     const std::string& from_charset);

    // ── Utility ──
    static std::string htmlEntityDecode(std::string_view text);

private:
    ExtractionResult extractHtml(const ExtractionPlan& plan,
                                  std::string_view data);
    ExtractionResult extractJson(const ExtractionPlan& plan,
                                  std::string_view data);
    ExtractionResult extractHeuristic(const ExtractionPlan& plan,
                                       std::string_view data);
    std::string dispatchContentType(const std::string& content_type);

    static uint8_t hexNibble(char c);
    static uint32_t decodeUtf8Codepoint(const char*& it, const char* end);
};

#endif // PNTP_DATA_EXTRACTOR_H
