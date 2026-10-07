# Phase 9: Data Extractor — Full Plan

**Time estimate:** 23 hours | **Files:** `include/pntp/data_extractor.h`, `src/data_extractor.cpp`, `test/test_data_extractor.cpp`

---

## Current State

- `include/pntp/data_extractor.h` — 25-line stub: 4 methods, `std::map`-based return
- `src/data_extractor.cpp` — 89 lines of `std::regex` + `std::cout` conceptual stubs + `std::cerr`
- `test/test_data_extractor.cpp` — 7 trivial tests (pass against regex stubs)
- **Design target** (`PNTP_V4_Design.md §3.8`): SAX streaming parser, CSS selector engine, JSON stream parser, ExtractionPlan, HeuristicEngine — with `extract()` as unified entry point

---

## Architecture

```
                          ┌──────────────────────────┐
                          │    DataExtractor          │
                          │  extract(plan, data, ct)  │
                          └──────┬───────────────────┘
                ┌─────────────────┼──────────────────────┐
                ▼                 ▼                      ▼
        ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐
        │ SAXParser     │  │ JSONStreamer │  │ HeuristicEngine  │
        │ (HTML tokens) │  │ (token+range) │  │ (pattern disc.)  │
        └──────┬───────┘  └──────┬───────┘  └──────────────────┘
               ▼                  ▼
        ┌──────────────┐  ┌──────────────┐
        │SelectorEngine│  │ JSONPath     │
        │(CSS matching) │  │(path matcher)│
        └──────────────┘  └──────────────┘
```

### Key Design Decisions

1. **No DOM tree** — SAX streaming throughout. Selector matching builds a lightweight element stack during parse, no full node tree.
2. **Flat token vector** — SAX collects tokens into a `std::vector<SAXToken>`. This enables random-access CSS matching while keeping memory bounded (per-request HTML isn't infinite).
3. **Tolerant parsing** — HTML in the wild is malformed. The tokenizer follows browser-like recovery: auto-close `<p>`, ignore stray `</div>`, handle unquoted attrs, decode HTML entities.
4. **Callback dispatch** — `extract()` installs selector/JSON-path matchers as callbacks into the SAX/JSON parser, avoiding a full token dump when possible.
5. **No exceptions** — Return-code style matches project convention.

---

## Tasks

### P9-001: SAX HTML Tokenizer (5h)

**File:** `src/data_extractor.cpp`

The HTML tokenizer converts raw bytes into a stream of tokens. It is the foundation everything else builds on.

**Token types:**

| Token | Fields | Example input |
|-------|--------|---------------|
| `TAG_OPEN` | `name`, `attrs[]` | `<div class="foo">` |
| `TAG_CLOSE` | `name` | `</div>` |
| `TEXT` | `content` | `hello world` |
| `COMMENT` | `content` | `<!-- comment -->` |
| `DOCTYPE` | `content` | `<!DOCTYPE html>` |
| `CDATA` | `content` | `<![CDATA[...]]>` |
| `SCRIPT` | `content` | `<script>var x=1;</script>` |
| `STYLE` | `content` | `<style>body{}</style>` |
| `EOF` | — | end of input |

**Attribute parsing:**
- Double-quoted: `name="value"`
- Single-quoted: `name='value'`
- Unquoted: `name=value` (terminated by whitespace or `>`)
- Boolean: `disabled`, `checked` (no `=value`)
- Handle character references: `&amp;` → `&`, `&lt;` → `<`, `&gt;` → `>`, `&quot;` → `"`, `&#NN;` → Unicode

**Void elements** (auto-close, no end tag): `area`, `base`, `br`, `col`, `embed`, `hr`, `img`, `input`, `link`, `meta`, `param`, `source`, `track`, `wbr`

**Raw text elements** (everything inside is text until closing tag): `script`, `style`, `textarea`, `title`

**Error recovery:**
- Stray closing tag with no open → skip
- Nested `<p>` → auto-close previous `<p>`
- Unknown elements → parsed generically
- Invalid characters → replaced with U+FFFD or skipped

**Memory:** Store token content inline via `std::string`. For very large text nodes (>64KB), store as `std::string_view` into original buffer (SAX caller must keep buffer alive).

```cpp
struct SAXToken {
    enum Type {
        TAG_OPEN, TAG_CLOSE, TEXT, COMMENT, DOCTYPE,
        CDATA, SCRIPT, STYLE, EOF_
    };
    Type type;
    std::string name;                     // tag/comment/doctype name
    std::string content;                  // TEXT content
    std::vector<Attribute> attributes;    // for TAG_OPEN
    size_t offset;                        // byte offset in source
};
struct Attribute {
    std::string name;
    std::string value;
    bool quoted;  // false for boolean attributes
};
```

**Deliverable tests:**
- Parse `<div>hello</div>` → TAG_OPEN("div"), TEXT("hello"), TAG_CLOSE("div")
- Parse `<br/>` → TAG_OPEN("br"), auto-closed
- Parse `<img src="a.jpg" alt="b">` → attrs parsed
- Parse `<script>var x = "</script>";</script>` → entire content captured
- Parse `<!-- comment -->` → COMMENT
- Parse nested structure correctly
- Parse malformed HTML without crash
- Parse HTML entities: `&amp;` → `&`

---

### P9-002: Token Callback API (1h)

**File:** `include/pntp/data_extractor.h`

Support both modes:
1. **Callback mode:** `parse(data, len, callback)` — invokes callback per token
2. **Collect mode:** `parse(data, len)` → returns `std::vector<SAXToken>`

The callback signature:
```cpp
using TokenCallback = std::function<bool(const SAXToken&)>;
// Return false to abort parsing early
```

**Integration:** `DataExtractor::extract()` uses a callback that feeds into SelectorEngine matchers in streaming fashion.

---

### P9-003: CSS Selector Tokenizer (2h)

**File:** `src/data_extractor.cpp`

Tokenize a CSS selector string into a sequence of simple selectors with combinators.

**Selector grammar subset:**

```
selector        = compound_selector (combinator compound_selector)*
combinator      = ' ' | '>' | '+' | '~'
compound        = type_sel | id_sel | class_sel | attr_sel | pseudo_sel
type_sel        = element_name | '*'
id_sel          = '#' identifier
class_sel       = '.' identifier
attr_sel        = '[' attr_name (op value)? ']'
op              = '=' | '~=' | '|=' | '^=' | '$=' | '*='
pseudo_sel      = ':nth-child(' an+b ')'
```

**Examples:**
- `h1` → type selector "h1"
- `.course-title` → class selector "course-title"
- `#main` → id selector "main"
- `div[data-url]` → type "div" + attr presence check
- `div.course > span.title` → descendant "div.course" → child "span.title"
- `ul li:nth-child(2)` → descendant + nth-child(2)

**Data structure:**
```cpp
struct SimpleSelector {
    enum Type { TAG, ID, CLASS, ATTR_PRESENCE, ATTR_EQUALS,
                ATTR_CONTAINS, ATTR_BEGINS, ATTR_ENDS,
                NTH_CHILD };
    Type type;
    std::string name;      // tag name, attr name, etc.
    std::string value;     // attr value, nth formula
    bool negate;           // for :not() future use
};
struct CompoundSelector {
    std::vector<SimpleSelector> simples;  // all must match
};
enum Combinator { DESCENDANT, CHILD, ADJACENT_SIBLING, GENERAL_SIBLING };
struct Selector {
    CompoundSelector compound;
    Combinator combinator;  // combinator BEFORE this compound
};
// Full selector: vector<Selector> in order
```

**Deliverable tests:**
- Tokenize `h1` → 1 compound, tag "h1"
- Tokenize `.foo.bar` → 1 compound, 2 simples
- Tokenize `div#id.cls[attr]` → 1 compound, 4 simples
- Tokenize `a > b` → 2 compounds with CHILD combinator
- Tokenize `:nth-child(2n+1)` → nth-child with formula "2n+1"
- Tokenize `[attr~=value]` → ATTR_CONTAINS
- Reject invalid selectors gracefully

---

### P9-004: CSS Selector Match Engine (3h)

**File:** `src/data_extractor.cpp`

Match a compiled selector against a SAX token stream (or token vector).

**Matching strategy:**

1. Parse selector into `std::vector<CompoundSelector>` with combinators
2. Walk the SAX token list, maintaining an element stack
3. For each TAG_OPEN token, check if it matches the last compound in the selector
4. If compound matches, check backwards against the element stack for combinator satisfaction:
   - DESCENDANT (space): any ancestor matches previous compound
   - CHILD (`>`): parent matches previous compound
   - ADJACENT_SIBLING (`+`): previous sibling matches
   - GENERAL_SIBLING (`~`): any previous sibling matches
5. Return all matching element positions

**Element stack maintenance:**
- On TAG_OPEN: push element (tag + id + classes + attrs) onto stack
- On TAG_CLOSE: pop matching element from stack
- The stack represents the current open-element ancestry

**Data structures:**
```cpp
struct ElementContext {
    std::string tag;
    std::string id;
    std::vector<std::string> classes;
    std::map<std::string, std::string> attrs;
};
struct Match {
    const SAXToken* token;  // matched opening tag
    std::string selector;   // the CSS selector that matched
    size_t depth;           // nesting depth
    // For convenience:
    std::string textContent() const;  // gather following TEXT tokens until matching close
    std::string attr(const std::string& name) const;
};
```

**Deliverable tests:**
- Match `h1` in `<h1>Title</h1>` → 1 match with text "Title"
- Match `.course` in `<div class="course">...</div>` → 1 match
- Match `#main h1` in nested structure → descendant match
- Match `ul > li` → direct child match
- Match `:nth-child(2)` → second child match
- Match `div[data-url]` with attr presence
- No false positives for class in `<div class="other">`
- Extract attribute via `attr()` helper

---

### P9-005: JSON Streaming Tokenizer (2h)

**File:** `src/data_extractor.cpp`

A streaming JSON parser that emits tokens without building a tree.

**Token types:**

| Token | Example |
|-------|---------|
| `OBJECT_START` | `{` |
| `OBJECT_END` | `}` |
| `ARRAY_START` | `[` |
| `ARRAY_END` | `]` |
| `STRING` | `"hello"` |
| `NUMBER` | `42`, `3.14`, `-1e5` |
| `BOOLEAN` | `true`, `false` |
| `NULL` | `null` |
| `COLON` | `:` |
| `COMMA` | `,` |
| `KEY` | `"key"` (object key context) |

```cpp
struct JSONToken {
    enum Type {
        OBJECT_START, OBJECT_END,
        ARRAY_START, ARRAY_END,
        STRING, NUMBER, BOOLEAN, NULL_,
        COLON, COMMA, KEY
    };
    Type type;
    std::string value;   // string content or number text
    size_t offset;       // byte offset in source
    size_t length;       // byte length including structural chars
};
```

**Number parsing:** Validate JSON number grammar (optional sign, integer, fraction, exponent). Store as text — no float conversion in hot path.

**Error handling:** On structural error, emit an ERROR token with offset and stop. Still return tokens consumed so far.

**Deliverable tests:**
- Tokenize `{"a":1}` → OBJECT_START, KEY("a"), COLON, NUMBER("1"), OBJECT_END
- Tokenize nested objects and arrays
- Tokenize strings with escape sequences (`\"`, `\\`, `\n`, `\uXXXX`)
- Reject trailing commas, unquoted keys, and other common JSON errors
- Tokenize large JSON (~1MB) without stack overflow

---

### P9-006: JSON Path Matcher (2h)

**File:** `src/data_extractor.cpp`

Match JSONPath expressions against the JSON token stream.

**JSONPath grammar:**
```
path          = '$' segment*
segment       = '.' identifier | '[' string ']' | '[' number ']' | '[*]'
identifier    = [a-zA-Z_][a-zA-Z0-9_]*
```

**Examples:**
- `$.data.course.title` → drill into nested object keys
- `$.data.courses[0].name` → array index access
- `$.data.items[*].id` → wildcard array — emit all matching values

**Matching strategy:**
1. Track current JSONPath as we walk the token stream
2. Build a path stack: each OBJECT_START/ARRAY_START pushes context, OBJECT_END/ARRAY_END pops
3. For each value token (STRING, NUMBER, BOOLEAN, NULL), compute its full JSONPath
4. If the path matches any requested path pattern, invoke the callback

**Wildcard matching:** `[*]` matches any array index. `[*]` within a path emits one callback per array element's matching sub-path.

**Deliverable tests:**
- Match `$.store.book[0].title` against sample JSON
- Match `$.store.book[*].author` → 4 callbacks for 4 books
- Match `$..author` (deep scan — optional stretch goal)
- No match when path doesn't exist
- Wildcard in middle of path

---

### P9-007: ExtractionPlan + Dispatch (2h)

**File:** `include/pntp/data_extractor.h`, `src/data_extractor.cpp`

**ExtractionPlan:**
```cpp
struct ExtractionRule {
    enum Type { CSS_SELECTOR, JSON_PATH, REGEX, HEURISTIC };
    Type type;
    std::string pattern;      // CSS selector, JSON path, or regex
    std::string output_name;  // key in result map
    std::string attribute;    // for CSS: "text" (default), "href", "src", etc.
    bool multiple;            // collect all matches vs first only
};
struct ExtractionPlan {
    std::vector<ExtractionRule> rules;
};
struct ExtractionResult {
    std::map<std::string, std::vector<std::string>> fields;
    double elapsed_ms;
    size_t bytes_processed;
};
```

**Content-type dispatch:**
```cpp
ExtractionResult extract(const ExtractionPlan& plan,
                         std::string_view data,
                         const std::string& content_type);
```

| Content-Type | Strategy |
|---|---|
| `text/html` | SAX HTML + CSS selectors |
| `application/json` | JSON streamer + JSONPath |
| `application/xml`, `text/xml` | SAX HTML tokenizer (tolerantly) + CSS selectors |
| `text/plain` | Heuristic engine |
| `*/*` fallback | Try SAX HTML first, if error try JSON, if error try heuristic |

**Route selection:** Parse content type from header (strip charset: `text/html; charset=utf-8` → `text/html`). Dispatch to appropriate engine.

**ExtractionRule::REGEX:** Only for fallback. Use `std::regex` wrapped in our regex cache to avoid recompilation. Low priority.

**Deliverable tests:**
- Define plan with 3 CSS rules, extract from sample HTML, verify all 3 populated
- Define plan with JSONPath rules, extract from sample JSON
- Auto-detect content type and select correct engine
- Empty plan returns empty result
- Rule with `multiple=false` returns only first match
- Rule with `multiple=true` returns all matches

---

### P9-008: Regex Heuristic Engine (1h)

**File:** `src/data_extractor.cpp`

Fallback pattern discovery for unstructured or unknown content types.

```cpp
struct DiscoveredPattern {
    std::regex pattern;
    std::string sample;          // first match (for preview)
    double confidence;           // 0.0 to 1.0
    std::string suggested_type;  // "url", "email", "price", "date", etc.
};
```

**Built-in pattern catalog:**
- URL: `https?://[^\s<>"']+`
- Email: `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`
- Price: `\$?\d+(?:\.\d{2})?`
- Date ISO: `\d{4}-\d{2}-\d{2}`
- HTML tag content: `<(\w+)[^>]*>([^<]+)</\1>` (low confidence)

**Confidence scoring:**
- Multiple matches → higher confidence
- Context match (e.g., price near "$" signs) → higher confidence
- Contradictory patterns → lower confidence

**Deliverable tests:**
- Discover URLs in plain text
- Discover prices in product description
- Empty input returns no patterns

---

### P9-009: Charset Detection (0.5h)

**File:** `src/data_extractor.cpp`

Detect and convert non-UTF-8 content.

**Detection order:**
1. Content-Type header charset parameter: `text/html; charset=iso-8859-1`
2. HTML `<meta charset="...">` or `<meta http-equiv="Content-Type" content="...">`
3. BOM (Byte Order Mark) at start
4. Fallback: treat as UTF-8 (or latin-1 if all bytes are valid latin-1)

**Conversion:**
- Use `iconv` via `#include <iconv.h>` (POSIX)
- Fallback: replace invalid sequences with U+FFFD
- Convert to UTF-8 before SAX/JSON parsing

**Note:** This can be stubbed if iconv is not available. Report error and attempt UTF-8 parsing.

**Deliverable tests:**
- Detect UTF-8 BOM
- Detect `<meta charset="iso-8859-1">`
- No charset → default to UTF-8

---

### P9-010: SAX→CSS Integration Pipeline (1h)

**File:** `src/data_extractor.cpp`

Wire SAXParser + SelectorEngine together for streaming extraction.

**Flow:**
1. `extract()` receives plan + data
2. Creates SAXParser with a callback lambda
3. Callback feeds each TAG_OPEN/TAG_CLOSE/TEXT to SelectorEngine's streaming context
4. SelectorEngine accumulates element context and checks against compiled selector list
5. On match: invoke result collector (extract text or attribute)
6. Return completed ExtractionResult

**Optimization:**
- Compile all CSS selectors once at extract() start
- Maintain one element context stack, matched against all compiled selectors in parallel
- Skip TEXT collection if no rule targets `attribute = "text"`

**Deliverable tests:**
- End-to-end: `extract({CSS rule "h1"})` on `<h1>Title</h1>` → `{"h1": ["Title"]}`
- End-to-end: extract href from `<a href="http://x.com">link</a>`
- Multiple rules in one pass
- Rule with no match returns empty vector for that key

---

### P9-011: Unit Tests — 100 known patterns (2h)

**File:** `test/test_data_extractor.cpp`

**Test HTML corpus (embedded in test):**
- Simple page with title, headings, paragraphs
- Page with navigation list, article, sidebar
- Udacity-like course listing page (multiple cards with title, instructor, price, URL)
- Table with data rows
- Form with inputs
- Malformed HTML (unclosed tags, stray tags)

**Test JSON corpus (embedded in test):**
- Simple object with nested keys
- Array of objects
- Deeply nested structure
- JSON with string escapes
- Malformed JSON (error recovery)

**Extraction scenarios:**
1. Extract single element by tag
2. Extract by class name
3. Extract by id
4. Extract by attribute presence
5. Extract by attribute value
6. Extract nested via descendant selector
7. Extract via direct child selector
8. Extract via nth-child
9. Extract combined selector (tag.class#id)
10. Extract multiple matches
11. Extract attribute vs text content
12. No match returns empty
13. JSONPath simple key
14. JSONPath nested key
15. JSONPath array index
16. JSONPath wildcard
17. Mixed plan (CSS + JSONPath)
18. Extraction from unknown content type (heuristic fallback)

---

### P9-012: CSS Selector Accuracy vs Reference (1h)

Write a test that compares CSS selector results against a known-good output for a fixed HTML document. Manually verify once, then encode as test assertion.

**Test document:** A diverse HTML page with:
- Multiple `h1`/`h2`/`h3` elements
- Elements with and without classes/ids
- Nested lists
- Tables with rows
- Links with href attributes
- Images with src and alt

For each selector, record expected match count and expected text/attr of first match.

---

### P9-013: Benchmark — SAX Throughput (0.5h)

**File:** `test/test_data_extractor.cpp` or `bench/bench_data_extractor.cpp`

**Metrics:**
- SAX parse throughput: MB/s for 1MB, 10MB, 100MB HTML (synthetic)
- CSS selector matching: matches/second for increasing selector complexity
- JSON stream throughput: MB/s
- ExtractionPlan overhead: plan with 1/10/100 rules

**Measurement:**
- Use `std::chrono::steady_clock` (or `CPUTimer` from assembly once Phase 12 is done)
- Report min/avg/max over 10 runs
- Target: >100 MB/s SAX parsing, >1M selectors/s matching

---

## Implementation Order

```
Priority 1 (Foundation):
  P9-001: SAX HTML tokenizer — everything depends on this
  P9-005: JSON streaming tokenizer — independent, can be parallel

Priority 2 (Matching):
  P9-003: CSS selector tokenizer
  P9-004: CSS selector match engine
  P9-006: JSON path matcher

Priority 3 (Integration):
  P9-002: Token callback API
  P9-007: ExtractionPlan + dispatch
  P9-010: SAX→CSS integration pipeline

Priority 4 (Polish):
  P9-008: Regex heuristic engine
  P9-009: Charset detection

Priority 5 (Validation):
  P9-011: Unit tests — 100 patterns
  P9-012: CSS accuracy vs reference
  P9-013: Benchmark
```

**Hardest-first order:** P9-001 → P9-005 → P9-003 → P9-004 → P9-006 → P9-002 → P9-007 → P9-010 → P9-008 → P9-009 → P9-011 → P9-012 → P9-013

---

## Risk Register

| Risk | Impact | Mitigation |
|------|--------|------------|
| HTML entity decoding is incomplete | Missing characters in output | Implement the 5 XML entities first; numeric entities (`&#NN;`) second; named HTML5 entities last (can skip) |
| CSS nth-child formula parsing is complex | Selector fails for `2n+1`, `odd`, `even` | Support `odd`/`even`/`n`/`2n`/`2n+1`/`n+3`; reject more complex formulas |
| JSON streaming parser OOM on huge inputs | Memory exhaustion | Bounded token buffer (configurable, default 10M tokens); error if exceeded |
| SAX tokenizer too slow on large HTML | Throughput below target | Optimize with `memchr` for tag boundaries, table-driven state machine |
| Charset iconv not available | Build failure | `#ifdef HAS_ICONV` guard; fallback to UTF-8-only mode |
| Selector specificity conflicts | Wrong element matched | Implement specificity calculation (RFC), match highest specificity first |
| Malformed HTML causes infinite loop | Hang | Maximum input size check; maximum nesting depth (default 1000); error token for malformed input |

---

## API Surface

```cpp
// ── SAX Token Types ──────────────────────────────────────────

struct Attribute {
    std::string name;
    std::string value;
    bool quoted;
};

struct SAXToken {
    enum Type {
        TAG_OPEN, TAG_CLOSE, TEXT, COMMENT, DOCTYPE,
        CDATA, SCRIPT, STYLE, ERROR, EOF_
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
    enum Type {
        TAG, ID, CLASS,
        ATTR_PRESENCE, ATTR_EQUALS, ATTR_CONTAINS_WORD,
        ATTR_BEGINS, ATTR_ENDS, ATTR_CONTAINS,
        NTH_CHILD
    };
    Type type;
    std::string name;
    std::string value;
};

struct CompoundSelector {
    std::vector<SimpleSelector> simples;
};

enum Combinator { DESCENDANT, CHILD, ADJACENT_SIBLING, GENERAL_SIBLING };

struct CompiledSelector {
    std::vector<std::pair<Combinator, CompoundSelector>> parts;
    // First part has combinator = DESCENDANT (no preceding combinator)
};
using CompiledSelectors = std::vector<CompiledSelector>;

// ── JSON Types ────────────────────────────────────────────────

struct JSONToken {
    enum Type {
        OBJECT_START, OBJECT_END,
        ARRAY_START, ARRAY_END,
        STRING, NUMBER, BOOLEAN, NULL_,
        COLON, COMMA, KEY, ERROR
    };
    Type type;
    std::string value;
    size_t offset;
    size_t length;
};

// ── Extraction Types ──────────────────────────────────────────

struct ExtractionRule {
    enum Type { CSS_SELECTOR, JSON_PATH, REGEX, HEURISTIC };
    Type type;
    std::string pattern;
    std::string output_name;
    std::string attribute;  // "text" | attr name
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

// ── Main Class ────────────────────────────────────────────────

class DataExtractor {
public:
    DataExtractor();

    // ── High-level extraction ──
    ExtractionResult extract(const ExtractionPlan& plan,
                             std::string_view data,
                             const std::string& content_type);

    // ── SAX HTML Parser ──
    using TokenCallback = std::function<bool(const SAXToken&)>;

    struct SAXParser {
        void parse(std::string_view html, TokenCallback cb);
        std::vector<SAXToken> parse(std::string_view html);
        static bool isVoidElement(std::string_view tag);
        static bool isRawTextElement(std::string_view tag);
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

    struct Match {
        const SAXToken* token;
        std::string selector_text;
        std::string textContent(const std::vector<SAXToken>& tokens) const;
    };

    // ── JSON Streaming Parser ──
    struct JSONStreamer {
        using ValueCallback = std::function<void(const std::vector<std::string>& path,
                                                  const JSONToken& value)>;
        void parse(std::string_view json,
                   const std::vector<std::string>& paths,
                   ValueCallback cb);
        std::vector<JSONToken> tokenize(std::string_view json);
    };

    // ── Heuristic Engine ──
    struct HeuristicEngine {
        std::vector<DiscoveredPattern> discover(std::string_view data);
    };

    struct DiscoveredPattern {
        std::string regex_str;
        std::string sample;
        double confidence;
        std::string suggested_type;
    };

    // ── Charset Handling ──
    static std::string detectCharset(std::string_view data,
                                     const std::string& content_type);
    static std::string convertToUtf8(std::string_view data,
                                     const std::string& from_charset);

private:
    ExtractionResult extractHtml(const ExtractionPlan& plan,
                                  std::string_view data);
    ExtractionResult extractJson(const ExtractionPlan& plan,
                                  std::string_view data);
    ExtractionResult extractHeuristic(const ExtractionPlan& plan,
                                       std::string_view data);
    std::string dispatchContentType(const std::string& content_type);
};
```

---

## Acceptance Criteria

- [ ] All ~130+ tests pass (7 existing migrate + ~125 new)
- [ ] SAX parser correctly tokenizes 10 HTML test files with >99% accuracy vs reference
- [ ] CSS selector matching matches known-good selectors on test document
- [ ] JSON streaming parser handles 1MB input without crash or OOM
- [ ] JSONPath `[*]` wildcard produces correct number of results
- [ ] ExtractionPlan correctly routes to HTML vs JSON vs heuristic paths
- [ ] No `std::regex` in hot path (CSS selectors and JSON paths are hand-written)
- [ ] No `std::cout`, `std::cerr`, or iostream in implementation
- [ ] No exceptions in hot path
- [ ] SAX throughput >50 MB/s (debug build, benchmark test)
- [ ] `ldd` shows no new unexpected dependencies

---

## Files Changed

| File | Change |
|------|--------|
| `include/pntp/data_extractor.h` | Rewrite: 25 lines → ~250 lines with full API |
| `src/data_extractor.cpp` | Rewrite: 89 lines regex stub → ~2500 lines implementation |
| `test/test_data_extractor.cpp` | Rewrite: 7 tests → ~130+ tests |
| `test/CMakeLists.txt` | Add data_extractor sources to PNTP_TEST_SOURCES |
