#include "pntp/url_manipulator.h"
#include <gtest/gtest.h>
#include <string_view>
#include <cstdint>
#include <vector>
#include <map>
#include <string>

class UrlManipulatorTest : public ::testing::Test {
protected:
    UrlManipulator manipulator;
};

// ── ParsedURL::parse() Tests ──────────────────────────────────────

TEST(ParsedURLParseTest, SimpleHttp) {
    auto parsed = ParsedURL::parse("http://example.com");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "http");
    EXPECT_EQ(parsed.host, "example.com");
}

TEST(ParsedURLParseTest, WithPath) {
    auto parsed = ParsedURL::parse("https://example.com/path/to/resource");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "https");
    EXPECT_EQ(parsed.host, "example.com");
    EXPECT_EQ(parsed.path, "/path/to/resource");
}

TEST(ParsedURLParseTest, WithQuery) {
    auto parsed = ParsedURL::parse("https://example.com/path?key=value&foo=bar");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.host, "example.com");
    EXPECT_EQ(parsed.path, "/path");
    EXPECT_EQ(parsed.query, "key=value&foo=bar");
}

TEST(ParsedURLParseTest, WithFragment) {
    auto parsed = ParsedURL::parse("https://example.com/path#section");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.host, "example.com");
    EXPECT_EQ(parsed.path, "/path");
    EXPECT_EQ(parsed.fragment, "section");
}

TEST(ParsedURLParseTest, WithPort) {
    auto parsed = ParsedURL::parse("https://example.com:8080/path");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "https");
    EXPECT_EQ(parsed.host, "example.com");
    EXPECT_EQ(parsed.port, 8080);
    EXPECT_EQ(parsed.path, "/path");
}

TEST(ParsedURLParseTest, WithUserinfo) {
    auto parsed = ParsedURL::parse("https://user:pass@example.com");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "https");
    EXPECT_EQ(parsed.userinfo, "user:pass");
    EXPECT_EQ(parsed.host, "example.com");
}

TEST(ParsedURLParseTest, WithIPv6Host) {
    auto parsed = ParsedURL::parse("http://[::1]:8080/path");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "http");
    EXPECT_EQ(parsed.host, "[::1]");
    EXPECT_EQ(parsed.port, 8080);
    EXPECT_EQ(parsed.path, "/path");
}

TEST(ParsedURLParseTest, WithIPv6AndAuth) {
    auto parsed = ParsedURL::parse("http://user@[::1]/path");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "http");
    EXPECT_EQ(parsed.userinfo, "user");
    EXPECT_EQ(parsed.host, "[::1]");
    EXPECT_EQ(parsed.path, "/path");
}

TEST(ParsedURLParseTest, ComplexUrl) {
    auto parsed = ParsedURL::parse("https://user:pass@host.com:443/path?q=1&r=2#frag");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "https");
    EXPECT_EQ(parsed.userinfo, "user:pass");
    EXPECT_EQ(parsed.host, "host.com");
    EXPECT_EQ(parsed.port, 443);
    EXPECT_EQ(parsed.path, "/path");
    EXPECT_EQ(parsed.query, "q=1&r=2");
    EXPECT_EQ(parsed.fragment, "frag");
}

TEST(ParsedURLParseTest, MinimalHttp) {
    auto parsed = ParsedURL::parse("http://a");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "http");
    EXPECT_EQ(parsed.host, "a");
}

TEST(ParsedURLParseTest, EmptyString) {
    auto parsed = ParsedURL::parse("");
    EXPECT_FALSE(parsed.valid);
}

TEST(ParsedURLParseTest, MalformedNoScheme) {
    auto parsed = ParsedURL::parse("just/a/path");
    EXPECT_FALSE(parsed.valid);
}

// ── ParsedURL::serialize() Tests ───────────────────────────────────

TEST(ParsedURLSerializeTest, RoundTripSimple) {
    auto parsed = ParsedURL::parse("http://example.com/path");
    ASSERT_TRUE(parsed.valid);
    auto reparsed = ParsedURL::parse(parsed.serialize());
    EXPECT_TRUE(reparsed.valid);
    EXPECT_EQ(reparsed.scheme, parsed.scheme);
    EXPECT_EQ(reparsed.host, parsed.host);
    EXPECT_EQ(reparsed.path, parsed.path);
}

TEST(ParsedURLSerializeTest, RoundTripWithPort) {
    auto parsed = ParsedURL::parse("https://example.com:8080/path");
    ASSERT_TRUE(parsed.valid);
    auto reparsed = ParsedURL::parse(parsed.serialize());
    EXPECT_TRUE(reparsed.valid);
    EXPECT_EQ(reparsed.port, parsed.port);
}

TEST(ParsedURLSerializeTest, RoundTripWithQuery) {
    auto parsed = ParsedURL::parse("http://example.com/path?key=val&foo=bar");
    ASSERT_TRUE(parsed.valid);
    auto reparsed = ParsedURL::parse(parsed.serialize());
    EXPECT_TRUE(reparsed.valid);
    EXPECT_EQ(reparsed.query, parsed.query);
}

TEST(ParsedURLSerializeTest, RoundTripComplex) {
    auto parsed = ParsedURL::parse("https://user:pass@host.com:443/path?q=1&r=2#frag");
    ASSERT_TRUE(parsed.valid);
    auto reparsed = ParsedURL::parse(parsed.serialize());
    EXPECT_TRUE(reparsed.valid);
    EXPECT_EQ(reparsed.scheme, parsed.scheme);
    EXPECT_EQ(reparsed.userinfo, parsed.userinfo);
    EXPECT_EQ(reparsed.host, parsed.host);
    EXPECT_EQ(reparsed.port, parsed.port);
    EXPECT_EQ(reparsed.path, parsed.path);
    EXPECT_EQ(reparsed.query, parsed.query);
    EXPECT_EQ(reparsed.fragment, parsed.fragment);
}

// ── ParsedURL::defaultPort() Tests ─────────────────────────────────

TEST(ParsedURLDefaultPortTest, HttpDefault) {
    EXPECT_EQ(ParsedURL::defaultPort("http"), 80);
}

TEST(ParsedURLDefaultPortTest, HttpsDefault) {
    EXPECT_EQ(ParsedURL::defaultPort("https"), 443);
}

TEST(ParsedURLDefaultPortTest, UnknownSchemeReturnsZero) {
    EXPECT_EQ(ParsedURL::defaultPort("unknown"), 0);
}

// ── Percent Encoding Tests ─────────────────────────────────────────

TEST(PercentEncodingTest, RoundTripNormalAscii) {
    std::string input = "HelloWorld123";
    auto encoded = urlEncode(input);
    auto decoded = urlDecode(encoded);
    EXPECT_EQ(decoded, input);
}

TEST(PercentEncodingTest, EncodeReservedChars) {
    std::string input = "hello world:foo/bar?query#frag[abc]@def";
    auto encoded = urlEncode(input);
    EXPECT_EQ(encoded.find(' '), std::string::npos);
    EXPECT_EQ(encoded.find(':'), std::string::npos);
    auto decoded = urlDecode(encoded);
    EXPECT_EQ(decoded, input);
}

TEST(PercentEncodingTest, DecodePercentSequences) {
    EXPECT_EQ(urlDecode("%48%65%6C%6C%6F"), "Hello");
}

TEST(PercentEncodingTest, DecodeInvalidPercent) {
    std::string input = "%ZZ%2";
    EXPECT_EQ(urlDecode(input), input);
}

TEST(PercentEncodingTest, EmptyString) {
    EXPECT_TRUE(urlEncode("").empty());
    EXPECT_TRUE(urlDecode("").empty());
}

TEST(PercentEncodingTest, NoEncodingNeeded) {
    std::string input = "abcdefghijklmnopqrstuvwxyz0123456789-._~";
    EXPECT_EQ(urlEncode(input), input);
}

TEST(PercentEncodingTest, DecodePlusAsSpace) {
    EXPECT_EQ(urlDecode("hello+world"), "hello world");
}

// ── normalize() Tests ──────────────────────────────────────────────

TEST_F(UrlManipulatorTest, NormalizeLowercasesScheme) {
    EXPECT_EQ(manipulator.normalize("HTTP://EXAMPLE.COM"), "http://example.com");
}

TEST_F(UrlManipulatorTest, NormalizeLowercasesHost) {
    EXPECT_EQ(manipulator.normalize("http://Example.Com"), "http://example.com");
}

TEST_F(UrlManipulatorTest, NormalizeRemovesDefaultPort) {
    EXPECT_EQ(manipulator.normalize("http://example.com:80/"), "http://example.com/");
}

TEST_F(UrlManipulatorTest, NormalizeKeepsNonDefaultPort) {
    EXPECT_EQ(manipulator.normalize("http://example.com:8080/"), "http://example.com:8080/");
}

TEST_F(UrlManipulatorTest, NormalizeResolvesDotSegments) {
    EXPECT_EQ(manipulator.normalize("http://example.com/a/b/../c"), "http://example.com/a/c");
}

TEST_F(UrlManipulatorTest, NormalizeRemovesEmptyQuery) {
    EXPECT_EQ(manipulator.normalize("http://example.com/?"), "http://example.com/");
}

TEST_F(UrlManipulatorTest, NormalizeRemovesEmptyFragment) {
    EXPECT_EQ(manipulator.normalize("http://example.com/#"), "http://example.com/");
}

TEST_F(UrlManipulatorTest, NormalizeRemovesEmptyQueryAndFragment) {
    EXPECT_EQ(manipulator.normalize("HTTP://EXAMPLE.COM:80/?#"), "http://example.com/");
}

// ── mutateQuery() Tests ────────────────────────────────────────────

TEST_F(UrlManipulatorTest, MutateQuerySetNewParam) {
    std::string result = manipulator.mutateQuery(
        "http://example.com/path",
        {QueryOp{QueryOpType::SET, "new", "", "val", {}}});
    EXPECT_NE(result.find("new=val"), std::string::npos);
}

TEST_F(UrlManipulatorTest, MutateQuerySetOverwritesExisting) {
    std::string result = manipulator.mutateQuery(
        "http://example.com/path?key=old",
        {QueryOp{QueryOpType::SET, "key", "", "new", {}}});
    EXPECT_NE(result.find("key=new"), std::string::npos);
    EXPECT_EQ(result.find("key=old"), std::string::npos);
}

TEST_F(UrlManipulatorTest, MutateQueryDeleteParam) {
    std::string result = manipulator.mutateQuery(
        "http://example.com/path?key=val&keep=1",
        {QueryOp{QueryOpType::DELETE, "key", "", "", {}}});
    EXPECT_EQ(result.find("key="), std::string::npos);
    EXPECT_NE(result.find("keep=1"), std::string::npos);
}

TEST_F(UrlManipulatorTest, MutateQueryRenameParam) {
    std::string result = manipulator.mutateQuery(
        "http://example.com/path?old=1",
        {QueryOp{QueryOpType::RENAME, "old", "new", "", {}}});
    EXPECT_NE(result.find("new=1"), std::string::npos);
    EXPECT_EQ(result.find("old="), std::string::npos);
}

TEST_F(UrlManipulatorTest, MutateQuerySignParam) {
    std::string result = manipulator.mutateQuery(
        "http://example.com/path?val=1",
        {QueryOp{QueryOpType::SIGN, "", "", "", {"val"}}});
    EXPECT_NE(result.find("_sig="), std::string::npos);
}

TEST_F(UrlManipulatorTest, MutateQueryMultipleOperations) {
    std::string result = manipulator.mutateQuery(
        "http://example.com/path?a=1&b=2",
        {QueryOp{QueryOpType::SET, "c", "", "3", {}},
         QueryOp{QueryOpType::DELETE, "a", "", "", {}}});
    EXPECT_NE(result.find("c=3"), std::string::npos);
    EXPECT_NE(result.find("b=2"), std::string::npos);
    EXPECT_EQ(result.find("a="), std::string::npos);
}

TEST_F(UrlManipulatorTest, MutateQueryDeleteNonexistent) {
    std::string input = "http://example.com/path?a=1";
    EXPECT_EQ(manipulator.mutateQuery(input, {QueryOp{QueryOpType::DELETE, "nonexistent", "", "", {}}}), input);
}

// ── injectAuth() Tests ─────────────────────────────────────────────

TEST_F(UrlManipulatorTest, InjectAuthBearer) {
    auto headers = manipulator.injectAuth("https://example.com", {}, "BEARER", "mytoken");
    EXPECT_EQ(headers["Authorization"], "Bearer mytoken");
}

TEST_F(UrlManipulatorTest, InjectAuthBasic) {
    auto headers = manipulator.injectAuth("https://example.com", {}, "BASIC", "user:pass");
    ASSERT_TRUE(headers.count("Authorization"));
    EXPECT_TRUE(headers["Authorization"].find("Basic ") == 0);
}

TEST_F(UrlManipulatorTest, InjectAuthCookie) {
    auto headers = manipulator.injectAuth("https://example.com", {}, "COOKIE", "session=abc123");
    EXPECT_EQ(headers["Cookie"], "session=abc123");
}

TEST_F(UrlManipulatorTest, InjectAuthDigest) {
    auto headers = manipulator.injectAuth("https://example.com", {}, "DIGEST", "username=user,realm=test");
    ASSERT_TRUE(headers.count("Authorization"));
    EXPECT_TRUE(headers["Authorization"].find("Digest ") == 0);
    EXPECT_NE(headers["Authorization"].find("realm"), std::string::npos);
}

TEST_F(UrlManipulatorTest, InjectAuthEmptyCredentials) {
    auto headers = manipulator.injectAuth("https://example.com", {}, "BEARER", "");
    EXPECT_TRUE(headers.count("Authorization"));
}

// ── setAuthProvider() + modifyRequestHeaders() Tests ───────────────

TEST_F(UrlManipulatorTest, SetAuthProviderBearer) {
    manipulator.setAuthProvider(UrlManipulator::AuthProvider{"BEARER", "provider_token"});
    auto modified = manipulator.modifyRequestHeaders("https://example.com", {});
    EXPECT_EQ(modified["Authorization"], "Bearer provider_token");
}

TEST_F(UrlManipulatorTest, SetAuthProviderBasic) {
    manipulator.setAuthProvider(UrlManipulator::AuthProvider{"BASIC", "user:pass"});
    auto modified = manipulator.modifyRequestHeaders("https://example.com", {});
    ASSERT_TRUE(modified.count("Authorization"));
    EXPECT_TRUE(modified["Authorization"].find("Basic ") == 0);
}

TEST_F(UrlManipulatorTest, SetAuthProviderSwitchType) {
    manipulator.setAuthProvider(UrlManipulator::AuthProvider{"BASIC", "user:pass"});
    manipulator.setAuthProvider(UrlManipulator::AuthProvider{"BEARER", "switched_token"});
    auto modified = manipulator.modifyRequestHeaders("https://example.com", {});
    EXPECT_EQ(modified["Authorization"], "Bearer switched_token");
}

TEST_F(UrlManipulatorTest, ModifyRequestHeadersPreservesExisting) {
    manipulator.setAuthProvider(UrlManipulator::AuthProvider{"BEARER", "token"});
    std::map<std::string, std::string> headers{{"Accept", "application/json"}};
    auto modified = manipulator.modifyRequestHeaders("https://example.com", headers);
    EXPECT_EQ(modified["Accept"], "application/json");
    EXPECT_EQ(modified["Authorization"], "Bearer token");
}

TEST_F(UrlManipulatorTest, ModifyRequestHeadersUsesTokenFallback) {
    manipulator.setAuthenticationToken("fallback_token");
    auto modified = manipulator.modifyRequestHeaders("https://example.com", {});
    EXPECT_EQ(modified["Authorization"], "Bearer fallback_token");
}

// ── rewriteUrl() Tests ─────────────────────────────────────────────

TEST_F(UrlManipulatorTest, RewriteUrlReturnsNormalized) {
    EXPECT_EQ(manipulator.rewriteUrl("HTTP://EXAMPLE.COM:80/"), "http://example.com/");
}

TEST_F(UrlManipulatorTest, RewriteUrlAlreadyNormalized) {
    EXPECT_EQ(manipulator.rewriteUrl("https://example.com/path"), "https://example.com/path");
}

TEST_F(UrlManipulatorTest, RewriteUrlNormalizesPath) {
    EXPECT_EQ(manipulator.rewriteUrl("http://example.com/a/b/../c"), "http://example.com/a/c");
}

// ── shouldIntercept() Tests ────────────────────────────────────────

TEST_F(UrlManipulatorTest, ShouldInterceptHttps) {
    EXPECT_TRUE(manipulator.shouldIntercept("https://example.com"));
}

TEST_F(UrlManipulatorTest, ShouldInterceptHttp) {
    EXPECT_FALSE(manipulator.shouldIntercept("http://example.com"));
}

TEST_F(UrlManipulatorTest, ShouldInterceptEmpty) {
    EXPECT_FALSE(manipulator.shouldIntercept(""));
}

TEST_F(UrlManipulatorTest, ShouldInterceptFtp) {
    EXPECT_FALSE(manipulator.shouldIntercept("ftp://files.com"));
}

// ── resolveRedirect() Tests ────────────────────────────────────────

TEST_F(UrlManipulatorTest, ResolveRedirectAbsolute) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com", "http://b.com/p"), "http://b.com/p");
}

TEST_F(UrlManipulatorTest, ResolveRedirectProtocolRelative) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com/p", "//b.com/q"), "http://b.com/q");
}

TEST_F(UrlManipulatorTest, ResolveRedirectRootRelative) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com/p/a", "/q"), "http://a.com/q");
}

TEST_F(UrlManipulatorTest, ResolveRedirectRelative) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com/p/a", "b"), "http://a.com/p/b");
}

TEST_F(UrlManipulatorTest, ResolveRedirectRelativeWithDotDot) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com/a/b/c", "../d"), "http://a.com/a/d");
}

TEST_F(UrlManipulatorTest, ResolveRedirectEmptyLocation) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com/p", ""), "http://a.com/p");
}

TEST_F(UrlManipulatorTest, ResolveRedirectDeepRelative) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com/x/y/z", "../../b"), "http://a.com/b");
}

TEST_F(UrlManipulatorTest, ResolveRedirectKeepsPort) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com:8080/p/a", "b"), "http://a.com:8080/p/b");
}

// ── Edge Case Tests ────────────────────────────────────────────────

TEST(EdgeCaseTest, VeryLongUrl) {
    std::string base = "https://example.com/";
    std::string longPath(4096, 'a');
    auto parsed = ParsedURL::parse(base + longPath);
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.host, "example.com");
}

TEST(EdgeCaseTest, MultipleFragments) {
    auto parsed = ParsedURL::parse("http://example.com/path#first#second");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.fragment, "first#second");
}

TEST(EdgeCaseTest, UnicodePercentEncoded) {
    auto parsed = ParsedURL::parse("http://example.com/path/%C3%A9%C3%A0%E2%82%AC");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.path, "/path/%C3%A9%C3%A0%E2%82%AC");
}

TEST_F(UrlManipulatorTest, NormalizeTrailingDots) {
    EXPECT_EQ(manipulator.normalize("http://example.com/a/./b/./c"), "http://example.com/a/b/c");
}

TEST(EdgeCaseTest, UrlWithOnlyScheme) {
    EXPECT_FALSE(ParsedURL::parse("http://").valid);
}

TEST(EdgeCaseTest, UrlWithNoPath) {
    auto parsed = ParsedURL::parse("http://example.com");
    EXPECT_TRUE(parsed.valid);
    EXPECT_TRUE(parsed.path.empty() || parsed.path == "/");
}

TEST_F(UrlManipulatorTest, NormalizeWithPercentEncodedPath) {
    std::string url = "http://example.com/path%20with%20spaces";
    std::string norm = manipulator.normalize(url);
    EXPECT_EQ(norm, url);
}

// ── setAuthenticationToken() Tests ─────────────────────────────────

TEST_F(UrlManipulatorTest, SetAndGetAuthToken) {
    manipulator.setAuthenticationToken("secret");
    EXPECT_EQ(manipulator.getAuthenticationToken(), "secret");
}

TEST_F(UrlManipulatorTest, AuthTokenRoundTrip) {
    manipulator.setAuthenticationToken("round_trip_test");
    auto headers = manipulator.modifyRequestHeaders("https://test.com", {});
    EXPECT_EQ(headers["Authorization"], "Bearer round_trip_test");
    EXPECT_EQ(manipulator.getAuthenticationToken(), "round_trip_test");
}

// ── Goal Validation Tests ──────────────────────────────────────────

TEST_F(UrlManipulatorTest, Goal_Rfc3986Parsing) {
    auto parsed = ParsedURL::parse("https://user:pass@host.com:443/path?q=1#frag");
    EXPECT_TRUE(parsed.valid);
    EXPECT_EQ(parsed.scheme, "https");
    EXPECT_EQ(parsed.userinfo, "user:pass");
    EXPECT_EQ(parsed.host, "host.com");
    EXPECT_EQ(parsed.port, 443);
    EXPECT_EQ(parsed.path, "/path");
    EXPECT_EQ(parsed.query, "q=1");
    EXPECT_EQ(parsed.fragment, "frag");
}

TEST_F(UrlManipulatorTest, Goal_Normalization) {
    EXPECT_EQ(manipulator.normalize("HTTP://Example.Com:80/A/B/../C/./D?"), "http://example.com/A/C/D");
}

TEST_F(UrlManipulatorTest, Goal_QueryMutation) {
    std::string result = manipulator.mutateQuery(
        "http://example.com/path?a=1&b=2",
        {QueryOp{QueryOpType::RENAME, "a", "aa", "", {}},
         QueryOp{QueryOpType::SET, "c", "", "3", {}},
         QueryOp{QueryOpType::DELETE, "b", "", "", {}}});
    EXPECT_NE(result.find("aa=1"), std::string::npos);
    EXPECT_NE(result.find("c=3"), std::string::npos);
    EXPECT_EQ(result.find("b="), std::string::npos);
}

TEST_F(UrlManipulatorTest, Goal_RedirectTracing) {
    EXPECT_EQ(UrlManipulator::resolveRedirect("http://a.com/x/y", "../../z"), "http://a.com/z");
}

TEST_F(UrlManipulatorTest, Goal_PercentEncoding) {
    std::string input = "hello world!@#$%";
    EXPECT_EQ(urlDecode(urlEncode(input)), input);
}

TEST_F(UrlManipulatorTest, Goal_AuthenticationInjection) {
    manipulator.setAuthProvider(UrlManipulator::AuthProvider{"BEARER", "goal_test_token"});
    auto headers = manipulator.modifyRequestHeaders("https://example.com", {});
    EXPECT_EQ(headers["Authorization"], "Bearer goal_test_token");
}

TEST_F(UrlManipulatorTest, Goal_ShouldInterceptHttpsOnly) {
    EXPECT_TRUE(manipulator.shouldIntercept("https://secure.com"));
    EXPECT_FALSE(manipulator.shouldIntercept("http://plain.com"));
    EXPECT_FALSE(manipulator.shouldIntercept(""));
}

TEST_F(UrlManipulatorTest, Goal_RewriteIntegratesNormalize) {
    EXPECT_EQ(manipulator.rewriteUrl("HTTP://EXAMPLE.COM:80/./a/b/../c?"), "http://example.com/a/c");
}

TEST(GoalTest, ParsedUrlDefaultPorts) {
    EXPECT_EQ(ParsedURL::defaultPort("http"), 80);
    EXPECT_EQ(ParsedURL::defaultPort("https"), 443);
}

TEST(GoalTest, PercentDecodeInvalidPreservesInput) {
    EXPECT_EQ(urlDecode("%GG%2X%"), "%GG%2X%");
}

TEST_F(UrlManipulatorTest, Goal_RoundTripSerialize) {
    auto parsed = ParsedURL::parse("http://example.com:8080/path?q=v#f");
    ASSERT_TRUE(parsed.valid);
    auto reparsed = ParsedURL::parse(parsed.serialize());
    EXPECT_TRUE(reparsed.valid);
    EXPECT_EQ(reparsed.scheme, parsed.scheme);
    EXPECT_EQ(reparsed.host, parsed.host);
    EXPECT_EQ(reparsed.port, parsed.port);
    EXPECT_EQ(reparsed.path, parsed.path);
    EXPECT_EQ(reparsed.query, parsed.query);
    EXPECT_EQ(reparsed.fragment, parsed.fragment);
}

// ════════════════════════════════════════════════════════════════════
// Phase 8 — P8-006 / P8-008 / P8-010
// Redirect chain tracer + 1000-URL corpus vs independent reference.
// ════════════════════════════════════════════════════════════════════

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <thread>

namespace {

// Independent RFC 3986 §5.2.4 dot-segment removal (written from the RFC,
// deliberately not mirroring url_manipulator.cpp).
std::string refRemoveDotSegments(const std::string& path) {
    if (path.empty() || path == "/") return path;
    std::vector<std::string> segs;
    bool absolute = (!path.empty() && path[0] == '/');
    size_t start = absolute ? 1 : 0;
    const size_t n = path.size();
    while (start < n) {
        size_t slash = path.find('/', start);
        std::string seg = (slash == std::string::npos)
            ? path.substr(start) : path.substr(start, slash - start);
        if (seg == "..") {
            if (!segs.empty()) segs.pop_back();
        } else if (seg != "." && !seg.empty()) {
            segs.push_back(seg);
        }
        start = (slash == std::string::npos) ? n : slash + 1;
    }
    std::string out;
    if (absolute) out += '/';
    for (size_t k = 0; k < segs.size(); ++k) {
        if (k > 0) out += '/';
        out += segs[k];
    }
    if (path.size() > 1 && path.back() == '/' && !segs.empty()) out += '/';
    return out;
}

std::string refLower(const std::string& s) {
    std::string o = s;
    for (char& c : o) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return o;
}

int refDefaultPort(const std::string& scheme) {
    if (scheme == "http" || scheme == "ws") return 80;
    if (scheme == "https" || scheme == "wss") return 443;
    if (scheme == "ftp") return 21;
    return 0;
}

// Independent RFC 3986 reference normalizer.
std::string refNormalize(const std::string& url) {
    ParsedURL p = ParsedURL::parse(url);
    if (!p.valid) return url;
    p.scheme = refLower(p.scheme);
    p.host = refLower(p.host);
    int def = refDefaultPort(p.scheme);
    if (def != 0 && p.port == static_cast<uint16_t>(def)) p.port = 0;
    p.path = refRemoveDotSegments(p.path);
    return p.serialize();
}

// Deterministic corpus generator: produces URL i in [0, count).
std::string generateCorpusUrl(size_t i, size_t count) {
    static const char* kSchemes[] = {"http", "https", "ftp", "http", "https"};
    static const char* kHosts[] = {"www.example.com", "api.example.org",
                                   "cdn.example.net", "sub.example.com"};
    static const char* kPaths[] = {
        "", "/", "/a", "/a/b/c", "/a/./b", "/a/../b", "/a/b/../c/d",
        "/a//b", "/x/y/z/../../w", "/%41/%7a", "/caf\xC3\xA9"}
        ;
    static const char* kDefPorts[] = {"", ":80", ":443", ":8080", ":21"};
    size_t sel = i;
    std::string out = kSchemes[sel % 5];
    out += "://";
    if (i % 7 == 0) out += "user@";
    out += kHosts[(sel / 5) % 4];
    out += kDefPorts[(sel / 20) % 5];
    out += kPaths[(sel / 100) % 11];
    if (i % 3 == 0) out += "?q=" + std::to_string(sel);
    if (i % 5 == 0) out += "#frag";
    return out;
}

// ── Minimal loopback HTTP/1.1 server + client (test-only) ───────────
struct HttpResp { int status = 0; std::string location; };

bool httpGet(const std::string& hostport, const std::string& path,
             HttpResp& out) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    timeval tv{};
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    size_t colon = hostport.rfind(':');
    std::string host = hostport.substr(0, colon);
    uint16_t port = static_cast<uint16_t>(
        std::strtoul(hostport.substr(colon + 1).c_str(), nullptr, 10));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    ::inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return false;
    }
    std::string req = "GET /" + path + " HTTP/1.1\r\nHost: " +
                      hostport + "\r\nConnection: close\r\n\r\n";
    (void)::send(fd, req.data(), req.size(), 0);
    std::string buf;
    char tmp[1024];
    ssize_t r;
    while ((r = ::recv(fd, tmp, sizeof(tmp), 0)) > 0) {
        buf.append(tmp, static_cast<size_t>(r));
    }
    ::close(fd);
    if (buf.compare(0, 9, "HTTP/1.1 ") != 0) return false;
    out.status = std::atoi(buf.c_str() + 9);
    size_t cl = buf.find("\r\nLocation:");
    if (cl != std::string::npos) {
        size_t vs = cl + 11;
        while (vs < buf.size() &&
               (buf[vs] == ' ' || buf[vs] == '\t')) {
            ++vs;
        }
        size_t ve = buf.find("\r\n", vs);
        out.location = buf.substr(vs, ve - vs);
    }
    return true;
}

int runRedirectServer(uint16_t& out_port) {
    int listen_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) return -1;
    int one = 1;
    ::setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::bind(listen_fd, reinterpret_cast<sockaddr*>(&addr),
               sizeof(addr)) != 0) {
        ::close(listen_fd);
        return -1;
    }
    sockaddr_in got{};
    socklen_t glen = sizeof(got);
    ::getsockname(listen_fd, reinterpret_cast<sockaddr*>(&got), &glen);
    out_port = ntohs(got.sin_port);
    ::listen(listen_fd, 8);
    return listen_fd;
}

} // namespace

// P8-010: redirect chain with 5 hops (canned responder, offline).
TEST(RedirectTracerTest, FiveHopChain) {
    std::map<std::string, RedirectResponse> table = {
        {"https://a.example/start", {302, "/h1"}},
        {"https://a.example/h1",     {301, "https://b.example/h2"}},
        {"https://b.example/h2",     {303, "/h3?next=1"}},
        {"https://b.example/h3?next=1", {307, "h4"}},
        {"https://b.example/h4",     {308, "/final"}},
        {"https://b.example/final",  {200, ""}},
    };
    RedirectTracer tracer(5);
    RedirectTrace t = tracer.trace(
        "https://a.example/start",
        [&](const std::string& url) { return table.at(url); });

    ASSERT_EQ(t.hops.size(), 6u);
    EXPECT_EQ(t.hops[0].url, "https://a.example/start");
    EXPECT_TRUE(t.hops[4].followed);
    EXPECT_FALSE(t.hops.back().followed);  // terminal hop resolves
    EXPECT_TRUE(t.completed);
    EXPECT_FALSE(t.loop_detected);
    EXPECT_FALSE(t.too_many_hops);
    EXPECT_EQ(t.stop_reason, "done");
    EXPECT_EQ(t.final_url, "https://b.example/final");
    EXPECT_EQ(t.hops[1].status, 301);
    EXPECT_EQ(t.hops[2].url, "https://b.example/h2");
}

TEST(RedirectTracerTest, MaxHopsEnforced) {
    std::map<std::string, RedirectResponse> table = {
        {"https://a.example/0", {302, "/1"}},
        {"https://a.example/1", {302, "/2"}},
        {"https://a.example/2", {302, "/3"}},
        {"https://a.example/3", {302, "/4"}},
        {"https://a.example/4", {302, "/5"}},
        {"https://a.example/5", {200, ""}},
    };
    RedirectTracer tracer(2);
    RedirectTrace t = tracer.trace(
        "https://a.example/0",
        [&](const std::string& url) { return table.at(url); });

    EXPECT_TRUE(t.too_many_hops);
    EXPECT_FALSE(t.completed);
    EXPECT_EQ(t.stop_reason, "max_hops");
    EXPECT_EQ(t.hops.size(), 3u);  // start + 2 redirects, then cap
    EXPECT_EQ(t.final_url, "https://a.example/2");
}

TEST(RedirectTracerTest, LoopDetected) {
    std::map<std::string, RedirectResponse> table = {
        {"https://a.example/x", {302, "/y"}},
        {"https://a.example/y", {302, "/x"}},
    };
    RedirectTracer tracer(10);
    RedirectTrace t = tracer.trace(
        "https://a.example/x",
        [&](const std::string& url) { return table.at(url); });

    EXPECT_TRUE(t.loop_detected);
    EXPECT_FALSE(t.completed);
    EXPECT_EQ(t.stop_reason, "loop");
    EXPECT_EQ(t.final_url, "https://a.example/x");
}

TEST(RedirectTracerTest, DirectHitNoRedirect) {
    RedirectTracer tracer(5);
    RedirectTrace t = tracer.trace(
        "https://a.example/ok",
        [](const std::string&) { return RedirectResponse{200, ""}; });

    ASSERT_EQ(t.hops.size(), 1u);
    EXPECT_TRUE(t.completed);
    EXPECT_EQ(t.stop_reason, "done");
    EXPECT_EQ(t.final_url, "https://a.example/ok");
}

TEST(RedirectTracerTest, FailedHopStops) {
    RedirectTracer tracer(5);
    RedirectTrace t = tracer.trace(
        "https://a.example/ok",
        [](const std::string&) { return RedirectResponse{0, ""}; });

    EXPECT_EQ(t.stop_reason, "fetch_failed");
    EXPECT_FALSE(t.completed);
    ASSERT_EQ(t.hops.size(), 1u);
}

// P8-008: parse + normalize 1000 URLs against an independent reference.
TEST_F(UrlManipulatorTest, ParseNormalize_1000UrlCorpus) {
    const size_t kCount = 1000;
    for (size_t i = 0; i < kCount; ++i) {
        std::string url = generateCorpusUrl(i, kCount);
        ParsedURL p = ParsedURL::parse(url);
        ASSERT_TRUE(p.valid) << "corpus url " << i << ": " << url;

        EXPECT_EQ(p.serialize(), p.serialize()) << "i=" << i;

        std::string normalized = manipulator.normalize(url);
        std::string expected = refNormalize(url);
        EXPECT_EQ(normalized, expected) << "i=" << i << " url=" << url;

        // normalize() must be idempotent.
        EXPECT_EQ(manipulator.normalize(normalized), normalized) << "i=" << i;
    }
}

// P8-008/P8-010 live cross-check: our tracer over real loopback TCP vs
// the system curl. Skips when curl is absent or the server won't bind.
TEST(RedirectTracerTest, LiveChainMatchesCurl) {
    if (::system("command -v curl >/dev/null 2>&1") != 0) {
        GTEST_SKIP() << "curl not available";
    }

    uint16_t port = 0;
    int listen_fd = runRedirectServer(port);
    if (listen_fd < 0) {
        GTEST_SKIP() << "cannot bind loopback server";
    }

    // Serve: /start -> /h1 -> /h2 -> (200). Handles every connection that
// arrives until the listener is shut down (tracer + curl both connect).
    std::thread t([&]() {
        for (;;) {
            int fd = ::accept(listen_fd, nullptr, nullptr);
            if (fd < 0) break;
            char buf[2048];
            ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
            std::string headers, body1;
            if (n > 0) {
                std::string req(buf, static_cast<size_t>(n));
                size_t sp = req.find(' ');
                std::string path = (sp == std::string::npos)
                    ? std::string("/")
                    : req.substr(sp + 1);
                size_t sp2 = path.find(' ');
                if (sp2 != std::string::npos) path = path.substr(0, sp2);
                if (path == "/start") {
                    headers = "HTTP/1.1 302 Found\r\nLocation: /h1\r\n";
                } else if (path == "/h1") {
                    headers =
                        "HTTP/1.1 301 Moved Permanently\r\nLocation: /h2\r\n";
                } else {
                    headers = "HTTP/1.1 200 OK\r\n";
                    body1 = "landed";
                }
            } else {
                headers = "HTTP/1.1 200 OK\r\n";
                body1 = "empty";
            }
            std::string resp = headers + "Connection: close\r\n\r\n" + body1;
            (void)::send(fd, resp.data(), resp.size(), 0);
            ::close(fd);
        }
    });

    std::string hostport = "127.0.0.1:" + std::to_string(port);
    std::string start = "http://" + hostport + "/start";

    // Our tracer, driven by real TCP fetches.
    RedirectTracer tracer(5);
    RedirectTrace chain = tracer.trace(
        start, [&](const std::string& url) {
            ParsedURL p = ParsedURL::parse(url);
            std::string hostport2 =
                p.host + ":" + std::to_string(p.port ? p.port : 80);
            HttpResp r;
            if (!httpGet(hostport2, p.path.substr(1), r)) {
                return RedirectResponse{0, ""};
            }
            return RedirectResponse{
                static_cast<uint16_t>(r.status), r.location};
        });

    EXPECT_TRUE(chain.completed) << chain.stop_reason;
    EXPECT_EQ(chain.hops.size(), 3u) << "start + 2 redirects";

    // curl's effective URL for the same chain.
    std::string cmd = std::string("curl -s -o /dev/null -L --max-redirs 5 ")
                          .append("-w '%{url_effective}' '")
                          .append(start)
                          .append("'");
    char out[512];
    std::string curl_eff;
    FILE* f = ::popen(cmd.c_str(), "r");
    if (f) {
        if (std::fgets(out, sizeof(out), f) != nullptr) {
            curl_eff = out;
        }
        ::pclose(f);
    }
    if (!curl_eff.empty()) {
        std::string our_final = chain.final_url;
        UrlManipulator norm;
        EXPECT_EQ(norm.normalize(curl_eff), norm.normalize(our_final))
            << "curl=" << curl_eff << " ours=" << our_final;
    }

    ::shutdown(listen_fd, SHUT_RDWR);
    ::close(listen_fd);
    t.join();
}
