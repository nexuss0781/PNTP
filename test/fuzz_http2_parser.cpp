// SPDX-License-Identifier: MIT
// Fuzz harness for Http2Parser — feeds arbitrary byte sequences through
// the parser to catch crashes, hangs, or memory errors.
//
// Compile with any fuzzer (libFuzzer, AFL++) or as a standalone binary:
//   g++ -std=c++20 -I../include -fsanitize=address,fuzzer \
//       ../src/http2_parser.cpp fuzz_http2_parser.cpp \
//       -o fuzz_http2_parser /usr/lib/libcrypto.a -lpthread
//
// Standalone mode (reads file or stdin):
//   echo -n "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" | ./fuzz_http2_parser
//   ./fuzz_http2_parser /path/to/corpus.bin

#include "pntp/http2_parser.h"
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <vector>

static void testOneInput(const uint8_t* data, size_t size) {
    // Create a fresh parser for each input to isolate state
    Http2Parser parser;

    // Feed the bytes — should never crash (may return early on error)
    parser.feed(data, size);

    // Try a few API calls with the resulting state to ensure they're safe
    parser.activeStreamCount();
    parser.isConnected();
    parser.connectionWindow();

    // Serialize some common frames (verify these don't crash)
    std::map<uint16_t, uint32_t> settings = {
        {1, 4096}, {2, 0}, {4, 1048576}
    };
    parser.serializeSettings(settings);
    parser.serializeGoaway(0, H2_NO_ERROR);
    uint8_t ping_data[8] = {0};
    parser.serializePing(ping_data);
    parser.serializeWindowUpdate(0, 65535);
}

// ── libFuzzer / AFL++ entry point ──────────────────────────────────
#ifdef __LIBFUZZER__
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size) {
    testOneInput(Data, Size);
    return 0;
}
#else
// ── Standalone mode ────────────────────────────────────────────────
int main(int argc, char** argv) {
    std::vector<uint8_t> buf;

    if (argc >= 2) {
        // Read from file
        FILE* f = fopen(argv[1], "rb");
        if (!f) { perror("fopen"); return 1; }
        fseek(f, 0, SEEK_END);
        long sz = ftell(f);
        fseek(f, 0, SEEK_SET);
        if (sz > 0) {
            buf.resize(static_cast<size_t>(sz));
            fread(buf.data(), 1, buf.size(), f);
        }
        fclose(f);
        fprintf(stderr, "Fuzzing %s (%zu bytes)\n", argv[1], buf.size());
        testOneInput(buf.data(), buf.size());
    } else {
        // Read from stdin
        int c;
        while ((c = getchar()) != EOF)
            buf.push_back(static_cast<uint8_t>(c));
        if (!buf.empty())
            testOneInput(buf.data(), buf.size());
    }

    fprintf(stderr, "OK — no crashes\n");
    return 0;
}
#endif
