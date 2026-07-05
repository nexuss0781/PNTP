#include "pntp/pntp_core.h"
#include <gtest/gtest.h>
#include <cstring>
#include <vector>
#include <set>
#include <thread>
#include <algorithm>
#include <cmath>

constexpr int SAMPLE_COUNT = 1000;

class PNTPCoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        init_entropy_pool();
    }
    void TearDown() override {}
};

// ── get_rdtsc ──────────────────────────────────────────────────────

TEST_F(PNTPCoreTest, GetRDTSC_ReturnsIncreasingValues) {
    uint64_t prev = 0;
    for (int i = 0; i < SAMPLE_COUNT; ++i) {
        uint64_t cur = get_rdtsc();
        EXPECT_GT(cur, prev) << "RDTSC should be monotonic at sample " << i;
        prev = cur;
    }
}

TEST_F(PNTPCoreTest, GetRDTSC_NonZero) {
    uint64_t tsc = get_rdtsc();
    EXPECT_NE(tsc, 0) << "RDTSC should never return zero on real hardware";
}

// ── get_rdtsc_serialized ──────────────────────────────────────────

TEST_F(PNTPCoreTest, GetRDTSCSerialized_ReturnsIncreasingValues) {
    uint64_t prev = 0;
    for (int i = 0; i < SAMPLE_COUNT; ++i) {
        uint64_t cur = get_rdtsc_serialized();
        EXPECT_GT(cur, prev) << "Serialized RDTSC should be monotonic at sample " << i;
        prev = cur;
    }
}

TEST_F(PNTPCoreTest, GetRDTSCSerialized_GreaterOrEqual_GetRDTSC) {
    for (int i = 0; i < 100; ++i) {
        uint64_t raw = get_rdtsc();
        uint64_t ser = get_rdtsc_serialized();
        EXPECT_GE(ser, raw) << "Serialized RDTSC should be >= raw RDTSC (fences add cycles)";
    }
}

TEST_F(PNTPCoreTest, GetRDTSCSerialized_MonotonicUnderConcurrentAccess) {
    std::vector<uint64_t> vals[4];
    std::vector<std::thread> threads;
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&vals, t]() {
            for (int i = 0; i < 500; ++i)
                vals[t].push_back(get_rdtsc_serialized());
        });
    }
    for (auto& th : threads) th.join();
    for (int t = 0; t < 4; ++t) {
        for (size_t i = 1; i < vals[t].size(); ++i) {
            EXPECT_GT(vals[t][i], vals[t][i - 1])
                << "Thread " << t << ": serialized RDTSC not monotonic";
        }
    }
}

// ── get_rdtscp ─────────────────────────────────────────────────────

TEST_F(PNTPCoreTest, GetRDTSCP_ReturnsIncreasingValues) {
    uint64_t prev = 0;
    for (int i = 0; i < SAMPLE_COUNT; ++i) {
        uint32_t lo, hi, proc;
        get_rdtscp(&lo, &hi, &proc);
        uint64_t val = (static_cast<uint64_t>(hi) << 32) | lo;
        EXPECT_GT(val, prev) << "RDTSCP should be monotonic at sample " << i;
        prev = val;
        EXPECT_LE(proc, 255u) << "Processor ID should be reasonable";
    }
}

TEST_F(PNTPCoreTest, GetRDTSCP_NullPtrs_DoesNotCrash) {
    uint32_t lo, hi, proc;
    get_rdtscp(nullptr, nullptr, nullptr);
    get_rdtscp(&lo, nullptr, nullptr);
    get_rdtscp(nullptr, &hi, nullptr);
    get_rdtscp(nullptr, nullptr, &proc);
    get_rdtscp(&lo, &hi, &proc);
    SUCCEED();
}

// ── mfence_acquire / mfence_release ────────────────────────────────

TEST_F(PNTPCoreTest, MFence_DoesNotCrash) {
    mfence_acquire();
    mfence_release();
    SUCCEED();
}

TEST_F(PNTPCoreTest, MFence_OrderingVisible) {
    volatile int flag = 0;
    volatile int data = 0;
    int observed_data = 0;

    std::thread writer([&]() {
        data = 42;
        mfence_release();
        flag = 1;
    });

    std::thread reader([&]() {
        while (flag == 0) { pause_loop(10); }
        mfence_acquire();
        observed_data = data;
    });

    writer.join();
    reader.join();
    EXPECT_EQ(observed_data, 42) << "MFence should ensure ordered visibility";
}

// ── cache_flush_line ───────────────────────────────────────────────

TEST_F(PNTPCoreTest, CacheFlushLine_DoesNotCrash) {
    int dummy = 0xDEAD;
    cache_flush_line(&dummy);
    SUCCEED();
}

TEST_F(PNTPCoreTest, CacheFlushLine_OnArrayDoesNotCrash) {
    alignas(64) char buf[4096];
    std::memset(buf, 0xAB, sizeof(buf));
    for (size_t i = 0; i < sizeof(buf); i += 64)
        cache_flush_line(&buf[i]);
    EXPECT_EQ(buf[0], static_cast<char>(0xAB));
}

TEST_F(PNTPCoreTest, CacheFlushLine_NullPtr_DoesNotCrash) {
    cache_flush_line(nullptr);
    SUCCEED();
}

// ── avx2_copy_nt ───────────────────────────────────────────────────

TEST_F(PNTPCoreTest, AVX2CopyNT_CopiesCorrectly_Aligned) {
    alignas(32) char src[1024];
    alignas(32) char dst[1024] = {0};
    for (size_t i = 0; i < 1024; ++i) src[i] = static_cast<char>(i & 0xFF);
    avx2_copy_nt(dst, src, 1024);
    EXPECT_EQ(std::memcmp(src, dst, 1024), 0) << "AVX2 NT copy should match source";
}

TEST_F(PNTPCoreTest, AVX2CopyNT_ZeroLength) {
    alignas(32) char src[64] = {1};
    alignas(32) char dst[64] = {0};
    avx2_copy_nt(dst, src, 0);
    EXPECT_EQ(dst[0], 0) << "Zero-length copy should not modify destination";
}

TEST_F(PNTPCoreTest, AVX2CopyNT_PartialLastBlock) {
    alignas(32) char src[48];
    alignas(32) char dst[48] = {0};
    for (size_t i = 0; i < 48; ++i) src[i] = static_cast<char>(i + 1);
    avx2_copy_nt(dst, src, 48);
    EXPECT_EQ(std::memcmp(src, dst, 48), 0) << "Partial block copy should match";
}

// ── stealth_rand ───────────────────────────────────────────────────

TEST_F(PNTPCoreTest, StealthRand_ReturnsDifferentValues) {
    std::vector<uint64_t> samples(SAMPLE_COUNT);
    for (auto& s : samples) s = stealth_rand();
    size_t unique = std::set<uint64_t>(samples.begin(), samples.end()).size();
    EXPECT_GT(unique, SAMPLE_COUNT / 2) << "stealth_rand should produce diverse values";
}

TEST_F(PNTPCoreTest, StealthRand_NonZero) {
    uint64_t r = stealth_rand();
    EXPECT_NE(r, 0) << "stealth_rand should rarely return zero";
}

TEST_F(PNTPCoreTest, StealthRand_Distribution_BitEntropy) {
    int bit_counts[16] = {0};
    constexpr int ITERS = 10000;
    for (int i = 0; i < ITERS; ++i) {
        uint64_t r = stealth_rand();
        for (int b = 0; b < 16; ++b)
            if (r & (1ULL << b)) bit_counts[b]++;
    }
    for (int b = 0; b < 16; ++b) {
        double ratio = static_cast<double>(bit_counts[b]) / ITERS;
        EXPECT_GT(ratio, 0.1) << "Bit " << b << " set too rarely: " << ratio;
        EXPECT_LT(ratio, 0.9) << "Bit " << b << " set too often: " << ratio;
    }
}

// ── init_entropy_pool ──────────────────────────────────────────────

TEST_F(PNTPCoreTest, InitEntropyPool_LeavesNonZeroData) {
    extern char entropy_pool[PNTP_ENTROPY_POOL_SIZE];
    bool any_nonzero = false;
    for (int i = 0; i < PNTP_ENTROPY_POOL_SIZE; ++i) {
        if (entropy_pool[i] != 0) { any_nonzero = true; break; }
    }
    EXPECT_TRUE(any_nonzero) << "Entropy pool should be seeded with non-zero values";
}

// ── cpuid_string ───────────────────────────────────────────────────

TEST_F(PNTPCoreTest, CPUIDString_Leaf0_ReturnsVendorString) {
    char buf[16] = {0};
    cpuid_string(0, buf);
    bool non_zero = false;
    for (int i = 0; i < 16; ++i) if (buf[i] != 0) non_zero = true;
    EXPECT_TRUE(non_zero) << "CPUID leaf 0 should return vendor string";
}

TEST_F(PNTPCoreTest, CPUIDString_Leaf1_ReturnsNonZero) {
    char buf[16] = {0};
    cpuid_string(1, buf);
    bool non_zero = false;
    for (int i = 0; i < 16; ++i) if (buf[i] != 0) non_zero = true;
    EXPECT_TRUE(non_zero) << "CPUID leaf 1 should return feature bits";
}

TEST_F(PNTPCoreTest, CPUIDString_DifferentLeaves_Differ) {
    char buf1[16] = {0}, buf2[16] = {0};
    cpuid_string(0, buf1);
    cpuid_string(1, buf2);
    EXPECT_NE(std::memcmp(buf1, buf2, 16), 0) << "Different CPUID leaves should differ";
}

// ── pause_loop ─────────────────────────────────────────────────────

TEST_F(PNTPCoreTest, PauseLoop_ZeroCount_ReturnsImmediately) {
    pause_loop(0);
    SUCCEED();
}

TEST_F(PNTPCoreTest, PauseLoop_SmallCount_Completes) {
    pause_loop(100);
    SUCCEED();
}

TEST_F(PNTPCoreTest, PauseLoop_LargeCount_Completes) {
    pause_loop(1000000);
    SUCCEED();
}

// ── prefetch_range ─────────────────────────────────────────────────

TEST_F(PNTPCoreTest, PrefetchRange_DoesNotCrash) {
    alignas(64) char buf[4096];
    std::memset(buf, 0xFF, sizeof(buf));
    prefetch_range(buf, sizeof(buf));
    EXPECT_EQ(buf[0], static_cast<char>(0xFF));
}

TEST_F(PNTPCoreTest, PrefetchRange_ZeroLength) {
    alignas(64) char buf[64];
    prefetch_range(buf, 0);
    SUCCEED();
}

TEST_F(PNTPCoreTest, PrefetchRange_LargeBuffer) {
    std::vector<char> buf(1024 * 1024, 0x42);
    prefetch_range(buf.data(), buf.size());
    EXPECT_EQ(buf[0], 0x42);
}

TEST_F(PNTPCoreTest, PrefetchRange_NullPtr_DoesNotCrash) {
    prefetch_range(nullptr, 0);
    SUCCEED();
}

// ── generate_stealth_id (existing, regression) ─────────────────────

TEST_F(PNTPCoreTest, GenerateStealthId_ProducesNonZeroBuffer) {
    char sid[16];
    std::memset(sid, 0, 16);
    generate_stealth_id(sid);
    bool all_zero = true;
    for (int i = 0; i < 16; ++i) {
        if (sid[i] != 0) { all_zero = false; break; }
    }
    EXPECT_FALSE(all_zero);
}

TEST_F(PNTPCoreTest, GenerateStealthId_CPUIDPartIsStable) {
    char sid1[16], sid2[16];
    generate_stealth_id(sid1);
    generate_stealth_id(sid2);
    bool cpuid_stable = true;
    for (int i = 8; i < 16; ++i)
        if (sid1[i] != sid2[i]) { cpuid_stable = false; break; }
    EXPECT_TRUE(cpuid_stable);
}

TEST_F(PNTPCoreTest, GenerateStealthId_WritesSixteenBytes) {
    char sid[16] = {0};
    generate_stealth_id(sid);
    bool any_nonzero = false;
    for (int i = 8; i < 16; ++i)
        if (sid[i] != 0) { any_nonzero = true; break; }
    EXPECT_TRUE(any_nonzero);
}

// ── Cross-function validation ──────────────────────────────────────

TEST_F(PNTPCoreTest, CrossCheck_AllTimingFunctions_Monotonic) {
    uint64_t t1 = get_rdtsc();
    uint64_t t2 = get_rdtsc_serialized();
    uint32_t lo, hi, proc;
    get_rdtscp(&lo, &hi, &proc);
    uint64_t t3 = (static_cast<uint64_t>(hi) << 32) | lo;
    EXPECT_LE(t1, t2) << "Unserialized RDTSC should be <= serialized";
    EXPECT_LE(t2, t3) << "Serialized RDTSC should be <= RDTSCP";
}

TEST_F(PNTPCoreTest, CrossCheck_RDTSC_ElapsedTimeReasonable) {
    uint64_t start = get_rdtsc_serialized();
    pause_loop(100000);
    uint64_t end = get_rdtsc_serialized();
    uint64_t elapsed = end - start;
    EXPECT_GT(elapsed, 0ULL) << "Elapsed TSC cycles should be positive";
    EXPECT_LT(elapsed, 1000000000ULL) << "100K PAUSE loops should not take 1B cycles";
}

TEST_F(PNTPCoreTest, CrossCheck_StealthRand_AfterEntropyInit) {
    init_entropy_pool();
    uint64_t r1 = stealth_rand();
    uint64_t r2 = stealth_rand();
    EXPECT_NE(r1, 0);
    EXPECT_NE(r2, 0);
    EXPECT_NE(r1, r2) << "Consecutive stealth_rand calls should differ";
}

TEST_F(PNTPCoreTest, CrossCheck_CPUID_Consistency) {
    char buf0[16], buf1[16];
    cpuid_string(0, buf0);
    cpuid_string(0, buf1);
    EXPECT_EQ(std::memcmp(buf0, buf1, 16), 0) << "Same CPUID leaf must be identical";
}

TEST_F(PNTPCoreTest, CrossCheck_AVX2Copy_Then_Prefetch) {
    alignas(32) char src[256], dst[256];
    for (size_t i = 0; i < 256; ++i) src[i] = static_cast<char>(i);
    std::memset(dst, 0, 256);
    avx2_copy_nt(dst, src, 256);
    prefetch_range(dst, 256);
    EXPECT_EQ(std::memcmp(src, dst, 256), 0);
}

TEST_F(PNTPCoreTest, CrossCheck_FlushThenRead_NoFault) {
    alignas(64) int val = 0xCAFE;
    cache_flush_line(&val);
    volatile int read = val;
    EXPECT_EQ(read, 0xCAFE);
}
