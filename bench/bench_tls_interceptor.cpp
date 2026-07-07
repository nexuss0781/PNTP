#include "pntp/tls_interceptor.h"
#include <benchmark/benchmark.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>
#include <cstring>
#include <thread>

// ── X25519 Key Exchange ─────────────────────────────────────────────

static void BM_X25519KeyExchange(benchmark::State& state) {
    uint8_t base[32];
    base[0] = 9;
    memset(base + 1, 0, 31);
    uint8_t priv_a[32], priv_b[32], pub_a[32], pub_b[32], shared[32];

    for (auto _ : state) {
        RAND_bytes(priv_a, 32);
        RAND_bytes(priv_b, 32);
        X25519(pub_a, priv_a, base);
        X25519(pub_b, priv_b, base);
        X25519(shared, priv_a, pub_b);
        benchmark::DoNotOptimize(shared);
    }
}
BENCHMARK(BM_X25519KeyExchange);

// ── AES-128-GCM Encrypt ─────────────────────────────────────────────

static void BM_AES128GCMEncrypt(benchmark::State& state) {
    uint8_t key[16], iv[12];
    RAND_bytes(key, 16);
    RAND_bytes(iv, 12);

    int pt_len = state.range(0);
    std::vector<uint8_t> pt(pt_len);
    RAND_bytes(pt.data(), pt_len);

    EVP_AEAD* aead = EVP_AEAD_fetch(nullptr, "AES-128-GCM", nullptr);
    EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, key, 16, 0);

    std::vector<uint8_t> ct(pt_len + 16);
    size_t ct_len;
    uint8_t tag[16];

    for (auto _ : state) {
        EVP_AEAD_CTX_seal(ctx, ct.data(), &ct_len, ct.size(),
                          iv, 12, pt.data(), pt_len, nullptr, 0, nullptr, 0);
        benchmark::DoNotOptimize(ct.data());
    }

    EVP_AEAD_CTX_free(ctx);
    EVP_AEAD_free(aead);
}
BENCHMARK(BM_AES128GCMEncrypt)->Arg(256)->Arg(1500)->Arg(16384);

// ── AES-128-GCM Decrypt ─────────────────────────────────────────────

static void BM_AES128GCMDecrypt(benchmark::State& state) {
    uint8_t key[16], iv[12];
    RAND_bytes(key, 16);
    RAND_bytes(iv, 12);

    int pt_len = state.range(0);
    std::vector<uint8_t> pt(pt_len);
    RAND_bytes(pt.data(), pt_len);

    EVP_AEAD* aead = EVP_AEAD_fetch(nullptr, "AES-128-GCM", nullptr);
    EVP_AEAD_CTX* ctx = EVP_AEAD_CTX_new(aead, key, 16, 0);

    std::vector<uint8_t> ct(pt_len + 16);
    size_t ct_len;
    EVP_AEAD_CTX_seal(ctx, ct.data(), &ct_len, ct.size(),
                      iv, 12, pt.data(), pt_len, nullptr, 0, nullptr, 0);

    std::vector<uint8_t> out(pt_len);
    size_t out_len;

    for (auto _ : state) {
        EVP_AEAD_CTX_open(ctx, out.data(), &out_len, out.size(),
                          iv, 12, ct.data(), ct_len, nullptr, 0, nullptr, 0);
        benchmark::DoNotOptimize(out.data());
    }

    EVP_AEAD_CTX_free(ctx);
    EVP_AEAD_free(aead);
}
BENCHMARK(BM_AES128GCMDecrypt)->Arg(256)->Arg(1500)->Arg(16384);

// ── HKDF-Extract (SHA-256) ──────────────────────────────────────────

static void BM_HKDFExtract(benchmark::State& state) {
    uint8_t salt_buf[32], ikm_buf[32];
    RAND_bytes(salt_buf, 32);
    RAND_bytes(ikm_buf, 32);
    std::vector<uint8_t> salt(salt_buf, salt_buf + 32);
    std::vector<uint8_t> ikm(ikm_buf, ikm_buf + 32);

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5];
    std::vector<uint8_t> prk(32);

    for (auto _ : state) {
        int n = 0;
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_MODE, const_cast<char*>("EXTRACT_ONLY"), 0);
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, ikm.data(), ikm.size());
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_SALT, salt.data(), salt.size());
        params[n] = OSSL_PARAM_construct_end();

        EVP_KDF_derive(kctx, prk.data(), 32, params);
        benchmark::DoNotOptimize(prk.data());
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
}
BENCHMARK(BM_HKDFExtract);

// ── HKDF-Expand (SHA-256) ───────────────────────────────────────────

static void BM_HKDFExpand(benchmark::State& state) {
    uint8_t prk_buf[32], info_buf[32];
    RAND_bytes(prk_buf, 32);
    RAND_bytes(info_buf, 32);
    std::vector<uint8_t> prk(prk_buf, prk_buf + 32);
    std::vector<uint8_t> info(info_buf, info_buf + 32);

    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "HKDF", nullptr);
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[5];
    std::vector<uint8_t> out(32);
    size_t L = state.range(0);

    for (auto _ : state) {
        int n = 0;
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_DIGEST, const_cast<char*>("SHA256"), 0);
        params[n++] = OSSL_PARAM_construct_utf8_string(
            OSSL_KDF_PARAM_MODE, const_cast<char*>("EXPAND_ONLY"), 0);
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_KEY, prk.data(), prk.size());
        params[n++] = OSSL_PARAM_construct_octet_string(
            OSSL_KDF_PARAM_INFO, info.data(), info.size());
        params[n] = OSSL_PARAM_construct_end();

        std::vector<uint8_t> buf(L);
        EVP_KDF_derive(kctx, buf.data(), L, params);
        benchmark::DoNotOptimize(buf.data());
    }

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
}
BENCHMARK(BM_HKDFExpand)->Arg(32)->Arg(64);

// ── Certificate Generation ──────────────────────────────────────────

static void BM_CertGeneration(benchmark::State& state) {
    // generateCA only needs to run once
    TLSInterceptor interceptor;
    interceptor.initialize();

    for (auto _ : state) {
        auto* cert = interceptor.getOrCreateCert("benchmark.example.com");
        benchmark::DoNotOptimize(cert);
    }
}
// Only run 10 iterations since cert generation is expensive
BENCHMARK(BM_CertGeneration)->Iterations(10);

// ── Record Layer ─────────────────────────────────────────────────────
// Simulate serialize + parse of a handshake record

static void BM_RecordLayer(benchmark::State& state) {
    std::vector<uint8_t> body(state.range(0));
    RAND_bytes(body.data(), body.size());
    std::vector<uint8_t> record;
    record.reserve(5 + body.size());

    // Build a TLS record (type 22 = handshake, version 0x0303)
    for (auto _ : state) {
        record.clear();
        record.push_back(22);
        record.push_back(0x03);
        record.push_back(0x03);
        record.push_back(static_cast<uint8_t>((body.size() >> 8) & 0xFF));
        record.push_back(static_cast<uint8_t>(body.size() & 0xFF));
        record.insert(record.end(), body.begin(), body.end());
        benchmark::DoNotOptimize(record.data());

        // Parse back
        uint8_t type = record[0];
        uint16_t version = (static_cast<uint16_t>(record[1]) << 8) | record[2];
        uint16_t len = (static_cast<uint16_t>(record[3]) << 8) | record[4];
        benchmark::DoNotOptimize(type);
        benchmark::DoNotOptimize(version);
        benchmark::DoNotOptimize(len);
    }
}
BENCHMARK(BM_RecordLayer)->Arg(64)->Arg(1500)->Arg(65535);

BENCHMARK_MAIN();
