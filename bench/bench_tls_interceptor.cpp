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
    for (auto _ : state) {
        EVP_PKEY_CTX* actx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY* a = nullptr;
        EVP_PKEY_keygen_init(actx);
        EVP_PKEY_keygen(actx, &a);
        EVP_PKEY_CTX_free(actx);
        EVP_PKEY_CTX* bctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
        EVP_PKEY* b = nullptr;
        EVP_PKEY_keygen_init(bctx);
        EVP_PKEY_keygen(bctx, &b);
        EVP_PKEY_CTX_free(bctx);
        EVP_PKEY_CTX* derive = EVP_PKEY_CTX_new(a, nullptr);
        EVP_PKEY_derive_init(derive);
        EVP_PKEY_derive_set_peer(derive, b);
        size_t slen = 32;
        uint8_t shared[32];
        EVP_PKEY_derive(derive, shared, &slen);
        benchmark::DoNotOptimize(shared);
        EVP_PKEY_CTX_free(derive);
        EVP_PKEY_free(a);
        EVP_PKEY_free(b);
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

    std::vector<uint8_t> ct(pt_len + 32);

    for (auto _ : state) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, iv);
        int out_len = 0;
        EVP_EncryptUpdate(ctx, ct.data(), &out_len, pt.data(), pt_len);
        int tmp = 0;
        EVP_EncryptFinal_ex(ctx, ct.data() + out_len, &tmp);
        out_len += tmp;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ct.data() + out_len);
        benchmark::DoNotOptimize(ct.data());
        EVP_CIPHER_CTX_free(ctx);
    }
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

    std::vector<uint8_t> ct(pt_len + 32);
    int ct_len = 0;
    {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, iv);
        EVP_EncryptUpdate(ctx, ct.data(), &ct_len, pt.data(), pt_len);
        int tmp = 0;
        EVP_EncryptFinal_ex(ctx, ct.data() + ct_len, &tmp);
        ct_len += tmp;
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ct.data() + ct_len);
        ct_len += 16;
        EVP_CIPHER_CTX_free(ctx);
    }

    std::vector<uint8_t> out(pt_len);

    for (auto _ : state) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, key, iv);
        int out_len = 0;
        EVP_DecryptUpdate(ctx, out.data(), &out_len, ct.data(), ct_len - 16);
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, ct.data() + ct_len - 16);
        int tmp = 0;
        EVP_DecryptFinal_ex(ctx, out.data() + out_len, &tmp);
        benchmark::DoNotOptimize(out.data());
        EVP_CIPHER_CTX_free(ctx);
    }
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

// BENCHMARK_MAIN removed - defined in bench_pntp_core.cpp
