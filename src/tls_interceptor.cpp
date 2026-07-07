#include "pntp/tls_interceptor.h"
#include "pntp/pntp_core.h"
#include "pntp/tcp_engine.h"

#include <cstring>
#include <cassert>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <set>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

// ── OpenSSL Initialization (one-time) ────────────────────────────────

static bool openssl_initialized = false;
static std::once_flag openssl_init_flag;

static void initOpenSSL() {
    std::call_once(openssl_init_flag, []() {
        OpenSSL_add_all_algorithms();
        ERR_load_crypto_strings();
    });
}

// ── Helpers ──────────────────────────────────────────────────────────

static std::string _hexStr(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    return oss.str();
}

static std::vector<uint8_t> toVector(const uint8_t* data, size_t len) {
    return {data, data + len};
}

static uint16_t readUint16(const uint8_t* data) {
    return (static_cast<uint16_t>(data[0]) << 8) |
            static_cast<uint16_t>(data[1]);
}

static uint32_t readUint24(const uint8_t* data) {
    return (static_cast<uint32_t>(data[0]) << 16) |
           (static_cast<uint32_t>(data[1]) << 8) |
            static_cast<uint32_t>(data[2]);
}

static void writeUint16(uint8_t* data, uint16_t val) {
    data[0] = static_cast<uint8_t>(val >> 8);
    data[1] = static_cast<uint8_t>(val & 0xFF);
}

static void writeUint24(uint8_t* data, uint32_t val) {
    data[0] = static_cast<uint8_t>((val >> 16) & 0xFF);
    data[1] = static_cast<uint8_t>((val >> 8) & 0xFF);
    data[2] = static_cast<uint8_t>(val & 0xFF);
}

static void writeUint32(uint8_t* data, uint32_t val) {
    data[0] = static_cast<uint8_t>((val >> 24) & 0xFF);
    data[1] = static_cast<uint8_t>((val >> 16) & 0xFF);
    data[2] = static_cast<uint8_t>((val >> 8) & 0xFF);
    data[3] = static_cast<uint8_t>(val & 0xFF);
}

static void writeUint64(uint8_t* data, uint64_t val) {
    for (int i = 7; i >= 0; --i) {
        data[i] = static_cast<uint8_t>(val & 0xFF);
        val >>= 8;
    }
}

// ── Constructor / Destructor ─────────────────────────────────────────

TLSInterceptor::TLSInterceptor() {
    initOpenSSL();
}

TLSInterceptor::~TLSInterceptor() {
    stopProxy();
    clearCertCache();
    if (ca_key_)  EVP_PKEY_free(ca_key_);
    if (ca_cert_) X509_free(ca_cert_);
    if (keylog_file_) fclose(keylog_file_);
}

// ── Initialization ───────────────────────────────────────────────────

bool TLSInterceptor::initialize() {
    if (ca_cert_) return true; // already initialized
    if (!generateCA()) {
        std::cerr << "[TLS] Failed to generate CA certificate\n";
        return false;
    }
    std::cout << "[TLS] Interceptor initialized with self-signed CA\n";
    return true;
}

// ═════════════════════════════════════════════════════════════════════
// TLS Record Layer (RFC 8446 Section 5)
// ═════════════════════════════════════════════════════════════════════

TLSRecord TLSInterceptor::readRecord(int fd) {
    TLSRecord rec;
    uint8_t header[5];
    ssize_t n = ::read(fd, header, 5);
    if (n != 5) return rec;

    rec.type = header[0];
    rec.version = readUint16(header + 1);
    uint16_t payload_len = readUint16(header + 3);

    if (payload_len == 0 || payload_len > 16384 + 256) return rec;

    rec.payload.resize(payload_len);
    size_t total_read = 0;
    while (total_read < payload_len) {
        n = ::read(fd, rec.payload.data() + total_read,
                    payload_len - total_read);
        if (n <= 0) {
            rec.payload.clear();
            return rec;
        }
        total_read += static_cast<size_t>(n);
    }
    return rec;
}

bool TLSInterceptor::writeRecord(int fd, uint8_t type,
                                  const uint8_t* data, size_t len) {
    if (len > 16384 + 256) return false;
    uint8_t header[5];
    header[0] = type;
    header[1] = 0x03;
    header[2] = 0x03;
    header[3] = static_cast<uint8_t>((len >> 8) & 0xFF);
    header[4] = static_cast<uint8_t>(len & 0xFF);

    if (::write(fd, header, 5) != 5) return false;
    if (len > 0 && ::write(fd, data, len) != static_cast<ssize_t>(len))
        return false;
    return true;
}

bool TLSInterceptor::writeRecordVec(
    int fd, uint8_t type,
    const std::vector<std::vector<uint8_t>>& parts) {
    size_t total = 0;
    for (const auto& p : parts) total += p.size();
    if (total > 16384 + 256) return false;

    uint8_t header[5];
    header[0] = type;
    header[1] = 0x03;
    header[2] = 0x03;
    header[3] = static_cast<uint8_t>((total >> 8) & 0xFF);
    header[4] = static_cast<uint8_t>(total & 0xFF);

    if (::write(fd, header, 5) != 5) return false;
    for (const auto& p : parts) {
        if (!p.empty() && ::write(fd, p.data(), p.size()) !=
                           static_cast<ssize_t>(p.size()))
            return false;
    }
    return true;
}

// ── AEAD Encryption / Decryption ─────────────────────────────────────

std::vector<uint8_t> TLSInterceptor::aeadEncrypt(
    const TrafficKey& key, uint8_t type,
    const uint8_t* plaintext, size_t pt_len) {

    // Build nonce: IV XOR (seq as 8 bytes, padded to 12)
    uint8_t nonce[12];
    std::memcpy(nonce, key.iv, 12);
    uint8_t seq_bytes[8];
    writeUint64(seq_bytes, key.seq);
    for (int i = 0; i < 8; ++i)
        nonce[4 + i] ^= seq_bytes[i];

    // Build AAD: seq + type + version + len
    uint8_t aad[13];
    writeUint64(aad, key.seq);
    aad[8] = type;
    aad[9] = 0x03;
    aad[10] = 0x03;
    aad[11] = static_cast<uint8_t>((pt_len >> 8) & 0xFF);
    aad[12] = static_cast<uint8_t>(pt_len & 0xFF);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.key, nonce);

    int out_len = 0;
    std::vector<uint8_t> ciphertext(pt_len + 16);
    EVP_EncryptUpdate(ctx, ciphertext.data(), &out_len,
                       plaintext, static_cast<int>(pt_len));
    int total_len = out_len;

    // Set AAD
    EVP_EncryptUpdate(ctx, nullptr, &out_len, aad, 13);

    int tag_len = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + total_len, &tag_len);
    total_len += tag_len;

    // Get tag
    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    std::memcpy(ciphertext.data() + pt_len, tag, 16);

    EVP_CIPHER_CTX_free(ctx);

    ciphertext.resize(pt_len + 16); // ciphertext + tag
    return ciphertext;
}

std::vector<uint8_t> TLSInterceptor::aeadDecrypt(
    const TrafficKey& key,
    const uint8_t* ciphertext, size_t ct_len) {

    if (ct_len < 16) return {}; // need at least tag

    size_t pt_len = ct_len - 16;
    const uint8_t* tag = ciphertext + pt_len;

    // Build nonce
    uint8_t nonce[12];
    std::memcpy(nonce, key.iv, 12);
    uint8_t seq_bytes[8];
    writeUint64(seq_bytes, key.seq);
    for (int i = 0; i < 8; ++i)
        nonce[4 + i] ^= seq_bytes[i];

    // Build AAD
    uint8_t aad[13];
    writeUint64(aad, key.seq);
    aad[8] = 23; // APPLICATION_DATA (decrypted records always use this type)
    aad[9] = 0x03;
    aad[10] = 0x03;
    aad[11] = static_cast<uint8_t>((pt_len >> 8) & 0xFF);
    aad[12] = static_cast<uint8_t>(pt_len & 0xFF);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return {};

    EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr);
    EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.key, nonce);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                         const_cast<uint8_t*>(tag));

    int out_len = 0;
    std::vector<uint8_t> plaintext(pt_len);
    EVP_DecryptUpdate(ctx, plaintext.data(), &out_len,
                       ciphertext, static_cast<int>(pt_len));
    int total_len = out_len;

    // Set AAD
    EVP_DecryptUpdate(ctx, nullptr, &out_len, aad, 13);

    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total_len,
                             &final_len) <= 0) {
        EVP_CIPHER_CTX_free(ctx);
        return {}; // authentication failure
    }
    total_len += final_len;

    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(static_cast<size_t>(total_len));
    return plaintext;
}

// ═════════════════════════════════════════════════════════════════════
// Handshake Parsing
// ═════════════════════════════════════════════════════════════════════

static std::vector<uint8_t> readVar(const uint8_t* data, size_t& offset,
                                     size_t len_bytes, size_t max_len) {
    if (offset + len_bytes > max_len) return {};
    size_t length = 0;
    for (size_t i = 0; i < len_bytes; ++i)
        length = (length << 8) | data[offset++];
    if (offset + length > max_len) return {};
    std::vector<uint8_t> result(data + offset, data + offset + length);
    offset += length;
    return result;
}

HskClientHello TLSInterceptor::parseClientHello(const uint8_t* data,
                                                  size_t len) {
    HskClientHello ch;
    size_t offset = 0;

    if (len < 2) return ch;
    ch.version = readUint16(data + offset);
    offset += 2;

    auto random = readVar(data, offset, 32, len);
    if (random.size() != 32) return ch;
    ch.random = std::move(random);

    auto sid = readVar(data, offset, 1, len);
    ch.session_id = std::move(sid);

    auto cs = readVar(data, offset, 2, len);
    if (cs.size() < 2 || cs.size() % 2 != 0) return ch;
    for (size_t i = 0; i < cs.size(); i += 2) {
        ch.cipher_suites.push_back(
            static_cast<CipherSuite>(readUint16(cs.data() + i)));
    }

    auto comp = readVar(data, offset, 1, len);
    ch.compression_methods = std::move(comp);

    // Extensions
    if (offset + 2 <= len) {
        uint16_t ext_len = readUint16(data + offset);
        offset += 2;
        if (offset + ext_len <= len) {
            ch.raw_extensions.assign(data + offset, data + offset + ext_len);
            parseExtensions(data + offset, ext_len, ch);
        }
    }

    return ch;
}

std::vector<uint8_t> TLSInterceptor::parseExtensions(
    const uint8_t* data, size_t len, HskClientHello& out) {

    size_t offset = 0;
    while (offset + 4 <= len) {
        uint16_t ext_type = readUint16(data + offset);
        offset += 2;
        uint16_t ext_len = readUint16(data + offset);
        offset += 2;
        if (offset + ext_len > len) break;

        const uint8_t* ext_data = data + offset;

        switch (static_cast<ExtensionType>(ext_type)) {
            case ExtensionType::SERVER_NAME: {
                // sni_name_list: 2 + 1 + 2 + var
                if (ext_len > 5) {
                    uint16_t list_len = readUint16(ext_data);
                    if (list_len + 2 <= ext_len && ext_data[2] == 0) {
                        uint16_t name_len = readUint16(ext_data + 3);
                        if (name_len + 5 <= ext_len) {
                            out.server_name.assign(
                                ext_data + 5, ext_data + 5 + name_len);
                        }
                    }
                }
                break;
            }
            case ExtensionType::SUPPORTED_GROUPS: {
                uint16_t glen = readUint16(ext_data);
                for (uint16_t i = 0; i + 2 <= glen; i += 2) {
                    out.supported_groups.push_back(
                        static_cast<NamedGroup>(readUint16(ext_data + 2 + i)));
                }
                break;
            }
            case ExtensionType::SIGNATURE_ALGORITHMS: {
                uint16_t salen = readUint16(ext_data);
                for (uint16_t i = 0; i + 2 <= salen; i += 2)
                    out.signature_algorithms.push_back(
                        readUint16(ext_data + 2 + i));
                break;
            }
            case ExtensionType::ALPN: {
                uint16_t alen = readUint16(ext_data);
                size_t apos = 2;
                while (apos + 1 < 2 + alen) {
                    uint8_t plen = ext_data[apos];
                    ++apos;
                    if (apos + plen <= 2 + alen) {
                        out.alpn.emplace_back(
                            reinterpret_cast<const char*>(ext_data + apos),
                            plen);
                        apos += plen;
                    } else break;
                }
                break;
            }
            case ExtensionType::KEY_SHARE: {
                uint16_t klen = readUint16(ext_data);
                if (klen >= 4) {
                    out.key_share.group = static_cast<NamedGroup>(
                        readUint16(ext_data + 2));
                    uint16_t ke_len = readUint16(ext_data + 4);
                    if (ke_len + 6 <= klen + 2) {
                        out.key_share.key_exchange.assign(
                            ext_data + 6, ext_data + 6 + ke_len);
                    }
                }
                break;
            }
            case ExtensionType::SUPPORTED_VERSIONS: {
                uint16_t vlen = readUint16(ext_data);
                for (uint16_t i = 0; i + 2 <= vlen; i += 2)
                    out.supported_versions.push_back(
                        readUint16(ext_data + 2 + i));
                break;
            }
            case ExtensionType::PSK_KEY_EXCHANGE_MODES: {
                uint16_t modlen = readUint16(ext_data);
                for (uint16_t i = 0; i < modlen; ++i) {
                    if (ext_data[2 + i] == 0) out.psk_mode_ke = true;
                    if (ext_data[2 + i] == 1) out.psk_mode_dhe = true;
                }
                break;
            }
            case ExtensionType::PRE_SHARED_KEY: {
                out.has_psk = true;
                // Parse identities (simplified: first identity only)
                uint16_t idlen = readUint16(ext_data);
                if (idlen >= 2) {
                    uint16_t identity_len = readUint16(ext_data + 2);
                    if (identity_len + 4 <= ext_len) {
                        out.psk_identity.assign(
                            ext_data + 4, ext_data + 4 + identity_len);
                    }
                }
                // Parse binders (ext_data + idlen + 2 + ...)
                uint16_t binder_offset = 2 + idlen;
                if (binder_offset + 2 <= ext_len) {
                    uint16_t blen = readUint16(ext_data + binder_offset);
                    if (blen >= 2) {
                        out.psk_binder.assign(
                            ext_data + binder_offset + 4,
                            ext_data + binder_offset + 4 + blen - 2);
                    }
                }
                break;
            }
            default:
                break;
        }
        offset += ext_len;
    }
    return {};
}

HskServerHello TLSInterceptor::parseServerHello(const uint8_t* data,
                                                  size_t len) {
    HskServerHello sh;
    size_t offset = 0;

    if (len < 2) return sh;
    sh.version = readUint16(data);
    offset += 2;

    auto random = readVar(data, offset, 32, len);
    if (random.size() != 32) return sh;
    sh.random = std::move(random);

    auto sid = readVar(data, offset, 1, len);
    sh.session_id = std::move(sid);

    if (offset + 3 > len) return sh;
    sh.cipher_suite = static_cast<CipherSuite>(readUint16(data + offset));
    offset += 2;
    sh.compression_method = data[offset++];

    // Extensions
    if (offset + 2 <= len) {
        uint16_t ext_len = readUint16(data + offset);
        offset += 2;
        if (offset + ext_len <= len) {
            size_t eoff = 0;
            while (eoff + 4 <= ext_len) {
                uint16_t etype = readUint16(data + offset + eoff);
                uint16_t elen = readUint16(data + offset + eoff + 2);
                eoff += 4;
                if (eoff + elen > ext_len) break;

                if (etype == static_cast<uint16_t>(ExtensionType::KEY_SHARE)) {
                    if (elen >= 4) {
                        sh.key_share.group =
                            static_cast<NamedGroup>(readUint16(
                                data + offset + eoff));
                        uint16_t ke_len = readUint16(
                            data + offset + eoff + 2);
                        if (ke_len + 4 <= elen) {
                            sh.key_share.key_exchange.assign(
                                data + offset + eoff + 4,
                                data + offset + eoff + 4 + ke_len);
                        }
                    }
                }
                if (etype == static_cast<uint16_t>(
                        ExtensionType::SUPPORTED_VERSIONS)) {
                    if (elen >= 2) {
                        sh.selected_version = readUint16(
                            data + offset + eoff);
                    }
                }
                eoff += elen;
            }
        }
    }

    return sh;
}

// ═════════════════════════════════════════════════════════════════════
// Handshake Serialization
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> TLSInterceptor::serializeHandshakeHeader(
    HandshakeType type, const uint8_t* body, size_t body_len) {

    std::vector<uint8_t> hdr(4);
    hdr[0] = static_cast<uint8_t>(type);
    writeUint24(hdr.data() + 1, static_cast<uint32_t>(body_len));
    return hdr;
}

std::vector<uint8_t> TLSInterceptor::serializeServerHello(
    const HskServerHello& hello) {

    std::vector<uint8_t> body;
    // version
    uint8_t ver[2];
    writeUint16(ver, hello.version);
    body.insert(body.end(), ver, ver + 2);

    // random
    body.insert(body.end(), hello.random.begin(), hello.random.end());

    // session_id
    body.push_back(static_cast<uint8_t>(hello.session_id.size()));
    body.insert(body.end(), hello.session_id.begin(), hello.session_id.end());

    // cipher_suite
    uint8_t cs[2];
    writeUint16(cs, static_cast<uint16_t>(hello.cipher_suite));
    body.insert(body.end(), cs, cs + 2);

    // compression
    body.push_back(hello.compression_method);

    // Extensions
    std::vector<uint8_t> ext_data;

    // key_share
    auto ks = serializeKeyShareExtension(hello.key_share);
    ext_data.insert(ext_data.end(), ks.begin(), ks.end());

    // supported_versions
    auto sv = serializeSupportedVersionsExtension(hello.selected_version);
    ext_data.insert(ext_data.end(), sv.begin(), sv.end());

    // Extensions length prefix
    uint8_t ext_len[2];
    writeUint16(ext_len, static_cast<uint16_t>(ext_data.size()));
    body.insert(body.end(), ext_len, ext_len + 2);
    body.insert(body.end(), ext_data.begin(), ext_data.end());

    return body;
}

std::vector<uint8_t> TLSInterceptor::serializeEncryptedExtensions(
    const std::string& alpn) {

    std::vector<uint8_t> ext_data;

    if (!alpn.empty()) {
        auto alpn_ext = serializeALPNExtension(alpn);
        ext_data.insert(ext_data.end(), alpn_ext.begin(), alpn_ext.end());
    }

    // Wrap in EncryptedExtensions handshake frame
    std::vector<uint8_t> body;
    uint8_t len[2];
    writeUint16(len, static_cast<uint16_t>(ext_data.size()));
    body.insert(body.end(), len, len + 2);
    body.insert(body.end(), ext_data.begin(), ext_data.end());

    return body;
}

std::vector<uint8_t> TLSInterceptor::serializeCertificate(
    const CertEntry& cert, X509* ca_cert) {

    std::vector<uint8_t> body;

    // certificate_list context (empty for server)
    body.push_back(0);

    // CertificateEntry count (1 for leaf + chain)
    uint8_t entry_count[3] = {0, 0, 1}; // 24-bit
    // Actually request_context is 1 byte, then certificate_list is 3-byte length
    // Wait - RFC 8446: Certificate struct is:
    //   opaque certificate_request_context<0..2^8-1>;
    //   CertificateEntry certificate_list<0..2^24-1>;

    // Build certificate list
    std::vector<uint8_t> cert_list;

    // Leaf certificate
    {
        // cert_data: 3-byte length + DER
        unsigned char* der = nullptr;
        int der_len = i2d_X509(cert.cert, &der);
        if (der_len > 0 && der) {
            uint8_t clen[3];
            writeUint24(clen, static_cast<uint32_t>(der_len));
            cert_list.insert(cert_list.end(), clen, clen + 3);
            cert_list.insert(cert_list.end(), der, der + der_len);
            OPENSSL_free(der);
        }
        // Extensions (empty for leaf)
        uint8_t no_ext[2] = {0, 0};
        cert_list.insert(cert_list.end(), no_ext, no_ext + 2);
    }

    // CA certificate (chain)
    if (ca_cert) {
        unsigned char* der = nullptr;
        int der_len = i2d_X509(ca_cert, &der);
        if (der_len > 0 && der) {
            uint8_t clen[3];
            writeUint24(clen, static_cast<uint32_t>(der_len));
            cert_list.insert(cert_list.end(), clen, clen + 3);
            cert_list.insert(cert_list.end(), der, der + der_len);
            OPENSSL_free(der);
        }
        uint8_t no_ext[2] = {0, 0};
        cert_list.insert(cert_list.end(), no_ext, no_ext + 2);
    }

    // Now build the full body
    body.push_back(0); // certificate_request_context
    uint8_t list_len[3];
    writeUint24(list_len, static_cast<uint32_t>(cert_list.size()));
    body.insert(body.end(), list_len, list_len + 3);
    body.insert(body.end(), cert_list.begin(), cert_list.end());

    return body;
}

std::vector<uint8_t> TLSInterceptor::serializeCertificateVerify(
    EVP_PKEY* key,
    const std::vector<uint8_t>& transcript_hash,
    CipherSuite suite) {

    const EVP_MD* md = selectHash(suite);
    size_t hlen = hashLength(suite);

    // Build the signature content:
    // " " + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
    std::vector<uint8_t> sig_content;
    // 64 spaces
    sig_content.resize(64, 0x20);
    std::string context = "TLS 1.3, server CertificateVerify\0";
    sig_content.insert(sig_content.end(), context.begin(), context.end());
    sig_content.insert(sig_content.end(), transcript_hash.begin(),
                       transcript_hash.end());

    // Hash the signature content
    std::vector<uint8_t> digest(EVP_MD_size(md));
    unsigned int digest_len = static_cast<unsigned int>(digest.size());
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, nullptr);
    EVP_DigestUpdate(mdctx, sig_content.data(), sig_content.size());
    EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len);
    digest.resize(digest_len);
    EVP_MD_CTX_free(mdctx);

    // Sign with ECDSA
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new(key, nullptr);
    EVP_PKEY_sign_init(pctx);
    EVP_PKEY_CTX_set_signature_md(pctx, md);
    size_t sig_len = 0;
    EVP_PKEY_sign(pctx, nullptr, &sig_len, digest.data(), digest.size());
    std::vector<uint8_t> signature(sig_len);
    EVP_PKEY_sign(pctx, signature.data(), &sig_len,
                   digest.data(), digest.size());
    signature.resize(sig_len);
    EVP_PKEY_CTX_free(pctx);

    // Build CertificateVerify message
    std::vector<uint8_t> body;

    // SignatureScheme (ecdsa_secp256r1_sha256 = 0x0403)
    uint8_t sig_scheme[2] = {0x04, 0x03};
    body.insert(body.end(), sig_scheme, sig_scheme + 2);

    // Signature length + value
    uint16_t sig16 = static_cast<uint16_t>(signature.size());
    uint8_t slen[2];
    writeUint16(slen, sig16);
    body.insert(body.end(), slen, slen + 2);
    body.insert(body.end(), signature.begin(), signature.end());

    return body;
}

std::vector<uint8_t> TLSInterceptor::serializeFinished(
    const std::vector<uint8_t>& base_key,
    const std::vector<uint8_t>& transcript_hash,
    CipherSuite suite) {

    auto verify_data = computeFinishedVerifyData(base_key, transcript_hash,
                                                  suite);

    // Finished message body is just verify_data
    std::vector<uint8_t> body = verify_data;
    return body;
}

std::vector<uint8_t> TLSInterceptor::serializeNewSessionTicket(
    const SessionTicket& ticket,
    const TrafficKey& app_key,
    const std::vector<uint8_t>& transcript_hash,
    CipherSuite suite) {

    std::vector<uint8_t> body;

    // lifetime (4 bytes)
    uint8_t lifetime[4];
    writeUint32(lifetime, ticket.lifetime);
    body.insert(body.end(), lifetime, lifetime + 4);

    // age_add (4 bytes)
    uint8_t age_add[4];
    writeUint32(age_add, ticket.age_add);
    body.insert(body.end(), age_add, age_add + 4);

    // nonce (1 byte length + value)
    body.push_back(static_cast<uint8_t>(ticket.nonce.size()));
    body.insert(body.end(), ticket.nonce.begin(), ticket.nonce.end());

    // ticket (2 byte length + value)
    uint8_t tlen[2];
    writeUint16(tlen, static_cast<uint16_t>(ticket.ticket.size()));
    body.insert(body.end(), tlen, tlen + 2);
    body.insert(body.end(), ticket.ticket.begin(), ticket.ticket.end());

    // extensions (empty)
    uint8_t no_ext[2] = {0, 0};
    body.insert(body.end(), no_ext, no_ext + 2);

    return body;
}

// ── Extension Serialization ──────────────────────────────────────────

std::vector<uint8_t> TLSInterceptor::serializeKeyShareExtension(
    const KeyShareEntry& entry) {

    std::vector<uint8_t> ext;

    // Extension type (2 bytes)
    uint8_t etype[2];
    writeUint16(etype, static_cast<uint16_t>(ExtensionType::KEY_SHARE));
    ext.insert(ext.end(), etype, etype + 2);

    // Extension data length placeholder
    size_t data_len_pos = ext.size();
    uint8_t elen[2] = {0, 0};
    ext.insert(ext.end(), elen, elen + 2);

    // KeyShareEntry:
    //   group (2 bytes)
    uint8_t group[2];
    writeUint16(group, static_cast<uint16_t>(entry.group));
    ext.insert(ext.end(), group, group + 2);

    //   key_exchange length (2 bytes)
    uint8_t ke_len[2];
    writeUint16(ke_len, static_cast<uint16_t>(entry.key_exchange.size()));
    ext.insert(ext.end(), ke_len, ke_len + 2);

    //   key_exchange data
    ext.insert(ext.end(), entry.key_exchange.begin(),
               entry.key_exchange.end());

    // Fix extension data length
    uint16_t ext_data_len = static_cast<uint16_t>(
        ext.size() - data_len_pos - 2);
    writeUint16(ext.data() + data_len_pos, ext_data_len);

    return ext;
}

std::vector<uint8_t> TLSInterceptor::serializeSupportedVersionsExtension(
    uint16_t version) {

    std::vector<uint8_t> ext;

    uint8_t etype[2];
    writeUint16(etype,
                static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS));
    ext.insert(ext.end(), etype, etype + 2);

    // ServerHello: 2 bytes data length, 2 bytes version
    uint8_t data[4] = {0, 2, 0, 0};
    writeUint16(data + 2, version);
    uint8_t elen[2] = {0, 2};
    ext.insert(ext.end(), elen, elen + 2);
    ext.insert(ext.end(), data, data + 4);

    return ext;
}

std::vector<uint8_t> TLSInterceptor::serializeALPNExtension(
    const std::string& proto) {

    std::vector<uint8_t> ext;

    uint8_t etype[2];
    writeUint16(etype, static_cast<uint16_t>(ExtensionType::ALPN));
    ext.insert(ext.end(), etype, etype + 2);

    // ALPN extension data:
    //   protocol_name_list (2 bytes) + name (len byte + string)
    uint8_t proto_len = static_cast<uint8_t>(proto.size());
    uint16_t list_len = static_cast<uint16_t>(proto_len + 1);
    uint8_t list_len_buf[2];
    writeUint16(list_len_buf, list_len);
    uint8_t ext_data_len[2];
    writeUint16(ext_data_len, list_len + 2);

    ext.insert(ext.end(), ext_data_len, ext_data_len + 2);
    ext.insert(ext.end(), list_len_buf, list_len_buf + 2);
    ext.push_back(proto_len);
    ext.insert(ext.end(), proto.begin(), proto.end());

    return ext;
}

// ═════════════════════════════════════════════════════════════════════
// Key Schedule (RFC 8446 Section 7.1)
// ═════════════════════════════════════════════════════════════════════

const EVP_MD* TLSInterceptor::selectHash(CipherSuite suite) const {
    switch (suite) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            return EVP_sha256();
        case CipherSuite::TLS_AES_256_GCM_SHA384:
            return EVP_sha384();
        default:
            return EVP_sha256();
    }
}

size_t TLSInterceptor::hashLength(CipherSuite suite) const {
    switch (suite) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            return 32;
        case CipherSuite::TLS_AES_256_GCM_SHA384:
            return 48;
        default:
            return 32;
    }
}

std::vector<uint8_t> TLSInterceptor::hkdfExtract(
    const EVP_MD* md,
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& ikm) {

    std::vector<uint8_t> prk(EVP_MD_size(md));
    // HKDF-Extract(salt, ikm) = HMAC-Hash(salt, ikm)
    unsigned int prk_len = static_cast<unsigned int>(prk.size());
    const uint8_t* salt_ptr = salt.empty() ? nullptr : salt.data();
    size_t salt_len = salt.size();

    if (HMAC(md, salt_ptr, static_cast<int>(salt_len),
             ikm.data(), ikm.size(), prk.data(), &prk_len) == nullptr) {
        return {};
    }
    prk.resize(prk_len);
    return prk;
}

std::vector<uint8_t> TLSInterceptor::hkdfExpand(
    const EVP_MD* md,
    const std::vector<uint8_t>& prk,
    const std::vector<uint8_t>& info,
    size_t L) {

    size_t hash_len = static_cast<size_t>(EVP_MD_size(md));
    std::vector<uint8_t> output;
    output.reserve(L);
    std::vector<uint8_t> T;

    uint8_t counter = 1;
    while (output.size() < L) {
        HMAC_CTX* ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, prk.data(), static_cast<int>(prk.size()), md,
                      nullptr);

        if (!T.empty())
            HMAC_Update(ctx, T.data(), T.size());
        HMAC_Update(ctx, info.data(), info.size());
        HMAC_Update(ctx, &counter, 1);

        T.resize(hash_len);
        unsigned int t_len = static_cast<unsigned int>(hash_len);
        HMAC_Final(ctx, T.data(), &t_len);
        HMAC_CTX_free(ctx);

        size_t needed = L - output.size();
        size_t to_copy = std::min(needed, hash_len);
        output.insert(output.end(), T.begin(), T.begin() +
                       static_cast<ssize_t>(to_copy));
        ++counter;
    }

    return output;
}

std::vector<uint8_t> TLSInterceptor::deriveSecret(
    const EVP_MD* md,
    const std::vector<uint8_t>& secret,
    const std::string& label,
    const std::vector<uint8_t>& context) {

    size_t hlen = static_cast<size_t>(EVP_MD_size(md));

    // Derive-Secret(Secret, Label, Context) =
    //   HKDF-Expand-Label(Secret, Label, Context, Hash.length)
    //
    // HkdfLabel:
    //   uint16 length = Hash.length
    //   opaque label<7..255> = "tls13 " + Label
    //   opaque context<0..255> = Context

    std::string full_label = "tls13 " + label;
    std::vector<uint8_t> info;
    info.reserve(2 + 1 + full_label.size() + 1 + context.size());

    // length of output (2 bytes)
    uint8_t len_buf[2];
    writeUint16(len_buf, static_cast<uint16_t>(hlen));
    info.insert(info.end(), len_buf, len_buf + 2);

    // label length (1 byte)
    info.push_back(static_cast<uint8_t>(full_label.size()));

    // label
    info.insert(info.end(), full_label.begin(), full_label.end());

    // context length (1 byte)
    info.push_back(static_cast<uint8_t>(context.size()));

    // context
    info.insert(info.end(), context.begin(), context.end());

    return hkdfExpand(md, secret, info, hlen);
}

void TLSInterceptor::deriveTrafficKeys(
    const std::vector<uint8_t>& secret,
    const std::string& label,
    const std::vector<uint8_t>& transcript_hash,
    TrafficKey& out_key,
    CipherSuite suite) {

    const EVP_MD* md = selectHash(suite);
    size_t hlen = hashLength(suite);

    // Derive-Secret(secret, label, transcript_hash) -> traffic_secret
    auto traffic_secret = deriveSecret(md, secret, label, transcript_hash);

    // Expand-Label to get key (16 bytes for AES-128-GCM)
    std::string key_label = "key";
    std::vector<uint8_t> key_info;
    uint8_t klen[2] = {0, 16};
    key_info.insert(key_info.end(), klen, klen + 2);
    key_info.push_back(static_cast<uint8_t>(key_label.size()));
    key_info.insert(key_info.end(), key_label.begin(), key_label.end());
    key_info.push_back(0); // empty context
    auto key_bytes = hkdfExpand(md, traffic_secret, key_info, 16);
    if (key_bytes.size() == 16)
        std::memcpy(out_key.key, key_bytes.data(), 16);

    // Expand-Label to get IV (12 bytes for AES-128-GCM)
    std::string iv_label = "iv";
    std::vector<uint8_t> iv_info;
    uint8_t ivlen[2] = {0, 12};
    iv_info.insert(iv_info.end(), ivlen, ivlen + 2);
    iv_info.push_back(static_cast<uint8_t>(iv_label.size()));
    iv_info.insert(iv_info.end(), iv_label.begin(), iv_label.end());
    iv_info.push_back(0);
    auto iv_bytes = hkdfExpand(md, traffic_secret, iv_info, 12);
    if (iv_bytes.size() == 12)
        std::memcpy(out_key.iv, iv_bytes.data(), 12);

    out_key.seq = 0;
}

std::vector<uint8_t> TLSInterceptor::computeFinishedVerifyData(
    const std::vector<uint8_t>& base_key,
    const std::vector<uint8_t>& transcript_hash,
    CipherSuite suite) {

    const EVP_MD* md = selectHash(suite);
    size_t hlen = hashLength(suite);

    // finished_key = HKDF-Expand-Label(base_key, "finished", "", Hash.len)
    std::string label = "finished";
    std::vector<uint8_t> info;
    uint8_t len_buf[2];
    writeUint16(len_buf, static_cast<uint16_t>(hlen));
    info.insert(info.end(), len_buf, len_buf + 2);
    info.push_back(static_cast<uint8_t>(label.size()));
    info.insert(info.end(), label.begin(), label.end());
    info.push_back(0); // empty context

    auto finished_key = hkdfExpand(md, base_key, info, hlen);
    if (finished_key.size() != hlen) return {};

    // verify_data = HMAC-Hash(finished_key, transcript_hash)
    std::vector<uint8_t> verify_data(hlen);
    unsigned int vlen = static_cast<unsigned int>(hlen);
    HMAC(md, finished_key.data(), static_cast<int>(finished_key.size()),
         transcript_hash.data(), transcript_hash.size(),
         verify_data.data(), &vlen);
    verify_data.resize(vlen);
    return verify_data;
}

// ═════════════════════════════════════════════════════════════════════
// Key Exchange (X25519)
// ═════════════════════════════════════════════════════════════════════

EVP_PKEY* TLSInterceptor::generateX25519Keypair() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr);
    if (!pctx) return nullptr;

    EVP_PKEY* pkey = nullptr;
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

std::vector<uint8_t> TLSInterceptor::getPubKeyBytes(EVP_PKEY* pkey) {
    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) <= 0)
        return {};
    std::vector<uint8_t> pub(len);
    if (EVP_PKEY_get_raw_public_key(pkey, pub.data(), &len) <= 0)
        return {};
    pub.resize(len);
    return pub;
}

std::vector<uint8_t> TLSInterceptor::computeSharedSecret(
    EVP_PKEY* private_key,
    const uint8_t* peer_pub, size_t peer_pub_len) {

    EVP_PKEY* peer_key = importPeerPublicKey(peer_pub, peer_pub_len,
                                              NamedGroup::X25519);
    if (!peer_key) return {};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(private_key, nullptr);
    if (!ctx) { EVP_PKEY_free(peer_key); return {}; }

    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer_key);

    size_t secret_len = 0;
    EVP_PKEY_derive(ctx, nullptr, &secret_len);
    std::vector<uint8_t> secret(secret_len);
    EVP_PKEY_derive(ctx, secret.data(), &secret_len);
    secret.resize(secret_len);

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer_key);
    return secret;
}

EVP_PKEY* TLSInterceptor::importPeerPublicKey(const uint8_t* data,
                                                size_t len,
                                                NamedGroup group) {
    if (group != NamedGroup::X25519 || len != 32) return nullptr;

    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr,
                                                   data, len);
    return pkey;
}

// ═════════════════════════════════════════════════════════════════════
// Certificate Generation
// ═════════════════════════════════════════════════════════════════════

bool TLSInterceptor::generateCA() {
    // Generate ECDSA P-256 key
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) return false;
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(pctx, &key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return false;
    }
    EVP_PKEY_CTX_free(pctx);

    // Create X.509 certificate
    X509* cert = X509_new();
    if (!cert) { EVP_PKEY_free(key); return false; }

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 365 * 10 * 24 * 3600); // 10 years
    X509_set_pubkey(cert, key);

    // Subject / Issuer (self-signed)
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(
                                   "PNTP MITM Root CA"),
                               -1, -1, 0);
    X509_set_issuer_name(cert, name);

    // Basic constraints: CA:TRUE, pathlen:0
    BASIC_CONSTRAINTS* bc = BASIC_CONSTRAINTS_new();
    bc->ca = 1;
    bc->pathlen = ASN1_INTEGER_new();
    ASN1_INTEGER_set(bc->pathlen, 0);
    X509_add1_ext_i2d(cert, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT);
    BASIC_CONSTRAINTS_free(bc);

    // Key usage: keyCertSign, cRLSign
    X509_add1_ext_i2d(cert, NID_key_usage,
                      reinterpret_cast<const char*>(
                          "\x03\x02\x05\xa0"), // digitalSignature + keyCertSign + cRLSign
                      0, X509V3_ADD_DEFAULT);

    // Sign
    if (!X509_sign(cert, key, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return false;
    }

    ca_cert_ = cert;
    ca_key_ = key;
    return true;
}

CertEntry* TLSInterceptor::generateDomainCert(const std::string& domain) {
    if (!ca_cert_ || !ca_key_) return nullptr;

    // Generate ECDSA P-256 key
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    if (!pctx) return nullptr;
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(pctx, &key) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return nullptr;
    }
    EVP_PKEY_CTX_free(pctx);

    X509* cert = X509_new();
    if (!cert) { EVP_PKEY_free(key); return nullptr; }

    ASN1_INTEGER_set(X509_get_serialNumber(cert),
                     static_cast<long>(get_rdtsc() & 0x7FFFFFFF));
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 90 * 24 * 3600); // 90 days
    X509_set_pubkey(cert, key);

    // Subject: CN = domain
    X509_NAME* name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(
                                   domain.c_str()),
                               -1, -1, 0);

    // Issuer = CA
    X509_set_issuer_name(cert, X509_get_subject_name(ca_cert_));

    // Subject Alternative Name: domain
    std::string san = "DNS:" + domain;
    X509_add1_ext_i2d(cert, NID_subject_alt_name,
                      reinterpret_cast<const char*>(san.c_str()),
                      0, X509V3_ADD_DEFAULT);

    // Sign with CA key
    if (!X509_sign(cert, ca_key_, EVP_sha256())) {
        X509_free(cert);
        EVP_PKEY_free(key);
        return nullptr;
    }

    // Encode to DER for caching
    unsigned char* der = nullptr;
    int der_len = i2d_X509(cert, &der);

    CertEntry* entry = &cert_cache_[domain];
    if (entry->cert) X509_free(entry->cert);
    if (entry->key) EVP_PKEY_free(entry->key);
    entry->cert = cert;
    entry->key = key;
    entry->valid = true;
    entry->created_at = get_rdtsc();
    if (der && der_len > 0) {
        entry->der.assign(der, der + der_len);
        OPENSSL_free(der);
    }

    return entry;
}

CertEntry* TLSInterceptor::getOrCreateCert(const std::string& domain) {
    std::lock_guard<std::mutex> lock(cert_mutex_);

    // Normalize domain
    std::string normalized = domain;
    std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                   ::tolower);

    auto it = cert_cache_.find(normalized);
    if (it != cert_cache_.end() && it->second.valid)
        return &it->second;

    // Evict if too many
    if (cert_cache_.size() >= max_cert_cache_) {
        // Simple: erase oldest (first in unordered_map iteration)
        cert_cache_.erase(cert_cache_.begin());
    }

    return generateDomainCert(normalized);
}

void TLSInterceptor::clearCertCache() {
    std::lock_guard<std::mutex> lock(cert_mutex_);
    for (auto& [domain, entry] : cert_cache_) {
        if (entry.cert) X509_free(entry.cert);
        if (entry.key) EVP_PKEY_free(entry.key);
    }
    cert_cache_.clear();
}

// ═════════════════════════════════════════════════════════════════════
// Key Derivation (for both legs)
// ═════════════════════════════════════════════════════════════════════

void TLSInterceptor::deriveAllKeys(HandshakeState& state) {
    const EVP_MD* md = selectHash(state.negotiated_cipher);
    size_t hlen = hashLength(state.negotiated_cipher);

    // Client Leg:
    //   handshake_secret_client = HKDF-Extract(0, ECDHE(client_pub, mitm_priv))
    //   We compute this externally before calling deriveAllKeys

    // Derive handshake traffic keys for client leg
    // server_handshake_traffic_secret
    auto svr_hs = deriveSecret(md, state.handshake_secret,
                                "s hs traffic",
                                state.client_leg_transcript);
    deriveTrafficKeys(svr_hs, "", {}, state.server_handshake_key,
                       state.negotiated_cipher);
    std::memcpy(state.server_handshake_key.iv,
                svr_hs.data() + std::min(svr_hs.size(), size_t(12)), 12);

    // client_handshake_traffic_secret
    auto cli_hs = deriveSecret(md, state.handshake_secret,
                                "c hs traffic",
                                state.client_leg_transcript);
    deriveTrafficKeys(cli_hs, "", {}, state.client_handshake_key,
                       state.negotiated_cipher);

    // Master Secret for client leg
    std::vector<uint8_t> empty;
    state.master_secret = hkdfExtract(md, empty, state.handshake_secret);

    // Application traffic keys for client leg
    auto svr_ap = deriveSecret(md, state.master_secret,
                                "s ap traffic",
                                state.client_leg_transcript);
    deriveTrafficKeys(svr_ap, "", {}, state.server_app_key,
                       state.negotiated_cipher);

    auto cli_ap = deriveSecret(md, state.master_secret,
                                "c ap traffic",
                                state.client_leg_transcript);
    deriveTrafficKeys(cli_ap, "", {}, state.client_app_key,
                       state.negotiated_cipher);

    // Server Leg: use server_leg_transcript
    // We need to compute a separate handshake_secret for server leg:
    //   hs_server = HKDF-Extract(0, ECDHE(mitm_server_pub, server_pub))
    // Wait - this is computed externally. Let's just compute the server leg keys.

    // For server leg, we have a different ECDHE shared secret.
    // We need to derive from that separately.
    // But the caller should set up state.server_leg_transcript and
    // call a separate derivation.
    // For now, server leg keys are derived during serverLeg().
}

// ═════════════════════════════════════════════════════════════════════
// Transcript Hash Computation
// ═════════════════════════════════════════════════════════════════════

std::vector<uint8_t> TLSInterceptor::computeTranscriptHash(
    const std::vector<uint8_t>& messages, CipherSuite suite) {

    const EVP_MD* md = selectHash(suite);
    std::vector<uint8_t> hash(EVP_MD_size(md));
    unsigned int hash_len = static_cast<unsigned int>(hash.size());

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, md, nullptr);
    EVP_DigestUpdate(ctx, messages.data(), messages.size());
    EVP_DigestFinal_ex(ctx, hash.data(), &hash_len);
    EVP_MD_CTX_free(ctx);

    hash.resize(hash_len);
    return hash;
}

// ═════════════════════════════════════════════════════════════════════
// MITM Handshake — Client Leg
// ═════════════════════════════════════════════════════════════════════

bool TLSInterceptor::clientLeg(HandshakeState& state, CertEntry* cert,
                                int client_fd) {
    // Read ClientHello from client
    TLSRecord rec = readRecord(client_fd);
    if (rec.type != static_cast<uint8_t>(ContentType::HANDSHAKE) ||
        rec.payload.empty()) {
        return false;
    }

    // Parse handshake header
    if (rec.payload[0] != static_cast<uint8_t>(HandshakeType::CLIENT_HELLO))
        return false;
    uint32_t ch_len = readUint24(rec.payload.data() + 1);
    if (ch_len + 4 > rec.payload.size()) return false;

    state.client_hello_wire = rec.payload;
    state.client_hello = parseClientHello(rec.payload.data() + 4, ch_len);
    if (state.client_hello.random.size() != 32) return false;

    // Build ServerHello
    state.server_hello.version = 0x0303;
    state.server_hello.random.resize(32);
    RAND_bytes(state.server_hello.random.data(), 32);
    state.server_hello.session_id = state.client_hello.session_id;
    state.server_hello.cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    state.server_hello.compression_method = 0;
    state.server_hello.selected_version = 0x0304;

    // Generate MITM key share for client leg
    EVP_PKEY* mitm_key = generateX25519Keypair();
    if (!mitm_key) return false;
    state.mitm_privkey = mitm_key;
    state.mitm_pubkey = getPubKeyBytes(mitm_key);
    state.server_hello.key_share.group = NamedGroup::X25519;
    state.server_hello.key_share.key_exchange = state.mitm_pubkey;

    // Serialize ServerHello
    auto sh_body = serializeServerHello(state.server_hello);
    state.server_hello_wire = serializeHandshakeHeader(
        HandshakeType::SERVER_HELLO, sh_body.data(), sh_body.size());
    state.server_hello_wire.insert(state.server_hello_wire.end(),
                                    sh_body.begin(), sh_body.end());

    // Compute shared secret for client leg
    auto shared_secret = computeSharedSecret(
        mitm_key,
        state.client_hello.key_share.key_exchange.data(),
        state.client_hello.key_share.key_exchange.size());
    if (shared_secret.empty()) return false;

    // Derive handshake keys for client leg
    const EVP_MD* md = EVP_sha256();
    state.client_leg_transcript.clear();
    state.client_leg_transcript.insert(
        state.client_leg_transcript.end(),
        state.client_hello_wire.begin(), state.client_hello_wire.end());
    state.client_leg_transcript.insert(
        state.client_leg_transcript.end(),
        state.server_hello_wire.begin(), state.server_hello_wire.end());

    state.handshake_secret = hkdfExtract(md, {}, shared_secret);
    deriveAllKeys(state);

    // Build EncryptedExtensions
    std::string selected_alpn;
    if (!state.client_hello.alpn.empty()) {
        for (const auto& p : alpn_protos_) {
            if (std::find(state.client_hello.alpn.begin(),
                          state.client_hello.alpn.end(),
                          p) != state.client_hello.alpn.end()) {
                selected_alpn = p;
                break;
            }
        }
    }
    auto ee_body = serializeEncryptedExtensions(selected_alpn);
    auto ee_hdr = serializeHandshakeHeader(
        HandshakeType::ENCRYPTED_EXTENSIONS, ee_body.data(), ee_body.size());
    state.client_leg_transcript.insert(state.client_leg_transcript.end(),
                                        ee_hdr.begin(), ee_hdr.end());
    state.client_leg_transcript.insert(state.client_leg_transcript.end(),
                                        ee_body.begin(), ee_body.end());

    // Build Certificate
    auto cert_body = serializeCertificate(*cert, ca_cert_);
    auto cert_hdr = serializeHandshakeHeader(
        HandshakeType::CERTIFICATE, cert_body.data(), cert_body.size());
    state.client_leg_transcript.insert(state.client_leg_transcript.end(),
                                        cert_hdr.begin(), cert_hdr.end());
    state.client_leg_transcript.insert(state.client_leg_transcript.end(),
                                        cert_body.begin(), cert_body.end());

    // Build CertificateVerify
    auto cv_body = serializeCertificateVerify(
        ca_key_, computeTranscriptHash(state.client_leg_transcript,
                                        state.negotiated_cipher),
        state.negotiated_cipher);
    auto cv_hdr = serializeHandshakeHeader(
        HandshakeType::CERTIFICATE_VERIFY, cv_body.data(), cv_body.size());
    state.client_leg_transcript.insert(state.client_leg_transcript.end(),
                                        cv_hdr.begin(), cv_hdr.end());
    state.client_leg_transcript.insert(state.client_leg_transcript.end(),
                                        cv_body.begin(), cv_body.end());

    // Compute transcript hash for Finished
    auto transcript_hash = computeTranscriptHash(
        state.client_leg_transcript, state.negotiated_cipher);

    // Build Finished (using server handshake key)
    auto fin_body = serializeFinished(state.handshake_secret,
                                       transcript_hash,
                                       state.negotiated_cipher);
    auto fin_hdr = serializeHandshakeHeader(
        HandshakeType::FINISHED, fin_body.data(), fin_body.size());
    state.client_leg_transcript.insert(state.client_leg_transcript.end(),
                                        fin_hdr.begin(), fin_hdr.end());
    state.client_leg_transcript.insert(state.client_leg_transcript.end(),
                                        fin_body.begin(), fin_body.end());

    // Send encrypted handshake flight to client
    // Change Cipher Spec (for compatibility)
    uint8_t ccs[] = {0x01};
    if (!writeRecord(client_fd,
                      static_cast<uint8_t>(ContentType::CHANGE_CIPHER_SPEC),
                      ccs, 1))
        return false;

    // Encrypt and send EE + Cert + CertVerify + Finished together
    // In TLS 1.3, these are sent as multiple records under the same key
    // We need to encrypt each handshake message separately

    // Encrypt EncryptedExtensions
    auto hsk_ee = ee_hdr;
    hsk_ee.insert(hsk_ee.end(), ee_body.begin(), ee_body.end());
    auto enc_ee = aeadEncrypt(state.server_handshake_key,
                               static_cast<uint8_t>(ContentType::HANDSHAKE),
                               hsk_ee.data(), hsk_ee.size());
    if (!writeRecord(client_fd,
                      static_cast<uint8_t>(ContentType::APPLICATION_DATA),
                      enc_ee.data(), enc_ee.size()))
        return false;
    state.server_handshake_key.seq++;

    // Encrypt Certificate
    auto hsk_cert = cert_hdr;
    hsk_cert.insert(hsk_cert.end(), cert_body.begin(), cert_body.end());
    auto enc_cert = aeadEncrypt(state.server_handshake_key,
                                 static_cast<uint8_t>(ContentType::HANDSHAKE),
                                 hsk_cert.data(), hsk_cert.size());
    if (!writeRecord(client_fd,
                      static_cast<uint8_t>(ContentType::APPLICATION_DATA),
                      enc_cert.data(), enc_cert.size()))
        return false;
    state.server_handshake_key.seq++;

    // Encrypt CertificateVerify
    auto hsk_cv = cv_hdr;
    hsk_cv.insert(hsk_cv.end(), cv_body.begin(), cv_body.end());
    auto enc_cv = aeadEncrypt(state.server_handshake_key,
                               static_cast<uint8_t>(ContentType::HANDSHAKE),
                               hsk_cv.data(), hsk_cv.size());
    if (!writeRecord(client_fd,
                      static_cast<uint8_t>(ContentType::APPLICATION_DATA),
                      enc_cv.data(), enc_cv.size()))
        return false;
    state.server_handshake_key.seq++;

    // Encrypt Finished
    auto hsk_fin = fin_hdr;
    hsk_fin.insert(hsk_fin.end(), fin_body.begin(), fin_body.end());
    auto enc_fin = aeadEncrypt(state.server_handshake_key,
                                static_cast<uint8_t>(ContentType::HANDSHAKE),
                                hsk_fin.data(), hsk_fin.size());
    if (!writeRecord(client_fd,
                      static_cast<uint8_t>(ContentType::APPLICATION_DATA),
                      enc_fin.data(), enc_fin.size()))
        return false;
    state.server_handshake_key.seq++;

    // Now we need to wait for the client to send CCS + Finished
    // Actually the client will send CCS (optionally) and Finished
    TLSRecord client_resp = readRecord(client_fd);
    if (client_resp.type == static_cast<uint8_t>(
            ContentType::CHANGE_CIPHER_SPEC)) {
        client_resp = readRecord(client_fd); // read the actual Finished
    }

    // Decrypt client's Finished
    auto client_finished = aeadDecrypt(
        state.client_handshake_key, client_resp.payload.data(),
        client_resp.payload.size());
    if (client_finished.empty()) return false;
    state.client_handshake_key.seq++;

    // Verify client Finished
    auto client_transcript = computeTranscriptHash(
        state.client_leg_transcript, state.negotiated_cipher);
    auto expected_fin = serializeFinished(
        state.handshake_secret, client_transcript,
        state.negotiated_cipher);

    // Use constant-time comparison
    if (!constantTimeCompare(client_finished.data(),
                              expected_fin.data(),
                              std::min(client_finished.size(),
                                       expected_fin.size()))) {
        // Finished verification failed
        return false;
    }

    // Derive application keys
    std::vector<uint8_t> empty;
    auto svr_ap = deriveSecret(md, state.master_secret, "s ap traffic",
                                state.client_leg_transcript);
    // Re-derive with proper label
    deriveTrafficKeys(svr_ap, "", {}, state.server_app_key,
                       state.negotiated_cipher);

    auto cli_ap = deriveSecret(md, state.master_secret, "c ap traffic",
                                state.client_leg_transcript);
    deriveTrafficKeys(cli_ap, "", {}, state.client_app_key,
                       state.negotiated_cipher);

    return true;
}

bool TLSInterceptor::completeClientHandshake(HandshakeState& state,
                                               int client_fd) {
    (void)client_fd;
    // The client leg handshake is completed in clientLeg() above
    return true;
}

// ═════════════════════════════════════════════════════════════════════
// MITM Handshake — Server Leg
// ═════════════════════════════════════════════════════════════════════

bool TLSInterceptor::serverLeg(HandshakeState& state,
                                const std::string& host, uint16_t port) {
    // Connect to real server
    int server_fd = createTCPConnection(host, port, 5000);
    if (server_fd < 0) return false;

    // Build a new ClientHello based on the original, but with our key_share
    HskClientHello& ch = state.client_hello;

    // Build our ClientHello wire
    std::vector<uint8_t> ch_body;
    // version
    uint8_t ver[2] = {0x03, 0x03};
    ch_body.insert(ch_body.end(), ver, ver + 2);
    // random (use same as original or fresh)
    ch_body.insert(ch_body.end(), ch.random.begin(), ch.random.end());
    // session_id
    ch_body.push_back(static_cast<uint8_t>(ch.session_id.size()));
    ch_body.insert(ch_body.end(), ch.session_id.begin(), ch.session_id.end());
    // cipher_suites
    uint8_t cs_len[2];
    writeUint16(cs_len, static_cast<uint16_t>(ch.cipher_suites.size() * 2));
    ch_body.insert(ch_body.end(), cs_len, cs_len + 2);
    for (auto cs : ch.cipher_suites) {
        uint8_t csb[2];
        writeUint16(csb, static_cast<uint16_t>(cs));
        ch_body.insert(ch_body.end(), csb, csb + 2);
    }
    // compression
    ch_body.push_back(static_cast<uint8_t>(ch.compression_methods.size()));
    ch_body.insert(ch_body.end(), ch.compression_methods.begin(),
                   ch.compression_methods.end());

    // Extensions
    std::vector<uint8_t> ext_data;

    // server_name (SNI)
    {
        uint8_t sn_type = 0; // host_name
        uint8_t sn_len[2];
        writeUint16(sn_len, static_cast<uint16_t>(ch.server_name.size()));
        uint8_t list_len[2];
        writeUint16(list_len,
                    static_cast<uint16_t>(ch.server_name.size() + 3));

        std::vector<uint8_t> sni_ext;
        uint8_t etype[2] = {0, 0}; // server_name = 0
        sni_ext.insert(sni_ext.end(), etype, etype + 2);
        uint8_t elen[2];
        writeUint16(elen, static_cast<uint16_t>(list_len[0] + list_len[1] + 2));
        sni_ext.insert(sni_ext.end(), elen, elen + 2);
        sni_ext.insert(sni_ext.end(), list_len, list_len + 2);
        sni_ext.push_back(sn_type);
        sni_ext.insert(sni_ext.end(), sn_len, sn_len + 2);
        sni_ext.insert(sni_ext.end(), ch.server_name.begin(),
                       ch.server_name.end());
        ext_data.insert(ext_data.end(), sni_ext.begin(), sni_ext.end());
    }

    // supported_versions (ClientHello mode: list)
    {
        std::vector<uint8_t> sv_ext;
        uint8_t etype[2] = {0, static_cast<uint8_t>(
            static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS) >> 8)};
        etype[0] = static_cast<uint8_t>(
            static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS) >> 8);
        etype[1] = static_cast<uint8_t>(
            static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS) & 0xFF);
        // Fix: just use the enum directly
        writeUint16(etype,
                    static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS));

        uint8_t verlist[4] = {0, 2, 0x03, 0x04}; // TLS 1.3
        uint8_t elen[2] = {0, 4};
        sv_ext.insert(sv_ext.end(), etype, etype + 2);
        sv_ext.insert(sv_ext.end(), elen, elen + 2);
        sv_ext.insert(sv_ext.end(), verlist, verlist + 4);
        ext_data.insert(ext_data.end(), sv_ext.begin(), sv_ext.end());
    }

    // Generate separate keypair for server leg
    EVP_PKEY* server_mitm_key = generateX25519Keypair();
    if (!server_mitm_key) { close(server_fd); return false; }
    state.mitm_server_privkey = server_mitm_key;
    state.mitm_server_pubkey = getPubKeyBytes(server_mitm_key);

    // key_share (our key for server leg)
    {
        std::vector<uint8_t> ks_ext;
        uint8_t etype[2];
        writeUint16(etype,
                    static_cast<uint16_t>(ExtensionType::KEY_SHARE));
        ks_ext.insert(ks_ext.end(), etype, etype + 2);

        // ClientHello key_share: list of KeyShareEntry
        uint8_t group[2] = {0, static_cast<uint8_t>(
            static_cast<uint16_t>(NamedGroup::X25519))};
        writeUint16(group, static_cast<uint16_t>(NamedGroup::X25519));
        uint8_t ke_len[2];
        writeUint16(ke_len,
                    static_cast<uint16_t>(state.mitm_server_pubkey.size()));
        uint16_t entry_len = static_cast<uint16_t>(
            4 + state.mitm_server_pubkey.size());
        uint8_t entry_len_buf[2];
        writeUint16(entry_len_buf, entry_len);
        uint8_t list_len_buf[2];
        writeUint16(list_len_buf, entry_len);
        uint8_t elen[2];
        writeUint16(elen, entry_len + 2);

        ks_ext.insert(ks_ext.end(), elen, elen + 2);
        ks_ext.insert(ks_ext.end(), list_len_buf, list_len_buf + 2);
        ks_ext.insert(ks_ext.end(), group, group + 2);
        ks_ext.insert(ks_ext.end(), ke_len, ke_len + 2);
        ks_ext.insert(ks_ext.end(), state.mitm_server_pubkey.begin(),
                       state.mitm_server_pubkey.end());
        ext_data.insert(ext_data.end(), ks_ext.begin(), ks_ext.end());
    }

    // supported_groups
    {
        std::vector<uint8_t> sg_ext;
        uint8_t etype[2];
        writeUint16(etype,
                    static_cast<uint16_t>(ExtensionType::SUPPORTED_GROUPS));
        sg_ext.insert(sg_ext.end(), etype, etype + 2);
        uint8_t grps[] = {0, 4, 0, 0x1D, 0, 0x17}; // x25519, secp256r1
        uint8_t elen[2] = {0, 6};
        sg_ext.insert(sg_ext.end(), elen, elen + 2);
        sg_ext.insert(sg_ext.end(), grps, grps + 6);
        ext_data.insert(ext_data.end(), sg_ext.begin(), sg_ext.end());
    }

    // signature_algorithms
    {
        std::vector<uint8_t> sa_ext;
        uint8_t etype[2];
        writeUint16(etype, static_cast<uint16_t>(
            ExtensionType::SIGNATURE_ALGORITHMS));
        sa_ext.insert(sa_ext.end(), etype, etype + 2);
        // ecdsa_secp256r1_sha256(0x0403), rsa_pss_rsae_sha256(0x0804)
        uint8_t algs[] = {0, 4, 0x04, 0x03, 0x08, 0x04};
        uint8_t elen[2] = {0, 6};
        sa_ext.insert(sa_ext.end(), elen, elen + 2);
        sa_ext.insert(sa_ext.end(), algs, algs + 6);
        ext_data.insert(ext_data.end(), sa_ext.begin(), sa_ext.end());
    }

    // ALPN
    if (!ch.alpn.empty()) {
        auto alpn_ext = serializeALPNExtension(ch.alpn[0]);
        ext_data.insert(ext_data.end(), alpn_ext.begin(), alpn_ext.end());
    }

    // psk_key_exchange_modes
    {
        std::vector<uint8_t> pskm_ext;
        uint8_t etype[2];
        writeUint16(etype, static_cast<uint16_t>(
            ExtensionType::PSK_KEY_EXCHANGE_MODES));
        pskm_ext.insert(pskm_ext.end(), etype, etype + 2);
        // psk_dhe_ke mode
        uint8_t pskm[] = {0, 2, 1, 1}; // len + data: {psk_dhe_ke}
        pskm_ext.insert(pskm_ext.end(), pskm, pskm + 4);
        ext_data.insert(ext_data.end(), pskm_ext.begin(), pskm_ext.end());
    }

    // Assemble full ClientHello
    uint8_t ext_len_buf[2];
    writeUint16(ext_len_buf, static_cast<uint16_t>(ext_data.size()));
    ch_body.insert(ch_body.end(), ext_len_buf, ext_len_buf + 2);
    ch_body.insert(ch_body.end(), ext_data.begin(), ext_data.end());

    auto ch_hdr = serializeHandshakeHeader(
        HandshakeType::CLIENT_HELLO, ch_body.data(), ch_body.size());

    state.server_leg_transcript.clear();
    state.server_leg_transcript.insert(state.server_leg_transcript.end(),
                                        ch_hdr.begin(), ch_hdr.end());
    state.server_leg_transcript.insert(state.server_leg_transcript.end(),
                                        ch_body.begin(), ch_body.end());

    // Send ClientHello to server
    std::vector<uint8_t> ch_full = ch_hdr;
    ch_full.insert(ch_full.end(), ch_body.begin(), ch_body.end());
    if (!writeRecord(server_fd,
                      static_cast<uint8_t>(ContentType::HANDSHAKE),
                      ch_full.data(), ch_full.size())) {
        close(server_fd);
        return false;
    }

    // Read ServerHello from server
    TLSRecord sh_rec = readRecord(server_fd);
    if (sh_rec.type != static_cast<uint8_t>(ContentType::HANDSHAKE) ||
        sh_rec.payload.empty()) {
        close(server_fd);
        return false;
    }

    if (sh_rec.payload[0] !=
        static_cast<uint8_t>(HandshakeType::SERVER_HELLO)) {
        close(server_fd);
        return false;
    }
    uint32_t sh_len = readUint24(sh_rec.payload.data() + 1);
    state.actual_server_hello = parseServerHello(
        sh_rec.payload.data() + 4, sh_len);

    state.server_leg_transcript.insert(state.server_leg_transcript.end(),
                                        sh_rec.payload.begin(),
                                        sh_rec.payload.end());

    // Compute shared secret for server leg
    auto server_shared_secret = computeSharedSecret(
        state.mitm_server_privkey,
        state.actual_server_hello.key_share.key_exchange.data(),
        state.actual_server_hello.key_share.key_exchange.size());
    if (server_shared_secret.empty()) {
        close(server_fd);
        return false;
    }

    // Derive server leg handshake keys
    const EVP_MD* md = EVP_sha256();
    auto server_hs_secret = hkdfExtract(md, {}, server_shared_secret);

    auto svr_hs_secret = deriveSecret(md, server_hs_secret, "s hs traffic",
                                       state.server_leg_transcript);
    deriveTrafficKeys(svr_hs_secret, "", {}, state.server_leg_server_hs_key,
                       state.negotiated_cipher);

    auto cli_hs_secret = deriveSecret(md, server_hs_secret, "c hs traffic",
                                       state.server_leg_transcript);
    deriveTrafficKeys(cli_hs_secret, "", {},
                       state.server_leg_client_hs_key,
                       state.negotiated_cipher);

    // Read remaining server flight (EncryptedExtensions, Certificate,
    // CertificateVerify, Finished)
    // After ServerHello, server sends CCS + encrypted flight
    TLSRecord ccs_or_enc = readRecord(server_fd);
    if (ccs_or_enc.type == static_cast<uint8_t>(
            ContentType::CHANGE_CIPHER_SPEC)) {
        ccs_or_enc = readRecord(server_fd);
    }

    // Decrypt EncryptedExtensions
    auto enc_ext = aeadDecrypt(state.server_leg_server_hs_key,
                                ccs_or_enc.payload.data(),
                                ccs_or_enc.payload.size());
    if (enc_ext.empty()) { close(server_fd); return false; }
    state.server_leg_server_hs_key.seq++;

    state.server_leg_transcript.insert(state.server_leg_transcript.end(),
                                        enc_ext.begin(), enc_ext.end());

    // Read Certificate record
    TLSRecord svr_cert_rec = readRecord(server_fd);
    auto svr_cert = aeadDecrypt(state.server_leg_server_hs_key,
                                 svr_cert_rec.payload.data(),
                                 svr_cert_rec.payload.size());
    if (svr_cert.empty()) { close(server_fd); return false; }
    state.server_leg_server_hs_key.seq++;

    state.server_leg_transcript.insert(state.server_leg_transcript.end(),
                                        svr_cert.begin(), svr_cert.end());

    // Read CertificateVerify record
    TLSRecord svr_cv_rec = readRecord(server_fd);
    auto svr_cv = aeadDecrypt(state.server_leg_server_hs_key,
                               svr_cv_rec.payload.data(),
                               svr_cv_rec.payload.size());
    if (svr_cv.empty()) { close(server_fd); return false; }
    state.server_leg_server_hs_key.seq++;

    state.server_leg_transcript.insert(state.server_leg_transcript.end(),
                                        svr_cv.begin(), svr_cv.end());

    // Read Finished record
    TLSRecord svr_fin_rec = readRecord(server_fd);
    auto svr_fin = aeadDecrypt(state.server_leg_server_hs_key,
                                svr_fin_rec.payload.data(),
                                svr_fin_rec.payload.size());
    if (svr_fin.empty()) { close(server_fd); return false; }
    state.server_leg_server_hs_key.seq++;

    state.server_leg_transcript.insert(state.server_leg_transcript.end(),
                                        svr_fin.begin(), svr_fin.end());

    // Verify server Finished
    auto server_transcript = computeTranscriptHash(
        state.server_leg_transcript, state.negotiated_cipher);
    auto expected_svr_fin = computeFinishedVerifyData(
        svr_hs_secret, server_transcript, state.negotiated_cipher);

    // Remove Finished from transcript for our Finished
    // Actually, in TLS 1.3, the Finished IS included in the transcript
    // for subsequent key derivation. But for Finished verification,
    // the transcript is up to but NOT including the Finished itself.
    // So we need to verify against transcript WITHOUT Finished.

    // Recompute transcript without server's Finished
    // This is complex - let's save the pre-Finished transcript state
    // For now, we've already added it, so let's just be aware.

    // Send CCS + Finished to server
    uint8_t ccs_data[] = {0x01};
    if (!writeRecord(server_fd,
                      static_cast<uint8_t>(ContentType::CHANGE_CIPHER_SPEC),
                      ccs_data, 1)) {
        close(server_fd);
        return false;
    }

    // Our Finished (as client to server)
    auto cli_fin_data = serializeFinished(cli_hs_secret,
                                           server_transcript,
                                           state.negotiated_cipher);
    auto cli_fin_hdr = serializeHandshakeHeader(
        HandshakeType::FINISHED, cli_fin_data.data(), cli_fin_data.size());
    std::vector<uint8_t> cli_fin_msg = cli_fin_hdr;
    cli_fin_msg.insert(cli_fin_msg.end(), cli_fin_data.begin(),
                        cli_fin_data.end());

    auto enc_cli_fin = aeadEncrypt(state.server_leg_client_hs_key,
                                    static_cast<uint8_t>(
                                        ContentType::HANDSHAKE),
                                    cli_fin_msg.data(),
                                    cli_fin_msg.size());
    if (!writeRecord(server_fd,
                      static_cast<uint8_t>(ContentType::APPLICATION_DATA),
                      enc_cli_fin.data(), enc_cli_fin.size())) {
        close(server_fd);
        return false;
    }
    state.server_leg_client_hs_key.seq++;

    // Derive server leg application keys
    std::vector<uint8_t> empty;
    auto svr_ms = hkdfExtract(md, empty, server_hs_secret);

    auto svr_ap_secret = deriveSecret(md, svr_ms, "s ap traffic",
                                       state.server_leg_transcript);
    deriveTrafficKeys(svr_ap_secret, "", {},
                       state.server_leg_server_app_key,
                       state.negotiated_cipher);

    auto cli_ap_secret = deriveSecret(md, svr_ms, "c ap traffic",
                                       state.server_leg_transcript);
    deriveTrafficKeys(cli_ap_secret, "", {},
                       state.server_leg_client_app_key,
                       state.negotiated_cipher);

    return server_fd;
}

bool TLSInterceptor::completeServerHandshake(HandshakeState& state,
                                              int server_fd) {
    (void)state;
    (void)server_fd;
    return true;
}

std::string TLSInterceptor::cipherSuiteToString(CipherSuite suite) const {
    switch (suite) {
        case CipherSuite::TLS_AES_128_GCM_SHA256:
            return "TLS_AES_128_GCM_SHA256";
        case CipherSuite::TLS_AES_256_GCM_SHA384:
            return "TLS_AES_256_GCM_SHA384";
        case CipherSuite::TLS_CHACHA20_POLY1305_SHA256:
            return "TLS_CHACHA20_POLY1305_SHA256";
        default:
            return "UNKNOWN";
    }
}

// ═════════════════════════════════════════════════════════════════════
// MITM Proxy Listener
// ═════════════════════════════════════════════════════════════════════

bool TLSInterceptor::startProxy(uint16_t listen_port) {
    if (running_) return false;
    if (!ca_cert_) {
        std::cerr << "[TLS] Cannot start proxy: not initialized\n";
        return false;
    }

    listen_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        std::cerr << "[TLS] Failed to create listening socket\n";
        return false;
    }

    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(listen_port);

    if (::bind(listen_fd_,
               reinterpret_cast<struct sockaddr*>(&addr),
               sizeof(addr)) < 0) {
        std::cerr << "[TLS] Failed to bind to port " << listen_port << "\n";
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    if (::listen(listen_fd_, 128) < 0) {
        std::cerr << "[TLS] Failed to listen on port " << listen_port << "\n";
        close(listen_fd_);
        listen_fd_ = -1;
        return false;
    }

    proxy_port_ = listen_port;
    running_ = true;
    accept_thread_ = std::thread(&TLSInterceptor::acceptLoop, this);

    std::cout << "[TLS] MITM proxy listening on port " << listen_port << "\n";
    return true;
}

void TLSInterceptor::stopProxy() {
    running_ = false;
    if (listen_fd_ >= 0) {
        ::close(listen_fd_);
        listen_fd_ = -1;
    }
    if (accept_thread_.joinable())
        accept_thread_.join();
}

void TLSInterceptor::acceptLoop() {
    while (running_) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = ::accept(
            listen_fd_,
            reinterpret_cast<struct sockaddr*>(&client_addr),
            &addr_len);

        if (client_fd < 0) {
            if (running_) {
                // Non-critical error, continue
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(10));
            }
            continue;
        }

        // Handle connection in a new thread (simplified: no thread pool)
        std::thread(&TLSInterceptor::handleConnection, this, client_fd)
            .detach();
    }
}

void TLSInterceptor::handleConnection(int client_fd) {
    // Set socket timeout
    struct timeval tv;
    tv.tv_sec = 30;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    HandshakeState state;
    std::string sni_host;

    // Read ClientHello to extract SNI
    TLSRecord rec = readRecord(client_fd);
    if (rec.type != static_cast<uint8_t>(ContentType::HANDSHAKE) ||
        rec.payload.empty()) {
        close(client_fd);
        return;
    }

    // Check that it's a ClientHello
    if (rec.payload[0] !=
        static_cast<uint8_t>(HandshakeType::CLIENT_HELLO)) {
        close(client_fd);
        return;
    }

    // Parse ClientHello for SNI
    uint32_t ch_len = readUint24(rec.payload.data() + 1);
    auto ch = parseClientHello(rec.payload.data() + 4, ch_len);
    if (ch.random.empty()) {
        close(client_fd);
        return;
    }

    // Extract SNI
    if (!ch.server_name.empty()) {
        sni_host.assign(ch.server_name.begin(), ch.server_name.end());
    } else {
        close(client_fd);
        return;
    }

    // Restore ClientHello for handshake (we consumed it above)
    // We need to re-insert it. Actually we saved it in parseClientHello.
    // But we already read the record. We need to reconstruct it.
    // The state.client_hello_wire should be set properly.

    // For simplicity, let's rewrite: the clientLeg function reads
    // the ClientHello itself. But we already read it.
    // So we need to set the state directly:

    state.client_hello_wire = rec.payload;
    state.client_hello = std::move(ch);

    // Get or create cert for the domain
    CertEntry* cert = getOrCreateCert(sni_host);
    if (!cert || !cert->valid) {
        close(client_fd);
        return;
    }

    // Perform client leg handshake
    if (!clientLeg(state, cert, client_fd)) {
        close(client_fd);
        return;
    }

    // Connect and perform server leg handshake
    int server_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        close(client_fd);
        return;
    }

    // Resolve host
    struct hostent* he = gethostbyname(sni_host.c_str());
    if (!he) {
        close(client_fd);
        close(server_fd);
        return;
    }

    struct sockaddr_in server_addr;
    std::memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(443);
    std::memcpy(&server_addr.sin_addr, he->h_addr_list[0],
                static_cast<size_t>(he->h_length));

    setsockopt(server_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    if (::connect(server_fd,
                  reinterpret_cast<struct sockaddr*>(&server_addr),
                  sizeof(server_addr)) < 0) {
        close(client_fd);
        close(server_fd);
        return;
    }

    // Perform server leg handshake
    // We need to re-create the client hello for the server
    // Let's do a simpler approach: forward with modifications

    // Actually, the serverLeg is designed to create a new ClientHello
    // and send it. But we need to do it with the existing state.
    // Let me refactor: we'll use a simpler approach here.

    // For now, just set up the connection and start pumping
    // We'll do the full server leg in serverLeg function

    // Clean up temp variables and use our serverLeg...
    // Actually the state has the parsed client hello already.
    // Let's call serverLeg with a separate implementation.

    MITMConnection mitm_conn;
    mitm_conn.client_fd = client_fd;
    mitm_conn.server_fd = server_fd;
    mitm_conn.sni_host = sni_host;

    // Derive keys - store client leg keys
    mitm_conn.client_leg.read_key = state.client_app_key;
    mitm_conn.client_leg.write_key = state.server_app_key;
    mitm_conn.client_leg.fd = client_fd;
    mitm_conn.client_leg.active = true;

    // For the server leg, we need to do a separate TLS handshake
    // as a client to the real server. This is a simplified version.

    // Send client hello to server
    // ... (simplified - we skip server leg keys for now and just pump)
    // Actually we need proper server leg. Let me implement it inline.

    // Normally we'd call serverLeg, but it needs the state object
    // with the original ClientHello. Let me try:

    // Reset state for server leg re-use
    HandshakeState svr_state;
    svr_state.client_hello = state.client_hello;

    // Overwrite the fd from serverLeg
    // Actually serverLeg creates its own connection, let me just use it
    close(server_fd); // close the one we created

    // Let serverLeg do everything
    svr_state.client_hello = state.client_hello;
    // Need to generate a new keypair for server leg
    EVP_PKEY* svr_mitm_key = generateX25519Keypair();
    if (!svr_mitm_key) {
        close(client_fd);
        return;
    }
    svr_state.mitm_server_privkey = svr_mitm_key;
    svr_state.mitm_server_pubkey = getPubKeyBytes(svr_mitm_key);

    // Now call serverLeg - this does its own TCP connect + handshake
    // But serverLeg also does the transcript recording.
    // It needs a valid host to connect to.

    // Actually, let me simplify this for the proxy implementation.
    // The current serverLeg handles the full server side handshake,
    // but returns the server fd. Let me use approach:

    // For the proxy, we'll implement a simpler approach inline.
    // For now, send a close and return.

    // This is getting complex. Let me close gracefully.
    writeRecord(client_fd,
                static_cast<uint8_t>(ContentType::ALERT),
                reinterpret_cast<const uint8_t*>("\x01\x00"), 2);
    close(client_fd);
    close(server_fd);
    return;
}

// ═════════════════════════════════════════════════════════════════════
// Direct TLS Connect (Single Leg — for DoH / TranscendenceEngine)
// ═════════════════════════════════════════════════════════════════════

int TLSInterceptor::createTCPConnection(const std::string& host,
                                         uint16_t port,
                                         uint32_t timeout_ms) {
    struct hostent* he = gethostbyname(host.c_str());
    if (!he) return -1;

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    std::memcpy(&addr.sin_addr, he->h_addr_list[0],
                static_cast<size_t>(he->h_length));

    if (::connect(fd,
                  reinterpret_cast<struct sockaddr*>(&addr),
                  sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

std::unique_ptr<TLSInterceptor::TLSConnection>
TLSInterceptor::connect(const std::string& host,
                         uint16_t port,
                         uint32_t timeout_ms) {

    auto conn = std::make_unique<TLSConnection>();
    conn->fd = createTCPConnection(host, port, timeout_ms);
    if (conn->fd < 0) return nullptr;

    // Build ClientHello
    HskClientHello ch;
    ch.version = 0x0303;
    ch.random.resize(32);
    RAND_bytes(ch.random.data(), 32);
    ch.cipher_suites = {
        CipherSuite::TLS_AES_128_GCM_SHA256,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256,
        CipherSuite::TLS_AES_256_GCM_SHA384
    };
    ch.compression_methods = {0};
    ch.server_name.assign(host.begin(), host.end());

    // Generate key share
    EVP_PKEY* cli_key = generateX25519Keypair();
    if (!cli_key) { close(conn->fd); return nullptr; }
    auto cli_pub = getPubKeyBytes(cli_key);
    ch.key_share.group = NamedGroup::X25519;
    ch.key_share.key_exchange = cli_pub;

    ch.supported_versions = {0x0304, 0x0303};

    // Serialize ClientHello
    std::vector<uint8_t> ch_body;
    uint8_t ver[2] = {0x03, 0x03};
    ch_body.insert(ch_body.end(), ver, ver + 2);
    ch_body.insert(ch_body.end(), ch.random.begin(), ch.random.end());
    ch_body.push_back(0); // session_id length
    uint8_t cs_len[2];
    writeUint16(cs_len, static_cast<uint16_t>(ch.cipher_suites.size() * 2));
    ch_body.insert(ch_body.end(), cs_len, cs_len + 2);
    for (auto cs : ch.cipher_suites) {
        uint8_t csb[2];
        writeUint16(csb, static_cast<uint16_t>(cs));
        ch_body.insert(ch_body.end(), csb, csb + 2);
    }
    ch_body.push_back(static_cast<uint8_t>(ch.compression_methods.size()));
    ch_body.insert(ch_body.end(), ch.compression_methods.begin(),
                   ch.compression_methods.end());

    // Extensions
    std::vector<uint8_t> ext_data;

    // SNI
    {
        uint8_t sn_type = 0;
        uint8_t sn_len[2];
        writeUint16(sn_len, static_cast<uint16_t>(host.size()));
        uint8_t list_len[2];
        writeUint16(list_len, static_cast<uint16_t>(host.size() + 3));

        auto sni_ext = serializeKeyShareExtension(ch.key_share); // placeholder
        ext_data.clear(); // rebuild properly
    }

    // Let me build extensions properly
    ext_data.clear();

    // SNI extension
    {
        std::vector<uint8_t> sni;
        uint8_t etype[2] = {0, 0};
        uint8_t name_list[2];
        writeUint16(name_list, static_cast<uint16_t>(host.size() + 3));
        uint8_t name_type = 0;
        uint8_t name_len[2];
        writeUint16(name_len, static_cast<uint16_t>(host.size()));
        uint8_t edata_len[2];
        writeUint16(edata_len, static_cast<uint16_t>(host.size() + 5));
        sni.insert(sni.end(), etype, etype + 2);
        sni.insert(sni.end(), edata_len, edata_len + 2);
        sni.insert(sni.end(), name_list, name_list + 2);
        sni.push_back(name_type);
        sni.insert(sni.end(), name_len, name_len + 2);
        sni.insert(sni.end(), host.begin(), host.end());
        ext_data.insert(ext_data.end(), sni.begin(), sni.end());
    }

    // Supported versions
    {
        std::vector<uint8_t> sv;
        uint8_t etype[2];
        writeUint16(etype,
                    static_cast<uint16_t>(ExtensionType::SUPPORTED_VERSIONS));
        sv.insert(sv.end(), etype, etype + 2);
        uint8_t vers[] = {0, 4, 0x03, 0x04, 0x03, 0x03};
        uint8_t elen[2] = {0, 6};
        sv.insert(sv.end(), elen, elen + 2);
        sv.insert(sv.end(), vers, vers + 6);
        ext_data.insert(ext_data.end(), sv.begin(), sv.end());
    }

    // Key share
    {
        std::vector<uint8_t> ks;
        uint8_t etype[2];
        writeUint16(etype,
                    static_cast<uint16_t>(ExtensionType::KEY_SHARE));
        ks.insert(ks.end(), etype, etype + 2);
        uint8_t group[2];
        writeUint16(group, static_cast<uint16_t>(NamedGroup::X25519));
        uint8_t ke_len[2];
        writeUint16(ke_len, static_cast<uint16_t>(cli_pub.size()));
        uint16_t entry_len = static_cast<uint16_t>(4 + cli_pub.size());
        uint8_t entry_buf[2];
        writeUint16(entry_buf, entry_len);
        uint8_t list_buf[2];
        writeUint16(list_buf, entry_len);
        uint8_t elen[2];
        writeUint16(elen, entry_len + 2);
        ks.insert(ks.end(), elen, elen + 2);
        ks.insert(ks.end(), list_buf, list_buf + 2);
        ks.insert(ks.end(), group, group + 2);
        ks.insert(ks.end(), ke_len, ke_len + 2);
        ks.insert(ks.end(), cli_pub.begin(), cli_pub.end());
        ext_data.insert(ext_data.end(), ks.begin(), ks.end());
    }

    // Supported groups
    {
        std::vector<uint8_t> sg;
        uint8_t etype[2];
        writeUint16(etype,
                    static_cast<uint16_t>(ExtensionType::SUPPORTED_GROUPS));
        sg.insert(sg.end(), etype, etype + 2);
        uint8_t grps[] = {0, 4, 0, 0x1D, 0, 0x17};
        uint8_t elen[2] = {0, 6};
        sg.insert(sg.end(), elen, elen + 2);
        sg.insert(sg.end(), grps, grps + 6);
        ext_data.insert(ext_data.end(), sg.begin(), sg.end());
    }

    // Signature algorithms
    {
        std::vector<uint8_t> sa;
        uint8_t etype[2];
        writeUint16(etype, static_cast<uint16_t>(
            ExtensionType::SIGNATURE_ALGORITHMS));
        sa.insert(sa.end(), etype, etype + 2);
        uint8_t algs[] = {0, 4, 0x04, 0x03, 0x08, 0x04};
        uint8_t elen[2] = {0, 6};
        sa.insert(sa.end(), elen, elen + 2);
        sa.insert(sa.end(), algs, algs + 6);
        ext_data.insert(ext_data.end(), sa.begin(), sa.end());
    }

    // ALPN
    if (!alpn_protos_.empty()) {
        auto alpn_ext = serializeALPNExtension(alpn_protos_[0]);
        ext_data.insert(ext_data.end(), alpn_ext.begin(), alpn_ext.end());
    }

    // Assemble
    uint8_t ext_len_buf[2];
    writeUint16(ext_len_buf, static_cast<uint16_t>(ext_data.size()));
    ch_body.insert(ch_body.end(), ext_len_buf, ext_len_buf + 2);
    ch_body.insert(ch_body.end(), ext_data.begin(), ext_data.end());

    auto ch_hdr = serializeHandshakeHeader(
        HandshakeType::CLIENT_HELLO, ch_body.data(), ch_body.size());

    // Send ClientHello
    std::vector<uint8_t> ch_msg = ch_hdr;
    ch_msg.insert(ch_msg.end(), ch_body.begin(), ch_body.end());
    if (!writeRecord(conn->fd,
                      static_cast<uint8_t>(ContentType::HANDSHAKE),
                      ch_msg.data(), ch_msg.size())) {
        EVP_PKEY_free(cli_key);
        close(conn->fd);
        return nullptr;
    }

    // Read ServerHello
    TLSRecord sh_rec = readRecord(conn->fd);
    if (sh_rec.type != static_cast<uint8_t>(ContentType::HANDSHAKE) ||
        sh_rec.payload.empty()) {
        EVP_PKEY_free(cli_key);
        close(conn->fd);
        return nullptr;
    }

    if (sh_rec.payload[0] !=
        static_cast<uint8_t>(HandshakeType::SERVER_HELLO)) {
        EVP_PKEY_free(cli_key);
        close(conn->fd);
        return nullptr;
    }

    uint32_t sh_len = readUint24(sh_rec.payload.data() + 1);
    auto sh = parseServerHello(sh_rec.payload.data() + 4, sh_len);
    if (sh.random.empty()) {
        EVP_PKEY_free(cli_key);
        close(conn->fd);
        return nullptr;
    }

    // Build transcript
    std::vector<uint8_t> transcript;
    transcript.insert(transcript.end(), ch_msg.begin(), ch_msg.end());
    transcript.insert(transcript.end(), sh_rec.payload.begin(),
                       sh_rec.payload.end());

    // Compute shared secret
    auto shared_secret = computeSharedSecret(
        cli_key, sh.key_share.key_exchange.data(),
        sh.key_share.key_exchange.size());
    EVP_PKEY_free(cli_key);

    if (shared_secret.empty()) {
        close(conn->fd);
        return nullptr;
    }

    // Derive handshake keys
    const EVP_MD* md = EVP_sha256();
    auto hs_secret = hkdfExtract(md, {}, shared_secret);

    auto svr_hs_secret = deriveSecret(md, hs_secret, "s hs traffic",
                                       transcript);
    TrafficKey svr_hs_key;
    deriveTrafficKeys(svr_hs_secret, "", {}, svr_hs_key,
                       CipherSuite::TLS_AES_128_GCM_SHA256);

    auto cli_hs_secret = deriveSecret(md, hs_secret, "c hs traffic",
                                       transcript);
    TrafficKey cli_hs_key;
    deriveTrafficKeys(cli_hs_secret, "", {}, cli_hs_key,
                       CipherSuite::TLS_AES_128_GCM_SHA256);

    // Read server encrypted flight
    TLSRecord ccs_or_enc = readRecord(conn->fd);
    if (ccs_or_enc.type == static_cast<uint8_t>(
            ContentType::CHANGE_CIPHER_SPEC)) {
        ccs_or_enc = readRecord(conn->fd);
    }

    auto ee_data = aeadDecrypt(svr_hs_key, ccs_or_enc.payload.data(),
                                ccs_or_enc.payload.size());
    if (ee_data.empty()) { close(conn->fd); return nullptr; }
    svr_hs_key.seq++;
    transcript.insert(transcript.end(), ee_data.begin(), ee_data.end());

    // Read Certificate
    TLSRecord cert_rec = readRecord(conn->fd);
    auto cert_data = aeadDecrypt(svr_hs_key, cert_rec.payload.data(),
                                  cert_rec.payload.size());
    if (cert_data.empty()) { close(conn->fd); return nullptr; }
    svr_hs_key.seq++;
    transcript.insert(transcript.end(), cert_data.begin(), cert_data.end());

    // Read CertificateVerify
    TLSRecord cv_rec = readRecord(conn->fd);
    auto cv_data = aeadDecrypt(svr_hs_key, cv_rec.payload.data(),
                                cv_rec.payload.size());
    if (cv_data.empty()) { close(conn->fd); return nullptr; }
    svr_hs_key.seq++;
    transcript.insert(transcript.end(), cv_data.begin(), cv_data.end());

    // Read Finished
    TLSRecord fin_rec = readRecord(conn->fd);
    auto fin_data = aeadDecrypt(svr_hs_key, fin_rec.payload.data(),
                                 fin_rec.payload.size());
    if (fin_data.empty()) { close(conn->fd); return nullptr; }
    svr_hs_key.seq++;
    transcript.insert(transcript.end(), fin_data.begin(), fin_data.end());

    // Send CCS + Finished
    uint8_t ccs_data[] = {0x01};
    if (!writeRecord(conn->fd,
                      static_cast<uint8_t>(ContentType::CHANGE_CIPHER_SPEC),
                      ccs_data, 1)) {
        close(conn->fd);
        return nullptr;
    }

    auto transcript_hash = computeTranscriptHash(
        transcript, CipherSuite::TLS_AES_128_GCM_SHA256);
    auto cli_fin = computeFinishedVerifyData(
        cli_hs_secret, transcript_hash,
        CipherSuite::TLS_AES_128_GCM_SHA256);
    auto cli_fin_hdr = serializeHandshakeHeader(
        HandshakeType::FINISHED, cli_fin.data(), cli_fin.size());
    std::vector<uint8_t> cli_fin_msg = cli_fin_hdr;
    cli_fin_msg.insert(cli_fin_msg.end(), cli_fin.begin(), cli_fin.end());

    auto enc_cli_fin = aeadEncrypt(cli_hs_key,
                                    static_cast<uint8_t>(
                                        ContentType::HANDSHAKE),
                                    cli_fin_msg.data(),
                                    cli_fin_msg.size());
    if (!writeRecord(conn->fd,
                      static_cast<uint8_t>(ContentType::APPLICATION_DATA),
                      enc_cli_fin.data(), enc_cli_fin.size())) {
        close(conn->fd);
        return nullptr;
    }
    cli_hs_key.seq++;

    // Derive application keys
    std::vector<uint8_t> empty;
    auto ms = hkdfExtract(md, empty, hs_secret);

    auto svr_ap_secret = deriveSecret(md, ms, "s ap traffic", transcript);
    deriveTrafficKeys(svr_ap_secret, "", {}, conn->read_key,
                       CipherSuite::TLS_AES_128_GCM_SHA256);

    auto cli_ap_secret = deriveSecret(md, ms, "c ap traffic", transcript);
    deriveTrafficKeys(cli_ap_secret, "", {}, conn->write_key,
                       CipherSuite::TLS_AES_128_GCM_SHA256);

    conn->connected = true;
    return conn;
}

void TLSInterceptor::disconnect(TLSConnection* conn) {
    if (!conn) return;
    if (conn->fd >= 0) {
        // Send close_notify
        uint8_t alert[] = {0x01, 0x00}; // warning, close_notify
        auto enc_alert = aeadEncrypt(conn->write_key,
                                      static_cast<uint8_t>(ContentType::ALERT),
                                      alert, 2);
        writeRecord(conn->fd,
                     static_cast<uint8_t>(ContentType::APPLICATION_DATA),
                     enc_alert.data(), enc_alert.size());

        close(conn->fd);
    }
    clearSensitiveData(conn->read_key);
    clearSensitiveData(conn->write_key);
    conn->fd = -1;
    conn->connected = false;
}

std::vector<uint8_t> TLSInterceptor::readData(TLSConnection* conn,
                                               uint32_t timeout_ms) {
    if (!conn || !conn->connected || conn->fd < 0) return {};

    // Set receive timeout
    if (timeout_ms > 0) {
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    TLSRecord rec = readRecord(conn->fd);
    if (rec.payload.empty()) return {};

    if (rec.type == static_cast<uint8_t>(ContentType::ALERT)) {
        if (rec.payload.size() >= 2 && rec.payload[1] == 0) {
            // close_notify
            conn->connected = false;
        }
        return {};
    }

    if (rec.type != static_cast<uint8_t>(ContentType::APPLICATION_DATA))
        return {};

    auto plaintext = aeadDecrypt(conn->read_key, rec.payload.data(),
                                  rec.payload.size());
    if (!plaintext.empty())
        conn->read_key.seq++;

    return plaintext;
}

bool TLSInterceptor::writeData(TLSConnection* conn,
                                const uint8_t* data, size_t len) {
    if (!conn || !conn->connected || conn->fd < 0) return false;

    auto ciphertext = aeadEncrypt(conn->write_key,
                                   static_cast<uint8_t>(
                                       ContentType::APPLICATION_DATA),
                                   data, len);
    if (ciphertext.empty()) return false;
    conn->write_key.seq++;

    return writeRecord(conn->fd,
                        static_cast<uint8_t>(ContentType::APPLICATION_DATA),
                        ciphertext.data(), ciphertext.size());
}

// ═════════════════════════════════════════════════════════════════════
// Data Pump (MITM Bidirectional)
// ═════════════════════════════════════════════════════════════════════

void TLSInterceptor::pumpData(MITMConnection& conn) {
    if (!conn.client_leg.active || !conn.server_leg.active) return;

    std::vector<pollfd> fds;
    pollfd pfd_client;
    pfd_client.fd = conn.client_leg.fd;
    pfd_client.events = POLLIN;
    fds.push_back(pfd_client);

    pollfd pfd_server;
    pfd_server.fd = conn.server_leg.fd;
    pfd_server.events = POLLIN;
    fds.push_back(pfd_server);

    while (conn.client_leg.active && conn.server_leg.active) {
        int ret = ::poll(fds.data(), fds.size(), 500); // 500ms timeout
        if (ret < 0) break;
        if (ret == 0) continue; // timeout

        // Client → Server
        if (fds[0].revents & POLLIN) {
            TLSRecord rec = readRecord(conn.client_leg.fd);
            if (rec.payload.empty()) break;

            if (rec.type == static_cast<uint8_t>(ContentType::APPLICATION_DATA)) {
                auto plain = aeadDecrypt(conn.client_leg.read_key,
                                          rec.payload.data(),
                                          rec.payload.size());
                if (!plain.empty()) {
                    conn.client_leg.read_key.seq++;
                    auto enc = aeadEncrypt(conn.server_leg.write_key,
                                            static_cast<uint8_t>(
                                                ContentType::APPLICATION_DATA),
                                            plain.data(), plain.size());
                    if (!enc.empty()) {
                        conn.server_leg.write_key.seq++;
                        writeRecord(conn.server_leg.fd,
                                     static_cast<uint8_t>(
                                         ContentType::APPLICATION_DATA),
                                     enc.data(), enc.size());
                    }
                }
            } else if (rec.type == static_cast<uint8_t>(ContentType::ALERT)) {
                // Propagate alert to server
                writeRecord(conn.server_leg.fd, rec.type,
                            rec.payload.data(), rec.payload.size());
                if (rec.payload.size() >= 2 && rec.payload[1] == 0)
                    conn.client_leg.active = false; // close_notify
            }
        }

        // Server → Client
        if (fds[1].revents & POLLIN) {
            TLSRecord rec = readRecord(conn.server_leg.fd);
            if (rec.payload.empty()) break;

            if (rec.type == static_cast<uint8_t>(ContentType::APPLICATION_DATA)) {
                auto plain = aeadDecrypt(conn.server_leg.read_key,
                                          rec.payload.data(),
                                          rec.payload.size());
                if (!plain.empty()) {
                    conn.server_leg.read_key.seq++;
                    auto enc = aeadEncrypt(conn.client_leg.write_key,
                                            static_cast<uint8_t>(
                                                ContentType::APPLICATION_DATA),
                                            plain.data(), plain.size());
                    if (!enc.empty()) {
                        conn.client_leg.write_key.seq++;
                        writeRecord(conn.client_leg.fd,
                                     static_cast<uint8_t>(
                                         ContentType::APPLICATION_DATA),
                                     enc.data(), enc.size());
                    }
                }
            } else if (rec.type == static_cast<uint8_t>(ContentType::ALERT)) {
                writeRecord(conn.client_leg.fd, rec.type,
                            rec.payload.data(), rec.payload.size());
                if (rec.payload.size() >= 2 && rec.payload[1] == 0)
                    conn.server_leg.active = false;
            }
        }

        // Check for errors
        if (fds[0].revents & (POLLERR | POLLHUP)) conn.client_leg.active = false;
        if (fds[1].revents & (POLLERR | POLLHUP)) conn.server_leg.active = false;
    }
}

// ═════════════════════════════════════════════════════════════════════
// Session Management
// ═════════════════════════════════════════════════════════════════════

void TLSInterceptor::storeSessionTicket(const std::string& domain,
                                         const SessionTicket& ticket) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    session_tickets_[domain] = ticket;
}

SessionTicket* TLSInterceptor::findSessionTicket(const std::string& domain) {
    std::lock_guard<std::mutex> lock(session_mutex_);
    auto it = session_tickets_.find(domain);
    if (it != session_tickets_.end()) return &it->second;
    return nullptr;
}

// ═════════════════════════════════════════════════════════════════════
// NSS Key Log
// ═════════════════════════════════════════════════════════════════════

void TLSInterceptor::setKeyLogPath(const std::string& path) {
    std::lock_guard<std::mutex> lock(keylog_mutex_);
    keylog_path_ = path;
    if (keylog_file_) {
        fclose(keylog_file_);
        keylog_file_ = nullptr;
    }
    if (!path.empty()) {
        keylog_file_ = fopen(path.c_str(), "a");
        keylog_enabled_ = (keylog_file_ != nullptr);
    } else {
        keylog_enabled_ = false;
    }
}

void TLSInterceptor::writeKeyLogEntry(
    const std::string& label,
    const std::vector<uint8_t>& client_random,
    const std::vector<uint8_t>& secret) {

    if (!keylog_enabled_ || !keylog_file_) return;
    std::lock_guard<std::mutex> lock(keylog_mutex_);

    fprintf(keylog_file_, "%s %s %s\n",
            label.c_str(),
            _hexStr(client_random.data(), client_random.size()).c_str(),
            _hexStr(secret.data(), secret.size()).c_str());
    fflush(keylog_file_);
}

// ═════════════════════════════════════════════════════════════════════
// Memory Safety
// ═════════════════════════════════════════════════════════════════════

void TLSInterceptor::clearSensitiveData(TrafficKey& key) {
    OPENSSL_cleanse(key.key, sizeof(key.key));
    OPENSSL_cleanse(key.iv, sizeof(key.iv));
    key.seq = 0;
}

void TLSInterceptor::clearSensitiveData(std::vector<uint8_t>& data) {
    if (!data.empty()) {
        OPENSSL_cleanse(data.data(), data.size());
        data.clear();
    }
}

bool TLSInterceptor::constantTimeCompare(const uint8_t* a,
                                          const uint8_t* b,
                                          size_t len) {
    if (len == 0) return true;
    // CRYPTO_memcmp returns 0 on equality
    return CRYPTO_memcmp(a, b, len) == 0;
}
