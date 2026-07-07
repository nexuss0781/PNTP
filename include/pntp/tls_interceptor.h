#ifndef PNTP_TLS_INTERCEPTOR_H
#define PNTP_TLS_INTERCEPTOR_H

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <atomic>
#include <thread>
#include <mutex>

// ── Forward declarations for OpenSSL libcrypto (not libssl) ─────────
typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;
typedef struct evp_md_st EVP_MD;
typedef struct evp_pkey_ctx_st EVP_PKEY_CTX;
typedef struct pkcs7_st PKCS7;

// ── TLS 1.3 Protocol Constants (RFC 8446) ───────────────────────────

enum class ContentType : uint8_t {
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23
};

enum class HandshakeType : uint8_t {
    CLIENT_HELLO        = 1,
    SERVER_HELLO        = 2,
    NEW_SESSION_TICKET  = 4,
    END_OF_EARLY_DATA   = 5,
    ENCRYPTED_EXTENSIONS = 8,
    CERTIFICATE         = 11,
    CERTIFICATE_REQUEST = 13,
    CERTIFICATE_VERIFY  = 15,
    FINISHED            = 20,
    KEY_UPDATE          = 24,
    MESSAGE_HASH        = 254
};

enum class NamedGroup : uint16_t {
    SECP256R1 = 0x0017,
    X25519    = 0x001D
};

enum class CipherSuite : uint16_t {
    TLS_AES_128_GCM_SHA256        = 0x1301,
    TLS_AES_256_GCM_SHA384        = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256  = 0x1303
};

enum class ExtensionType : uint16_t {
    SERVER_NAME              = 0,
    MAX_FRAGMENT_LENGTH      = 1,
    STATUS_REQUEST           = 5,
    SUPPORTED_GROUPS         = 10,
    SIGNATURE_ALGORITHMS     = 13,
    ALPN                     = 16,
    SESSION_TICKET           = 35,
    PRE_SHARED_KEY           = 41,
    EARLY_DATA               = 42,
    SUPPORTED_VERSIONS       = 43,
    COOKIE                   = 44,
    PSK_KEY_EXCHANGE_MODES   = 45,
    CERTIFICATE_AUTHORITIES  = 47,
    OID_FILTERS              = 48,
    POST_HANDSHAKE_AUTH      = 49,
    SIGNATURE_ALGORITHMS_CERT = 50,
    KEY_SHARE                = 51
};

// ── TLS Record Layer ────────────────────────────────────────────────

struct TLSRecord {
    uint8_t type = 0;
    uint16_t version = 0x0303;
    std::vector<uint8_t> payload;
};

// ── Key Structures ──────────────────────────────────────────────────

struct TrafficKey {
    uint8_t key[16] = {};
    uint8_t iv[12]  = {};
    uint64_t seq    = 0;

    bool operator==(const TrafficKey& o) const {
        return seq == o.seq &&
               std::memcmp(key, o.key, 16) == 0 &&
               std::memcmp(iv, o.iv, 12) == 0;
    }
    bool operator!=(const TrafficKey& o) const { return !(*this == o); }
};

struct KeyShareEntry {
    NamedGroup group = NamedGroup::X25519;
    std::vector<uint8_t> key_exchange;
};

struct TrafficLeg {
    TrafficKey read_key;
    TrafficKey write_key;
    int fd = -1;
    bool active = false;
};

// ── Handshake Message Structures ────────────────────────────────────

struct HskClientHello {
    uint16_t version = 0x0303;
    std::vector<uint8_t> random;
    std::vector<uint8_t> session_id;
    std::vector<CipherSuite> cipher_suites;
    std::vector<uint8_t> compression_methods;
    // Parsed extensions
    std::vector<uint8_t> server_name;
    std::vector<NamedGroup> supported_groups;
    std::vector<uint16_t> signature_algorithms;
    std::vector<std::string> alpn;
    KeyShareEntry key_share;
    std::vector<uint16_t> supported_versions;
    std::vector<uint8_t> psk_identity;
    std::vector<uint8_t> psk_binder;
    bool has_psk = false;
    bool psk_mode_ke = false;
    bool psk_mode_dhe = false;
    std::vector<uint8_t> raw_extensions;
};

struct HskServerHello {
    uint16_t version = 0x0303;
    std::vector<uint8_t> random;
    std::vector<uint8_t> session_id;
    CipherSuite cipher_suite = CipherSuite::TLS_AES_128_GCM_SHA256;
    uint8_t compression_method = 0;
    KeyShareEntry key_share;
    uint16_t selected_version = 0x0304;
};

// ── Certificate Entry ───────────────────────────────────────────────

struct CertEntry {
    X509* cert = nullptr;
    EVP_PKEY* key = nullptr;
    std::vector<uint8_t> der;
    uint64_t created_at = 0;
    bool valid = false;
};

// ── Connection State (per MITM session) ─────────────────────────────

struct MITMConnection {
    TrafficLeg client_leg;
    TrafficLeg server_leg;
    int client_fd = -1;
    int server_fd = -1;
    std::string sni_host;
    std::string alpn_protocol;
    CipherSuite negotiated_cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
    bool handshake_done = false;
};

// ── Handshake Internal State ────────────────────────────────────────

struct HandshakeState {
    HskClientHello client_hello;
    HskServerHello server_hello;
    HskServerHello actual_server_hello; // from real server
    std::vector<uint8_t> client_hello_wire;
    std::vector<uint8_t> server_hello_wire;
    std::vector<uint8_t> transcript_hash;
    std::vector<uint8_t> client_leg_transcript;
    std::vector<uint8_t> server_leg_transcript;
    std::vector<uint8_t> handshake_secret;
    std::vector<uint8_t> master_secret;
    TrafficKey client_handshake_key;
    TrafficKey server_handshake_key;
    TrafficKey client_app_key;
    TrafficKey server_app_key;
    TrafficKey server_leg_client_app_key;
    TrafficKey server_leg_server_app_key;
    TrafficKey server_leg_client_hs_key;
    TrafficKey server_leg_server_hs_key;
    EVP_PKEY* mitm_privkey = nullptr;
    std::vector<uint8_t> mitm_pubkey;
    std::vector<uint8_t> server_pubkey;
    EVP_PKEY* mitm_server_privkey = nullptr;
    std::vector<uint8_t> mitm_server_pubkey;
    CipherSuite negotiated_cipher = CipherSuite::TLS_AES_128_GCM_SHA256;
    std::vector<uint8_t> hello_retry_request;
    bool early_data_accepted = false;

    ~HandshakeState() {
        if (mitm_privkey) EVP_PKEY_free(mitm_privkey);
        if (mitm_server_privkey) EVP_PKEY_free(mitm_server_privkey);
    }
};

// ── Session Ticket ──────────────────────────────────────────────────

struct SessionTicket {
    std::vector<uint8_t> ticket;
    uint32_t lifetime = 0;
    uint32_t age_add = 0;
    std::vector<uint8_t> nonce;
    uint64_t created_at = 0;
    std::string domain;
};

// ── TLSInterceptor ──────────────────────────────────────────────────

class TLSInterceptor {
public:
    TLSInterceptor();
    ~TLSInterceptor();

    // Non-copyable
    TLSInterceptor(const TLSInterceptor&) = delete;
    TLSInterceptor& operator=(const TLSInterceptor&) = delete;

    // ── Initialization ─────────────────────────────────────────────
    bool initialize();
    bool isInitialized() const { return ca_cert_ != nullptr; }

    // ── Certificate Management ─────────────────────────────────────
    CertEntry* getOrCreateCert(const std::string& domain);
    X509* getCACert() const { return ca_cert_; }
    EVP_PKEY* getCAKey() const { return ca_key_; }
    void clearCertCache();

    // ── MITM Proxy ─────────────────────────────────────────────────
    bool startProxy(uint16_t listen_port);
    void stopProxy();
    bool isProxyRunning() const { return running_; }
    uint16_t getProxyPort() const { return proxy_port_; }

    // ── Direct TLS Connect (for outbound / DoH) ────────────────────
    // Single-leg TLS connection (not MITM, for fetching through our stack)
    struct TLSConnection {
        int fd = -1;
        TrafficKey read_key;
        TrafficKey write_key;
        std::string alpn;
        bool connected = false;
    };

    // Connect to a TLS server directly (one leg, no MITM)
    // This is used by DNS DoH and TranscendenceEngine for outbound TLS
    std::unique_ptr<TLSConnection> connect(const std::string& host,
                                            uint16_t port,
                                            uint32_t timeout_ms = 5000);
    void disconnect(TLSConnection* conn);

    // ── Data Operations ────────────────────────────────────────────
    // Read application data from a TLS connection (single leg)
    std::vector<uint8_t> readData(TLSConnection* conn, uint32_t timeout_ms = 1000);

    // Write application data to a TLS connection (single leg)
    bool writeData(TLSConnection* conn, const uint8_t* data, size_t len);

    // Bidirectional pump for MITM connections
    void pumpData(MITMConnection& conn);

    // ── NSS Key Log ─────────────────────────────────────────────────
    void setKeyLogPath(const std::string& path);
    void enableKeyLog(bool enable) { keylog_enabled_ = enable; }

    // ── Memory Safety ──────────────────────────────────────────────
    static void clearSensitiveData(TrafficKey& key);
    static void clearSensitiveData(std::vector<uint8_t>& data);
    static bool constantTimeCompare(const uint8_t* a, const uint8_t* b,
                                     size_t len);

    // ── Configuration ──────────────────────────────────────────────
    void setALPNProtocols(const std::vector<std::string>& protos) {
        alpn_protos_ = protos;
    }
    std::vector<std::string> getALPNProtocols() const { return alpn_protos_; }

    void setSessionTimeout(uint32_t seconds) { session_timeout_ = seconds; }
    uint32_t getSessionTimeout() const { return session_timeout_; }

    void setMaxCertCache(size_t max) { max_cert_cache_ = max; }

private:
    // ── Record Layer ───────────────────────────────────────────────
    TLSRecord readRecord(int fd);
    bool writeRecord(int fd, uint8_t type, const uint8_t* data, size_t len);
    bool writeRecordVec(int fd, uint8_t type,
                         const std::vector<std::vector<uint8_t>>& parts);

    std::vector<uint8_t> aeadDecrypt(const TrafficKey& key,
                                      const uint8_t* ciphertext, size_t ct_len);
    std::vector<uint8_t> aeadEncrypt(const TrafficKey& key,
                                      uint8_t type,
                                      const uint8_t* plaintext, size_t pt_len);

    // ── Handshake Parsing ──────────────────────────────────────────
    HskClientHello parseClientHello(const uint8_t* data, size_t len);
    HskServerHello parseServerHello(const uint8_t* data, size_t len);
    std::vector<uint8_t> parseExtensions(const uint8_t* data, size_t len,
                                          HskClientHello& out);
    NamedGroup parseNamedGroup(const uint8_t* data, size_t len);
    KeyShareEntry parseKeyShareEntry(const uint8_t* data, size_t len);
    uint16_t parseUint16(const uint8_t* data, size_t offset);

    // ── Handshake Serialization ────────────────────────────────────
    std::vector<uint8_t> serializeHandshakeHeader(HandshakeType type,
                                                    const uint8_t* body,
                                                    size_t body_len);
    std::vector<uint8_t> serializeServerHello(const HskServerHello& hello);
    std::vector<uint8_t> serializeEncryptedExtensions(const std::string& alpn);
    std::vector<uint8_t> serializeCertificate(const CertEntry& cert,
                                               X509* ca_cert);
    std::vector<uint8_t> serializeCertificateVerify(
        EVP_PKEY* key,
        const std::vector<uint8_t>& transcript_hash,
        CipherSuite suite);
    std::vector<uint8_t> serializeFinished(
        const std::vector<uint8_t>& base_key,
        const std::vector<uint8_t>& transcript_hash,
        CipherSuite suite);
    std::vector<uint8_t> serializeNewSessionTicket(
        const SessionTicket& ticket,
        const TrafficKey& app_key,
        const std::vector<uint8_t>& transcript_hash,
        CipherSuite suite);

    // ── Extension Serialization ────────────────────────────────────
    std::vector<uint8_t> serializeKeyShareExtension(
        const KeyShareEntry& entry);
    std::vector<uint8_t> serializeSupportedVersionsExtension(
        uint16_t version);
    std::vector<uint8_t> serializeALPNExtension(const std::string& proto);

    // ── Key Schedule (RFC 8446 Section 7.1) ────────────────────────
    std::vector<uint8_t> hkdfExtract(const EVP_MD* md,
                                      const std::vector<uint8_t>& salt,
                                      const std::vector<uint8_t>& ikm);
    std::vector<uint8_t> hkdfExpand(const EVP_MD* md,
                                     const std::vector<uint8_t>& prk,
                                     const std::vector<uint8_t>& info,
                                     size_t L);
    std::vector<uint8_t> deriveSecret(const EVP_MD* md,
                                       const std::vector<uint8_t>& secret,
                                       const std::string& label,
                                       const std::vector<uint8_t>& context);
    void deriveTrafficKeys(const std::vector<uint8_t>& secret,
                            const std::string& label,
                            const std::vector<uint8_t>& transcript_hash,
                            TrafficKey& out_key,
                            CipherSuite suite);
    std::vector<uint8_t> computeFinishedVerifyData(
        const std::vector<uint8_t>& base_key,
        const std::vector<uint8_t>& transcript_hash,
        CipherSuite suite);

    // ── Key Exchange ───────────────────────────────────────────────
    EVP_PKEY* generateX25519Keypair();
    std::vector<uint8_t> getPubKeyBytes(EVP_PKEY* pkey);
    std::vector<uint8_t> computeSharedSecret(EVP_PKEY* private_key,
                                              const uint8_t* peer_pub,
                                              size_t peer_pub_len);
    EVP_PKEY* importPeerPublicKey(const uint8_t* data, size_t len,
                                   NamedGroup group);

    // ── Certificate Generation ─────────────────────────────────────
    bool generateCA();
    CertEntry* generateDomainCert(const std::string& domain);

    // ── MITM Handshake ─────────────────────────────────────────────
    bool clientLeg(HandshakeState& state, CertEntry* cert, int client_fd);
    bool serverLeg(HandshakeState& state, const std::string& host,
                    uint16_t port);
    bool completeClientHandshake(HandshakeState& state, int client_fd);
    bool completeServerHandshake(HandshakeState& state, int server_fd);
    void deriveAllKeys(HandshakeState& state);
    std::vector<uint8_t> computeTranscriptHash(
        const std::vector<uint8_t>& messages, CipherSuite suite);

    // ── Proxy listener ─────────────────────────────────────────────
    void acceptLoop();
    void handleConnection(int client_fd);

    // ── Session Management ─────────────────────────────────────────
    void storeSessionTicket(const std::string& domain,
                             const SessionTicket& ticket);
    SessionTicket* findSessionTicket(const std::string& domain);

    // ── Key Logging ────────────────────────────────────────────────
    void writeKeyLogEntry(const std::string& label,
                           const std::vector<uint8_t>& client_random,
                           const std::vector<uint8_t>& secret);

    // ── Helpers ────────────────────────────────────────────────────
    const EVP_MD* selectHash(CipherSuite suite) const;
    size_t hashLength(CipherSuite suite) const;
    std::string cipherSuiteToString(CipherSuite suite) const;
    int createTCPConnection(const std::string& host, uint16_t port,
                             uint32_t timeout_ms);

    // ── Members ────────────────────────────────────────────────────
    X509* ca_cert_ = nullptr;
    EVP_PKEY* ca_key_ = nullptr;
    std::unordered_map<std::string, CertEntry> cert_cache_;
    std::mutex cert_mutex_;
    size_t max_cert_cache_ = 1000;

    int listen_fd_ = -1;
    std::thread accept_thread_;
    std::atomic<bool> running_{false};
    uint16_t proxy_port_ = 0;

    std::vector<std::string> alpn_protos_{"h2", "http/1.1"};
    uint32_t session_timeout_ = 7200; // 2 hours

    bool keylog_enabled_ = false;
    std::string keylog_path_;
    FILE* keylog_file_ = nullptr;
    std::mutex keylog_mutex_;

    std::unordered_map<std::string, SessionTicket> session_tickets_;
    std::mutex session_mutex_;

    // Replay protection for 0-RTT
    std::unordered_map<std::string, uint64_t> replay_cache_;
    std::mutex replay_mutex_;
};

#endif // PNTP_TLS_INTERCEPTOR_H
