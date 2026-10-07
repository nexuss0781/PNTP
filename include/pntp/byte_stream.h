#ifndef PNTP_BYTE_STREAM_H
#define PNTP_BYTE_STREAM_H

#include <cstddef>
#include <cstdint>
#include <vector>
#include <sys/types.h>

class TCPEngine;
struct TCPConnection;

// Abstract bidirectional byte transport used by the TLS record layer.
// Both the POSIX-fd path (DoH/MITM) and the raw-socket TCP path
// (TranscendenceEngine) are exposed as a ByteStream so the TLS 1.3
// handshake and application-data path are transport-agnostic.
class ByteStream {
public:
    virtual ~ByteStream() = default;

    // Read up to len bytes. Returns the number of bytes read (> 0 on
    // data), 0 on orderly EOF or timeout, or -1 on error. The stream
    // blocks until at least one byte is available or timeout_ms elapses
    // (timeout_ms == 0 disables the timeout and blocks indefinitely).
    virtual ssize_t read(void* buf, size_t len, uint32_t timeout_ms = 0) = 0;

    // Write all bytes. Returns false on failure.
    virtual bool write(const void* data, size_t len) = 0;

    // Close/release the underlying connection.
    virtual void close() = 0;

    // True while the underlying connection is usable.
    virtual bool isOpen() const = 0;

    // ByteStream is non-copyable (owns a transport).
    ByteStream(const ByteStream&) = delete;
    ByteStream& operator=(const ByteStream&) = delete;

protected:
    ByteStream() = default;
};

// ByteStream over a plain POSIX file descriptor (::read / ::write).
class FdByteStream : public ByteStream {
public:
    // If owns_fd is true the stream closes the fd on close()/destruction.
    // Owned fds must have been created with a dup()'d descriptor (or be
    // otherwise safe to close); wrapping an already-owned fd with
    // owns_fd=false leaves the fd untouched for the caller.
    explicit FdByteStream(int fd, bool owns_fd = true);
    ~FdByteStream() override;

    ssize_t read(void* buf, size_t len, uint32_t timeout_ms = 0) override;
    bool write(const void* data, size_t len) override;
    void close() override;
    bool isOpen() const override;

    void setFd(int fd);

private:
    int fd_;
    bool owns_fd_;
};

// ByteStream over the native raw-socket TCP engine. Recv chunks are
// buffered so TLS record reads (header + payload) are satisfied
// without losing framing.
class RawTCPByteStream : public ByteStream {
public:
    RawTCPByteStream() = default;
    // owns_conn=true: close() closes the TCP connection through the
    // engine. owns_conn=false: close() only detaches, leaving the
    // connection open for a caller that owns it (transcendFetch).
    RawTCPByteStream(TCPEngine* engine, TCPConnection* conn,
                     bool owns_conn = true);
    ~RawTCPByteStream() override;

    virtual ssize_t read(void* buf, size_t len, uint32_t timeout_ms = 0) override;
    virtual bool write(const void* data, size_t len) override;
    virtual void close() override;
    virtual bool isOpen() const override;

    void bind(TCPEngine* engine, TCPConnection* conn, bool owns_conn = true);

protected:
    TCPEngine* engine_ = nullptr;
    TCPConnection* conn_ = nullptr;
    bool owns_conn_ = true;
    std::vector<uint8_t> buffer_;
    size_t buffer_pos_ = 0;
};

#endif // PNTP_BYTE_STREAM_H