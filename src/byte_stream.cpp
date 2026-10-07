#include "pntp/byte_stream.h"
#include "pntp/tcp_engine.h"

#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <cstring>
#include <chrono>
#include <algorithm>

// ── FdByteStream ──────────────────────────────────────────────────────

FdByteStream::FdByteStream(int fd, bool owns_fd)
    : fd_(fd), owns_fd_(owns_fd) {}

FdByteStream::~FdByteStream() {
    close();
}

void FdByteStream::setFd(int fd) {
    close();
    fd_ = fd;
    owns_fd_ = true;
}

ssize_t FdByteStream::read(void* buf, size_t len, uint32_t timeout_ms) {
    if (fd_ < 0) return -1;

    if (timeout_ms > 0) {
        struct timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    ssize_t n = ::read(fd_, buf, len);
    if (n < 0) {
        if (n == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 0;
        return -1;
    }
    return n;
}

bool FdByteStream::write(const void* data, size_t len) {
    if (fd_ < 0) return false;
    size_t total_written = 0;
    while (total_written < len) {
        ssize_t n = ::write(fd_,
                            static_cast<const uint8_t*>(data) + total_written,
                            len - total_written);
        if (n <= 0) return false;
        total_written += static_cast<size_t>(n);
    }
    return true;
}

void FdByteStream::close() {
    if (owns_fd_ && fd_ >= 0) {
        ::close(fd_);
    }
    fd_ = -1;
    owns_fd_ = false;
}

bool FdByteStream::isOpen() const {
    return fd_ >= 0;
}

// ── RawTCPByteStream ──────────────────────────────────────────────────

RawTCPByteStream::RawTCPByteStream(TCPEngine* engine, TCPConnection* conn,
                                   bool owns_conn)
    : engine_(engine), conn_(conn), owns_conn_(owns_conn) {
    buffer_.reserve(16384 + 256);
}

RawTCPByteStream::~RawTCPByteStream() {
    close();
}

void RawTCPByteStream::bind(TCPEngine* engine, TCPConnection* conn,
                            bool owns_conn) {
    engine_ = engine;
    conn_ = conn;
    owns_conn_ = owns_conn;
    buffer_.clear();
    buffer_pos_ = 0;
}

ssize_t RawTCPByteStream::read(void* buf, size_t len, uint32_t timeout_ms) {
    uint8_t* out = static_cast<uint8_t*>(buf);
    size_t filled = 0;

    if (buffer_pos_ < buffer_.size()) {
        size_t avail = buffer_.size() - buffer_pos_;
        size_t n = std::min(len, avail);
        std::memcpy(out, buffer_.data() + buffer_pos_, n);
        buffer_pos_ += n;
        filled += n;
        if (filled == len || buffer_pos_ == buffer_.size()) {
            if (buffer_pos_ == buffer_.size()) {
                buffer_.clear();
                buffer_pos_ = 0;
            }
            return static_cast<ssize_t>(filled);
        }
    }

    if (!engine_ || !conn_) {
        return filled > 0 ? static_cast<ssize_t>(filled) : -1;
    }
    if (conn_->state == TCPState::CLOSED ||
        conn_->state == TCPState::CLOSE_WAIT) {
        return filled > 0 ? static_cast<ssize_t>(filled) : 0;
    }

    auto start = std::chrono::steady_clock::now();
    uint32_t budget_ms = timeout_ms > 0 ? timeout_ms : 30000;

    while (filled < len) {
        ReceiveResult result = engine_->recv(conn_, 50);
        if (result.error) break;
        if (result.closed) break;
        if (result.valid && !result.data.empty()) {
            buffer_.insert(buffer_.end(), result.data.begin(), result.data.end());
            size_t avail = buffer_.size() - buffer_pos_;
            size_t n = std::min(len - filled, avail);
            std::memcpy(out + filled, buffer_.data() + buffer_pos_, n);
            buffer_pos_ += n;
            filled += n;
            if (filled == len) break;
            continue;
        }

        if (timeout_ms > 0) {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               now - start).count();
            if (static_cast<uint32_t>(elapsed) >= budget_ms) break;
        } else {
            auto now = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                               now - start).count();
            if (elapsed >= 30000) break;
        }
    }

    if (buffer_pos_ == buffer_.size()) {
        buffer_.clear();
        buffer_pos_ = 0;
    }
    return static_cast<ssize_t>(filled);
}

bool RawTCPByteStream::write(const void* data, size_t len) {
    if (!engine_ || !conn_) return false;
    if (len == 0) return true;
    return engine_->send(conn_, static_cast<const uint8_t*>(data), len);
}

void RawTCPByteStream::close() {
    if (owns_conn_ && engine_ && conn_) {
        engine_->close(conn_);
    }
    conn_ = nullptr;
    engine_ = nullptr;
    buffer_.clear();
    buffer_pos_ = 0;
}

bool RawTCPByteStream::isOpen() const {
    return conn_ != nullptr;
}