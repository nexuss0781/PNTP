#ifndef PNTP_LOG_H
#define PNTP_LOG_H

#include <iostream>
#include <cstdio>

namespace pntp {
namespace log {

enum class Level : uint8_t {
    TRACE = 0,
    DEBUG = 1,
    INFO  = 2,
    WARN  = 3,
    ERROR = 4,
    FATAL = 5
};

const char* levelToString(Level l) {
    switch (l) {
        case Level::TRACE: return "TRACE";
        case Level::DEBUG: return "DEBUG";
        case Level::INFO:  return "INFO";
        case Level::WARN:  return "WARN";
        case Level::ERROR: return "ERROR";
        case Level::FATAL: return "FATAL";
        default:           return "UNKNOWN";
    }
}

inline void write(Level l, const char* module, const char* msg) {
    std::cout << "[" << levelToString(l) << "][" << module << "] " << msg << std::endl;
}

} // namespace log
} // namespace pntp

// Phase 0 stub macros — will be replaced by real lockless logging in Phase 14
#define PNTP_LOG(level, module, msg) \
    pntp::log::write(pntp::log::Level::level, module, msg)

#define PNTP_DEBUG(module, msg)  PNTP_LOG(DEBUG, module, msg)
#define PNTP_INFO(module, msg)   PNTP_LOG(INFO,  module, msg)
#define PNTP_WARN(module, msg)   PNTP_LOG(WARN,  module, msg)
#define PNTP_ERROR(module, msg)  PNTP_LOG(ERROR, module, msg)

// Stream-style logging (Phase 0 compatibility)
#define PNTP_LOG_STREAM(level, module) \
    std::cout << "[" << pntp::log::levelToString(pntp::log::Level::level) << "][" << module << "] "

#endif // PNTP_LOG_H
