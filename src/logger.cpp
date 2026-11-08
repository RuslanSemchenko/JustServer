#include "logger.hpp"
#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>

namespace js {

namespace {

// Maximum number of characters of a single log message that is written out
// (after escaping). Longer messages are cut and marked as truncated, so a
// client cannot flood the log with huge URIs / headers.
constexpr std::size_t kMaxLogMessageChars = 2048;

// Makes an arbitrary (possibly attacker-controlled) message safe to write to a
// log file or a terminal:
//   - printable ASCII (0x20..0x7E) is kept as is, except the backslash;
//   - the backslash is written as "\\" so that an escaped sequence can never be
//     confused with literal text coming from the input;
//   - every other byte (control characters such as ESC, CR, LF, NUL, DEL, and
//     all bytes >= 0x80) is written as "\xNN".
// This prevents log forging (CWE-117) and terminal escape sequence injection.
std::string sanitize_for_log(std::string_view s) {
    static constexpr char kHex[] = "0123456789abcdef";
    static constexpr std::string_view kTruncated = "...[truncated]";

    std::string out;
    out.reserve(std::min(s.size(), kMaxLogMessageChars) + kTruncated.size());

    for (unsigned char c : s) {
        std::size_t need = 1;
        if (c == '\\') {
            need = 2;
        } else if (c < 0x20 || c >= 0x7F) {
            need = 4;
        }

        if (out.size() + need > kMaxLogMessageChars) {
            out += kTruncated;
            break;
        }

        if (c == '\\') {
            out += "\\\\";
        } else if (c >= 0x20 && c < 0x7F) {
            out += static_cast<char>(c);
        } else {
            out += "\\x";
            out += kHex[c >> 4];
            out += kHex[c & 0x0F];
        }
    }
    return out;
}

} // namespace

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

void Logger::set_level(LogLevel level) {
    level_ = level;
}

void Logger::set_level(std::string_view level_str) {
    if (level_str == "debug") level_ = LogLevel::DEBUG;
    else if (level_str == "info") level_ = LogLevel::INFO;
    else if (level_str == "warn") level_ = LogLevel::WARN;
    else if (level_str == "error") level_ = LogLevel::ERROR;
}

void Logger::debug(std::string_view msg) {
    log(LogLevel::DEBUG, "DEBUG", msg);
}

void Logger::info(std::string_view msg) {
    log(LogLevel::INFO, "INFO", msg);
}

void Logger::warn(std::string_view msg) {
    log(LogLevel::WARN, "WARN", msg);
}

void Logger::error(std::string_view msg) {
    log(LogLevel::ERROR, "ERROR", msg);
}

void Logger::log(LogLevel level, std::string_view prefix, std::string_view msg) {
    if (static_cast<int>(level) < static_cast<int>(level_)) return;

    auto now = std::chrono::system_clock::now();
    auto time_t_now = std::chrono::system_clock::to_time_t(now);
    struct tm tm_buf{};
    localtime_r(&time_t_now, &tm_buf);

    char time_str[64];
    std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm_buf);

    // Sanitize before taking the lock to keep the critical section short.
    const std::string safe_msg = sanitize_for_log(msg);

    std::lock_guard lock(mutex_);
    std::fprintf(stderr, "[%s] [%.*s] %.*s\n",
        time_str,
        static_cast<int>(prefix.size()), prefix.data(),
        static_cast<int>(safe_msg.size()), safe_msg.data());
}

} // namespace js
