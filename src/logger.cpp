#include "logger.hpp"
#include <cstring>
#include <algorithm>

namespace js {

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

    std::lock_guard lock(mutex_);
    std::fprintf(stderr, "[%s] [%.*s] %.*s\n",
        time_str,
        static_cast<int>(prefix.size()), prefix.data(),
        static_cast<int>(msg.size()), msg.data());
}

} // namespace js
