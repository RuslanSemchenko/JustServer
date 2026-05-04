#pragma once

#include <string_view>
#include <cstdio>
#include <chrono>
#include <ctime>
#include <mutex>

namespace js {

enum class LogLevel : int {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
};

class Logger {
public:
    static Logger& instance();

    void set_level(LogLevel level);
    void set_level(std::string_view level_str);

    void debug(std::string_view msg);
    void info(std::string_view msg);
    void warn(std::string_view msg);
    void error(std::string_view msg);

private:
    Logger() = default;
    void log(LogLevel level, std::string_view prefix, std::string_view msg);

    LogLevel level_ = LogLevel::INFO;
    std::mutex mutex_;
};

// Convenience macros
#define LOG_DEBUG(msg) js::Logger::instance().debug(msg)
#define LOG_INFO(msg)  js::Logger::instance().info(msg)
#define LOG_WARN(msg)  js::Logger::instance().warn(msg)
#define LOG_ERROR(msg) js::Logger::instance().error(msg)

} // namespace js
