// src/common/StreamLogger.h
#pragma once

#include <spdlog/spdlog.h>
#include <sstream>

class StreamLogger
{
private:
    spdlog::level::level_enum lvl_;
    spdlog::source_loc loc_;
    std::ostringstream oss_;

public:
    // We pass source location to capture where the macro was called
    StreamLogger(spdlog::level::level_enum lvl, spdlog::source_loc loc)
        : lvl_(lvl), loc_(loc) {}

    // Destructor performs the actual logging
    ~StreamLogger()
    {
        // spdlog::log accepts source_loc to print correct filename/line number
        spdlog::log(loc_, lvl_, oss_.str());
    }

    // Template operator<< to handle all types
    template <typename T>
    StreamLogger &operator<<(const T &val)
    {
        oss_ << val;
        return *this;
    }
};

// HELPER: Use a Voidify class to handle the ternary operator syntax safely
// This allows the macro to work inside if/else blocks without braces.
class LogVoidify
{
public:
    void operator&(std::ostream &) {}
    void operator&(const StreamLogger &) {}
};

#define LOG_STREAM(level) \
    !(spdlog::should_log(level)) ? (void)0 : LogVoidify() & StreamLogger(level, spdlog::source_loc{__FILE__, __LINE__, SPDLOG_FUNCTION})

// 3. User Macros
#define LOG_DBG LOG_STREAM(spdlog::level::debug)
#define LOG_INF LOG_STREAM(spdlog::level::info)
#define LOG_WAR LOG_STREAM(spdlog::level::warn)
#define LOG_ERR LOG_STREAM(spdlog::level::err)
#define LOG_CRT LOG_STREAM(spdlog::level::critical)
