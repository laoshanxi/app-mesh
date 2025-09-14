#pragma once

#include <nlohmann/json.hpp>
#include <string>

class JSON
{
public:
    // Dump JSON to UTF-8 string with optional sanitization
    static std::string dump(const nlohmann::json &j, int indent = -1, bool sanitizeUTF8 = false);

    // Dump JSON to local encoding (Windows CP_ACP or UTF-8 on POSIX)
    static std::string dumpToLocalEncoding(const nlohmann::json &j, int indent = -1);

    // Parse JSON from string
    static nlohmann::json parse(const std::string &input, bool allowExceptions = true);

    // Parse JSON from iterator range
    template <typename IteratorType>
    static nlohmann::json parse(IteratorType first, IteratorType last, bool allowExceptions = true);

private:
    // Log detailed parse error information
    static void logParseError(const std::string &input, const nlohmann::json::parse_error &e) noexcept;
};