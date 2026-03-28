// src/common/json.h
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
};
