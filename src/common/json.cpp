// src/common/json.cpp
#include <string>

#include "Utility.h"
#include "json.h"

// Dump JSON to UTF-8 string with fallback on invalid UTF-8
std::string JSON::dump(const nlohmann::json &j, int indent, bool sanitizeUTF8)
{
    try
    {
        if (sanitizeUTF8)
        {
            return j.dump(indent, ' ', false, nlohmann::json::error_handler_t::replace);
        }
        else
        {
            return j.dump(indent);
        }
    }
    catch (const nlohmann::json::exception &e)
    {
        LOG_ERR << "JSON dump failed: " << e.what() << " (id: " << e.id << ")";

        // If caller didn't ask for sanitization try again with replacement
        if (!sanitizeUTF8)
        {
            try
            {
                LOG_ERR << "Retrying with UTF-8 sanitization...";
                return j.dump(indent, ' ', false, nlohmann::json::error_handler_t::replace);
            }
            catch (...)
            {
                LOG_ERR << "Fallback also failed, returning empty JSON";
                return "{}";
            }
        }
        throw;
    }
}

// Dump JSON converted to the current ANSI code page on Windows (CP_ACP).
// For POSIX platforms this returns the UTF-8 string unchanged.
std::string JSON::dumpToLocalEncoding(const nlohmann::json &j, int indent)
{
    const std::string utf8Str = JSON::dump(j, indent);
    return Utility::utf8ToLocalEncoding(utf8Str);
}
