#pragma once

#include <cmath>
#include <memory>
#include <string>
#include <vector>

#if defined(WIN32)
#include <windows.h>
#endif

#include "Utility.h"

// --- Small note ---
// This file extends the existing JSON helpers to add robust UTF-8 <-> wide
// string conversions and a convenience dump that returns either UTF-8,
// a wide string (UTF-16 on Windows), or a string converted to the current
// ANSI code page (useful when writing to legacy Windows consoles/loggers).

struct JSONErrorContext
{
    std::string path;
    std::string value;
    std::string details;
};

class JSONValidator
{
public:
    // Validate UTF-8 sequence for overlong encodings and invalid code points
    static bool isValidUTF8Sequence(const unsigned char *bytes, size_t length) noexcept
    {
        if (!bytes || length == 0 || length > 4)
            return false;

        uint32_t codePoint = 0;

        // Validate based on sequence length
        switch (length)
        {
        case 1:
            // ASCII (0x00-0x7F)
            return bytes[0] <= 0x7F;

        case 2:
            // 2-byte sequence: 110xxxxx 10xxxxxx
            if ((bytes[0] & 0xE0) != 0xC0 || (bytes[1] & 0xC0) != 0x80)
                return false;
            codePoint = ((bytes[0] & 0x1F) << 6) | (bytes[1] & 0x3F);
            // Check for overlong encoding (must be >= 0x80)
            return codePoint >= 0x80 && codePoint <= 0x7FF;
        case 3:
            // 3-byte sequence: 1110xxxx 10xxxxxx 10xxxxxx
            if ((bytes[0] & 0xF0) != 0xE0 || (bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80)
                return false;
            codePoint = ((bytes[0] & 0x0F) << 12) | ((bytes[1] & 0x3F) << 6) | (bytes[2] & 0x3F);
            // Check for overlong encoding and surrogates (U+D800-U+DFFF are invalid)
            return codePoint >= 0x800 && codePoint <= 0xFFFF && (codePoint < 0xD800 || codePoint > 0xDFFF);
        case 4:
            // 4-byte sequence: 11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
            if ((bytes[0] & 0xF8) != 0xF0 || (bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80 || (bytes[3] & 0xC0) != 0x80)
                return false;
            codePoint = ((bytes[0] & 0x07) << 18) | ((bytes[1] & 0x3F) << 12) | ((bytes[2] & 0x3F) << 6) | (bytes[3] & 0x3F);
            // Check for overlong encoding and maximum valid Unicode (U+10FFFF)
            return codePoint >= 0x10000 && codePoint <= 0x10FFFF;

        default:
            return false;
        }
    }

    // Find and log errors in the JSON object
    static void findErrors(const nlohmann::json &j, std::vector<JSONErrorContext> &errors, const std::string &path = "") noexcept
    {
        try
        {
            if (j.is_object())
            {
                validateObject(j, errors, path);
            }
            else if (j.is_array())
            {
                validateArray(j, errors, path);
            }
            else if (j.is_string())
            {
                validateString(j, errors, path);
            }
            else if (j.is_number())
            {
                validateNumber(j, errors, path);
            }
        }
        catch (const std::exception &e)
        {
            errors.emplace_back(JSONErrorContext{path, "", std::string("Validation error: ") + e.what()});
        }
    }

    // Report collected JSON errors
    static void reportErrors(const std::vector<JSONErrorContext> &errors) noexcept
    {
        if (!errors.empty())
        {
            LOG_ERR << "Found JSON validation issues:";
            for (const auto &error : errors)
            {
                LOG_ERR << "  Path: " << (error.path.empty() ? "<root>" : error.path);
                if (!error.value.empty())
                    LOG_ERR << "  Value: " << error.value;
                LOG_ERR << "  Details: " << error.details;
            }
        }
    }

private:
    // Validate JSON object
    static void validateObject(const nlohmann::json &j, std::vector<JSONErrorContext> &errors, const std::string &path) noexcept
    {
        for (auto it = j.begin(); it != j.end(); ++it)
        {
            try
            {
                std::string newPath = path.empty() ? it.key() : path + "." + it.key();
                findErrors(it.value(), errors, newPath);
            }
            catch (const std::exception &e)
            {
                errors.emplace_back(JSONErrorContext{path, it.key(), e.what()});
            }
        }
    }

    // Validate JSON array
    static void validateArray(const nlohmann::json &j, std::vector<JSONErrorContext> &errors, const std::string &path) noexcept
    {
        for (size_t i = 0; i < j.size(); ++i)
        {
            try
            {
                findErrors(j[i], errors, path + "[" + std::to_string(i) + "]");
            }
            catch (const std::exception &e)
            {
                errors.emplace_back(JSONErrorContext{path + "[" + std::to_string(i) + "]", "array_element", e.what()});
            }
        }
    }

    // Validate JSON string with comprehensive UTF-8 validation
    static void validateString(const nlohmann::json &j, std::vector<JSONErrorContext> &errors, const std::string &path) noexcept
    {
        try
        {
            const std::string &value = j.get<std::string>();
            const unsigned char *bytes = reinterpret_cast<const unsigned char *>(value.data());
            size_t len = value.length();

            for (size_t i = 0; i < len;)
            {
                // ASCII characters
                if (bytes[i] <= 0x7F)
                {
                    i++;
                    continue;
                }

                // Multi-byte UTF-8 sequence
                size_t sequenceLen = 0;
                if ((bytes[i] & 0xE0) == 0xC0)
                    sequenceLen = 2;
                else if ((bytes[i] & 0xF0) == 0xE0)
                    sequenceLen = 3;
                else if ((bytes[i] & 0xF8) == 0xF0)
                    sequenceLen = 4;
                else
                {
                    errors.emplace_back(JSONErrorContext{path, "", "Invalid UTF-8 leading byte at position " + std::to_string(i)});
                    return;
                }

                // Check bounds
                if (i + sequenceLen > len)
                {
                    errors.emplace_back(JSONErrorContext{path, "", "Incomplete UTF-8 sequence at position " + std::to_string(i)});
                    return;
                }

                // Validate the complete sequence using the comprehensive validator
                if (!isValidUTF8Sequence(bytes + i, sequenceLen))
                {
                    errors.emplace_back(JSONErrorContext{path, "", "Invalid UTF-8 sequence at position " + std::to_string(i)});
                    return;
                }

                i += sequenceLen;
            }
        }
        catch (const std::exception &e)
        {
            errors.emplace_back(JSONErrorContext{path, "", std::string("String validation error: ") + e.what()});
        }
    }

    // Validate JSON number
    static void validateNumber(const nlohmann::json &j, std::vector<JSONErrorContext> &errors, const std::string &path) noexcept
    {
        try
        {
            if (j.is_number_float())
            {
                double value = j.get<double>();
                if (std::isinf(value) || std::isnan(value))
                {
                    errors.emplace_back(JSONErrorContext{path, j.dump(), "Invalid floating-point value (inf or nan)"});
                }
            }
        }
        catch (const std::exception &e)
        {
            errors.emplace_back(JSONErrorContext{path, "", std::string("Number validation error: ") + e.what()});
        }
    }
};

class JSON
{
public:
    // Original dump returning UTF-8 std::string (nlohmann::json stores strings as UTF-8)
    static std::string dump(const nlohmann::json &j, int indent = -1, bool sanitizeUTF8 = false)
    {
        try
        {
            // Use error_handler::replace to handle invalid UTF-8 sequences
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

            // Attempt validation to identify specific issues
            std::vector<JSONErrorContext> errors;
            JSONValidator::findErrors(j, errors);
            JSONValidator::reportErrors(errors);

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

    // Return a string converted to the current ANSI code page on Windows (CP_ACP).
    // For POSIX platforms this returns the UTF-8 string unchanged. This is
    // intended for legacy consoles / loggers which don't interpret UTF-8.
    static std::string dumpToLocalCP(const nlohmann::json &j, int indent = -1, bool ensure_ascii = false)
    {
        const std::string utf8Str = j.dump(indent, ' ', ensure_ascii);
#if defined(WIN32)
        // UTF-8 -> UTF-16 (explicit size, no trailing NUL in count)
        if (utf8Str.empty())
            return std::string();

        int wideLen = MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), static_cast<int>(utf8Str.size()), nullptr, 0);
        if (wideLen <= 0)
            return utf8Str; // fallback to UTF-8 on failure

        std::wstring wideStr(wideLen, L'\0');
        if (MultiByteToWideChar(CP_UTF8, 0, utf8Str.data(), static_cast<int>(utf8Str.size()), wideStr.data(), wideLen) <= 0)
            return utf8Str;

        // Choose target code page: console CP if available, else ACP
        UINT cp = GetConsoleOutputCP();
        if (cp == 0)
            cp = CP_ACP;

        // UTF-16 -> target CP
        int ansiLen = WideCharToMultiByte(cp, 0, wideStr.data(), static_cast<int>(wideStr.size()), nullptr, 0, nullptr, nullptr);
        if (ansiLen <= 0)
            return utf8Str;

        std::string ansiStr(ansiLen, '\0');
        if (WideCharToMultiByte(cp, 0, wideStr.data(), static_cast<int>(wideStr.size()), ansiStr.data(), ansiLen, nullptr, nullptr) <= 0)
            return utf8Str;

        return ansiStr;
#else
        // POSIX: consoles are UTF-8; return as-is
        return utf8Str;
#endif
    }

    // Parsing helpers (unchanged behavior) — note: these forward to nlohmann::json::parse
    static nlohmann::json parse(const std::string &input, bool allowExceptions = true)
    {
        try
        {
            return nlohmann::json::parse(input);
        }
        catch (const nlohmann::json::parse_error &e)
        {
            LOG_ERR << "JSON parse error at byte " << e.byte << ": " << e.what();
            logParseError(input, e);

            if (allowExceptions)
                throw;

            return nlohmann::json();
        }
    }

    // Parse with iterator range
    template <typename IteratorType>
    static nlohmann::json parse(IteratorType first, IteratorType last, bool allowExceptions = true)
    {
        try
        {
            return nlohmann::json::parse(first, last);
        }
        catch (const nlohmann::json::parse_error &e)
        {
            std::string context;
            try
            {
                auto distance = std::distance(first, last);
                context = std::string(first, (distance > 100 ? first + 100 : last));
            }
            catch (...)
            { /* best-effort */
            }
            LOG_ERR << "JSON parse error: " << e.what();
            LOG_ERR << "Context: " << context;

            if (allowExceptions)
                throw;

            return nlohmann::json();
        }
    }

private:
    // Log parse error with context
    static void logParseError(const std::string &input, const nlohmann::json::parse_error &e) noexcept
    {
        // Log error type
        switch (e.id)
        {
        case 101:
            LOG_ERR << "Error type: Unexpected end of input";
            break;
        case 102:
            LOG_ERR << "Error type: Unexpected token";
            break;
        case 103:
            LOG_ERR << "Error type: Invalid literal";
            break;
        case 104:
            LOG_ERR << "Error type: Value separator expected";
            break;
        case 105:
            LOG_ERR << "Error type: Object separator expected";
            break;
        case 106:
            LOG_ERR << "Error type: Expected value";
            break;
        case 107:
            LOG_ERR << "Error type: Expected end of input";
            break;
        case 108:
            LOG_ERR << "Error type: Unexpected character";
            break;
        case 109:
            LOG_ERR << "Error type: Number overflow";
            break;
        case 110:
            LOG_ERR << "Error type: Invalid number";
            break;
        case 111:
            LOG_ERR << "Error type: Invalid unicode escape";
            break;
        case 112:
            LOG_ERR << "Error type: Invalid UTF-8 string";
            break;
        case 113:
            LOG_ERR << "Error type: Unescaped control character";
            break;
        case 316:
            LOG_ERR << "Error type: Invalid UTF-8 byte sequence";
            break;
        default:
            LOG_ERR << "Error type: Unknown (id: " << e.id << ")";
            break;
        }

        // Show error context if possible
        if (e.byte <= input.length())
        {
            size_t contextStart = (e.byte > 30) ? e.byte - 30 : 0;
            size_t contextEnd = std::min(e.byte + 30, input.length());

            if (contextStart < contextEnd)
            {
                std::string context = input.substr(contextStart, contextEnd - contextStart);
                LOG_ERR << "Context: \"" << context << "\"";
                if (e.byte >= contextStart)
                {
                    LOG_ERR << " " << std::string(e.byte - contextStart, ' ') << "^-- error here";
                }
            }
        }

        // Try partial parse for additional validation
        try
        {
            auto partialJson = nlohmann::json::parse(input, nullptr, false);
            if (!partialJson.is_discarded())
            {
                std::vector<JSONErrorContext> errors;
                JSONValidator::findErrors(partialJson, errors);
                if (!errors.empty())
                {
                    LOG_ERR << "Additional validation issues found:";
                    JSONValidator::reportErrors(errors);
                }
            }
        }
        catch (...)
        { /* ignore */
        }
    }

public:
    // --- Conversions ---
    static std::string ansiToUtf8(const std::string &ansi)
    {
#if defined(WIN32)
        // Windows: ANSI → UTF-8
        if (ansi.empty())
            return {};

        int wideLen = MultiByteToWideChar(CP_ACP, 0, ansi.data(), static_cast<int>(ansi.size()), nullptr, 0);
        if (wideLen <= 0)
            return {};

        std::wstring wideStr(wideLen, L'\0');
        MultiByteToWideChar(CP_ACP, 0, ansi.data(), static_cast<int>(ansi.size()), wideStr.data(), wideLen);

        int utf8Len = WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), wideLen, nullptr, 0, nullptr, nullptr);
        if (utf8Len <= 0)
            return {};

        std::string utf8Str(utf8Len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wideStr.data(), wideLen, utf8Str.data(), utf8Len, nullptr, nullptr);

        return utf8Str;
#else
        // POSIX: already UTF-8
        return ansi;
#endif
    }
};
