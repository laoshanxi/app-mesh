#pragma once
#include <iomanip>
#include <nlohmann/json.hpp>
#include <sstream>

#include "Utility.h"

struct JSONErrorContext
{
    std::string path;
    std::string value;
    std::string details;
};

class JSONValidator
{
public:
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
            errors.emplace_back(JSONErrorContext{path, j.dump(), e.what()});
        }
    }

    // Report collected JSON errors
    static void reportErrors(const std::vector<JSONErrorContext> &errors) noexcept
    {
        if (!errors.empty())
        {
            LOG_ERR << "Found the following issues:";
            for (const auto &error : errors)
            {
                LOG_ERR << "Path: " << error.path;
                if (!error.value.empty())
                {
                    // Truncate very long values
                    std::string displayValue = (error.value.length() > 100) ? error.value.substr(0, 97) + "..." : error.value;
                    LOG_ERR << "Value: " << displayValue;
                }
                LOG_ERR << "Details: " << error.details;
                LOG_ERR << "---";
            }
        }
        else
        {
            LOG_ERR << "No specific issues found during validation. The error might be in the overall structure.";
        }
    }

    // Get a summary of JSON errors
    static std::string getErrorSummary(const std::vector<JSONErrorContext> &errors) noexcept
    {
        std::ostringstream oss;
        if (!errors.empty())
        {
            oss << "Found " << errors.size() << " issue(s):\n";
            for (const auto &error : errors)
            {
                oss << "Path: " << error.path << "\n";
                oss << "Details: " << error.details << "\n";
                oss << "---\n";
            }
        }
        else
        {
            oss << "No specific issues found during validation.";
        }
        return oss.str();
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

    // Validate JSON string
    static void validateString(const nlohmann::json &j, std::vector<JSONErrorContext> &errors, const std::string &path) noexcept
    {
        const std::string &value = j.get<std::string>();
        // Check for UTF-8 validity
        const unsigned char *bytes = reinterpret_cast<const unsigned char *>(value.data());
        size_t len = value.length();

        for (size_t i = 0; i < len; i++)
        {
            if (bytes[i] <= 0x7F)
                continue;

            size_t extraBytes = 0;
            if ((bytes[i] & 0xE0) == 0xC0)
                extraBytes = 1;
            else if ((bytes[i] & 0xF0) == 0xE0)
                extraBytes = 2;
            else if ((bytes[i] & 0xF8) == 0xF0)
                extraBytes = 3;

            if (extraBytes == 0 || i + extraBytes >= len)
            {
                std::ostringstream hexDump;
                size_t contextStart = (i > 8) ? i - 8 : 0;
                size_t contextEnd = std::min(i + 8, len);

                for (size_t pos = contextStart; pos < contextEnd; pos++)
                {
                    if (pos == i)
                        hexDump << "[";
                    hexDump << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(bytes[pos]);
                    if (pos == i)
                        hexDump << "]";
                    hexDump << " ";
                }

                errors.emplace_back(JSONErrorContext{path, value, "Invalid UTF-8 sequence at position " + std::to_string(i) + " (hex: " + hexDump.str() + ")"});
                break;
            }

            for (size_t j = 1; j <= extraBytes; j++)
            {
                if ((bytes[i + j] & 0xC0) != 0x80)
                {
                    errors.emplace_back(JSONErrorContext{path, value, "Invalid UTF-8 continuation byte at position " + std::to_string(i + j)});
                    i = len; // Break outer loop
                    break;
                }
            }
            i += extraBytes;
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
            errors.emplace_back(JSONErrorContext{path, j.dump(), e.what()});
        }
    }
};

class JSON
{
public:
    // Wrapper for nlohmann::json::dump to catch exceptions and log error information
    static std::string dump(const nlohmann::json &j, int indent = -1)
    {
        try
        {
            // Attempt to dump the JSON object
            return j.dump(indent);
        }
        catch (const nlohmann::json::exception &e)
        {
            LOG_ERR << "JSON exception during dump: " << e.what();
            handleJsonDumpException(j, e);
            throw;
        }
        catch (const std::exception &e)
        {
            LOG_ERR << "Unexpected error during dump: " << e.what();
            throw;
        }
    }

    // Wrapper for nlohmann::json::parse to catch exceptions and log error information
    static nlohmann::json parse(const std::string &input)
    {
        try
        {
            return nlohmann::json::parse(input);
        }
        catch (const nlohmann::json::parse_error &e)
        {
            LOG_ERR << "JSON parse error: " << e.what();
            handleJsonParseException(input, e);
            throw;
        }
        catch (const std::exception &e)
        {
            LOG_ERR << "Unexpected error during parse: " << e.what();
            throw;
        }
    }

private:
    // Handle JSON dump exceptions
    static void handleJsonDumpException(const nlohmann::json &j, const nlohmann::json::exception &e) noexcept
    {
        std::vector<JSONErrorContext> errors;
        try
        {
            JSONValidator::findErrors(j, errors);
            JSONValidator::reportErrors(errors);

            if (j.is_object() && j.empty())
            {
                LOG_ERR << "Warning: Empty JSON object";
            }
            if (j.is_array() && j.empty())
            {
                LOG_ERR << "Warning: Empty JSON array";
            }
        }
        catch (const std::exception &validationError)
        {
            LOG_ERR << "Error during validation: " << validationError.what();
        }

        logSpecificErrorType(e.id);
    }

    // Handle JSON parse exceptions
    static void handleJsonParseException(const std::string &input, const nlohmann::json::parse_error &e) noexcept
    {
        LOG_ERR << "Error details:";
        LOG_ERR << " Message: " << e.what();
        LOG_ERR << " Exception id: " << e.id;
        LOG_ERR << " Byte position of error: " << e.byte;

        // Print the context around the error
        size_t contextStart = e.byte > 20 ? e.byte - 20 : 0;
        size_t contextEnd = std::min(e.byte + 20, input.length());
        std::string errorContext = input.substr(contextStart, contextEnd - contextStart);

        LOG_ERR << "Error context:";
        LOG_ERR << " " << errorContext;
        LOG_ERR << " " << std::string(e.byte - contextStart, ' ') << "^";

        // Try to parse partially and validate
        std::vector<JSONErrorContext> errors;
        try
        {
            nlohmann::json partialJson = nlohmann::json::parse(input, nullptr, false);
            if (!partialJson.is_discarded())
            {
                JSONValidator::findErrors(partialJson, errors);
                JSONValidator::reportErrors(errors);
            }
            else
            {
                LOG_ERR << "The JSON could not be partially parsed for validation.";
            }
        }
        catch (const std::exception &validationError)
        {
            LOG_ERR << "Error during validation: " << validationError.what();
        }

        logSpecificErrorType(e.id);
    }

    // Log specific JSON error types
    static void logSpecificErrorType(int errorId) noexcept
    {
        switch (errorId)
        {
        case 101:
            LOG_ERR << "Parse error: unexpected end of input";
            break;
        case 102:
            LOG_ERR << "Parse error: unexpected token";
            break;
        case 103:
            LOG_ERR << "Parse error: invalid literal";
            break;
        case 104:
            LOG_ERR << "Parse error: value separator expected";
            break;
        case 105:
            LOG_ERR << "Parse error: object separator expected";
            break;
        case 106:
            LOG_ERR << "Parse error: expected value";
            break;
        case 107:
            LOG_ERR << "Parse error: expected end of input";
            break;
        case 108:
            LOG_ERR << "Parse error: unexpected character";
            break;
        case 109:
            LOG_ERR << "Parse error: number overflow";
            break;
        case 110:
            LOG_ERR << "Parse error: invalid number";
            break;
        case 111:
            LOG_ERR << "Parse error: invalid unicode escape";
            break;
        case 112:
            LOG_ERR << "Parse error: invalid UTF-8 string";
            break;
        case 113:
            LOG_ERR << "Parse error: unescaped control character";
            break;
        default:
            LOG_ERR << "Unexpected JSON error type: " << errorId;
        }
    }
};
