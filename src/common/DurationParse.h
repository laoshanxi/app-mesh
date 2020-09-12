#pragma once
#include <string>

/// @brief Easily converts ISO 8601 Durations to Seconds and Seconds to ISO 8601 Durations
/// Durations in ISO8601 comes in two formats:
///     PnYnMnDTnHnMnS - P<date>T<time>
///     PnW - the week format
/// https://en.wikipedia.org/wiki/ISO_8601#Durations
/// https://github.com/bretterer/iso_duration_converter
class DurationParse
{
public:
    DurationParse();
    virtual ~DurationParse();

    /// @brief Convert ISO8601 Duration string to seconds
    /// @param duration : ISO8601 Duration, "PT8S","PT5M", "PT6M4S"
    /// @return total seconds
    int parse(const std::string &duration);

    /// @brief Convert seconds to ISO8601 Duration string
    /// @param time seconds
    /// @param weekMode week mode or datetime mode
    /// @return ISO8601 time string
    std::string compose(int time, bool weekMode = false);

    int parsePart(const std::string &mode, const std::string &regexPart);
    void composePart(const std::string &mode, int &totalTime, std::string &composedDuration);

    /// @brief ignore last char
    /// @param str 
    /// @return 
    int extractInt(const std::string &str);
};
