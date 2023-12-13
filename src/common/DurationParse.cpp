#include <math.h>

#include <boost/algorithm/string_regex.hpp>

#include "DurationParse.h"
#include "Utility.h"

#define DURATION_WEEK R"(^P([0-9]+W)$)"
#define DURATION_DATE_TIME R"(^P(([0-9]+Y)?([0-9]+M)?([0-9]+D)?)?(T([0-9]+H)?([0-9]+M)?([0-9]+S)?)?$)"

// https://github.com/ChannelMeter/iso8601duration/blob/master/duration.go
int DurationParse::parse(const std::string &duration)
{
    const static char fname[] = "DurationParse::parse ";
    LOG_DBG << fname << duration;
    int totalSeconds = 0;

    // return 0 for empty input
    if (duration.empty())
    {
        return 0;
    }
    if (Utility::isNumber(duration))
    {
        totalSeconds = std::stoi(duration);
        LOG_DBG << fname << "number duration: " << duration << "=" << totalSeconds;
        return totalSeconds;
    }

    // regex parse
    boost::cmatch what;
    if (boost::regex_match(duration.c_str(), what, boost::regex(DURATION_WEEK)))
    {
        if (what.size() > 1)
        {
            totalSeconds = parsePart("week", what[1]);
            LOG_DBG << fname << "week duration: " << duration << "=" << totalSeconds;
            return totalSeconds;
        }
    }
    else if (boost::regex_match(duration.c_str(), what, boost::regex(DURATION_DATE_TIME)))
    {
        /*
        // note that the index position is depend on reges expression
        for (size_t i = 0; i < what.size(); i++)
        {
            std::cout << "DURATION_DATE_TIME: " << i << " str:" << what[i].str() << std::endl;
        }
        0:P1Y2M3DT4H5M6S
        1:1Y2M3D
        2:1Y
        3:2M
        4:3D
        5:T4H5M6S
        6:4H
        7:5M
        8:6S
        */
        for (size_t i = 0; i < what.size(); i++)
        {
            if (i == 2)
                totalSeconds += parsePart("date", what[i]);
            if (i == 3)
                totalSeconds += parsePart("date", what[i]);
            if (i == 4)
                totalSeconds += parsePart("date", what[i]);

            if (i == 6)
                totalSeconds += parsePart("time", what[i]);
            if (i == 7)
                totalSeconds += parsePart("time", what[i]);
            if (i == 8)
                totalSeconds += parsePart("time", what[i]);
        }
        LOG_DBG << fname << "date time duration: " << duration << "=" << totalSeconds;
        return totalSeconds;
    }
    LOG_WAR << fname << "invalid ISO8601 duration format: " << duration;
    throw std::invalid_argument("invalid ISO8601 duration format");
}

std::string DurationParse::compose(int time, bool weekMode)
{
    const static char fname[] = "DurationParse::compose ";
    LOG_DBG << fname << "time:" << time << " weekMode:" << weekMode;

    int totalTime = time;
    std::string composedDuration = "P";

    if (weekMode)
    {
        composePart("week W", totalTime, composedDuration);
    }
    else
    {
        composePart("date D", totalTime, composedDuration);
        composePart("time H", totalTime, composedDuration);
        composePart("time M", totalTime, composedDuration);
        composePart("time S", totalTime, composedDuration);
    }

    return composedDuration;
}

int DurationParse::parsePart(const std::string &mode, const std::string &regexPart)
{
    const static char fname[] = "DurationParse::parsePart ";

    if (regexPart.length() == 0)
        return 0;
    auto n = extractInt(regexPart);
    if (0 == n)
        return 0;

    auto id = mode + ' ' + regexPart[regexPart.length() - 1];
    if (id == "time S")
        return n * 1;
    if (id == "time M")
        return n * 60;
    if (id == "time H")
        return n * 60 * 60;
    if (id == "date D")
        return n * 24 * 60 * 60;
    if (id == "date M")
        throw std::invalid_argument("ISO8601 months is not supported");
    if (id == "date Y")
        return n * 365 * 24 * 60 * 60;
    if (id == "week W")
        return n * 7 * 24 * 60 * 60;

    LOG_WAR << fname << "Ambiguous duration " << regexPart << " for " << mode;
    throw std::invalid_argument("Ambiguous duration");
}

void DurationParse::composePart(const std::string &mode, int &totalTime, std::string &composedDuration)
{
    bool time = true;
    std::string result;

    if (mode == "time S")
    {
        auto strValue = std::max((int)std::floor(totalTime / 1), 0);
        totalTime -= strValue * 1;
        result = strValue > 0 ? std::to_string(strValue) + 'S' : "";
    }
    if (mode == "time M")
    {
        auto strValue = std::max((int)std::floor(totalTime / 60), 0);
        totalTime -= strValue * 60;
        result = strValue > 0 ? std::to_string(strValue) + 'M' : "";
    }
    if (mode == "time H")
    {
        auto strValue = std::max((int)std::floor(totalTime / 3600), 0);
        totalTime -= strValue * 3600;
        result = strValue > 0 ? std::to_string(strValue) + 'H' : "";
    }
    if (mode == "date D")
    {
        auto strValue = std::max((int)std::floor(totalTime / 86400), 0);
        totalTime -= strValue * 86400;
        result = strValue > 0 ? std::to_string(strValue) + 'D' : "";
        time = false;
    }
    if (mode == "week W")
    {
        auto strValue = std::max((int)std::floor(totalTime / 604800), 0);
        result = std::to_string(strValue) + 'W';
        totalTime -= strValue * 604800;
        time = false;
    }

    if (time && (composedDuration.find('T') == std::string::npos) && result.length())
    {
        composedDuration += 'T';
    }

    composedDuration += result;
}

int DurationParse::extractInt(const std::string &str)
{
    return std::stoi(str.substr(0, str.length() - 1));
}
