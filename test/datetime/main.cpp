#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/common/DateTime.h"
#include "../../src/common/Utility.h"
#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <catch.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <time.h>

void init()
{
    static bool initialized = false;
    if (!initialized)
    {
        initialized = true;
        ACE::init();
        // Log level
        Utility::setLogLevel("DEBUG");

        LOG_INF << "Logging process ID:" << getpid();
    }
}

TEST_CASE("DateTime Class Test", "[DateTime]")
{
    init();

    // covert now to seconds
    auto now = std::chrono::system_clock::now();

    std::string timeStr = "2020-10-08T14:14:00+08";
    LOG_DBG << timeStr << " is " << DateTime::formatISO8601Time(DateTime::parseISO8601DateTime(timeStr, ""));
    auto localTime = std::chrono::system_clock::from_time_t(std::chrono::system_clock::to_time_t(now));
    LOG_DBG << "now formatISO8601Time: " << DateTime::formatISO8601Time(localTime);
    LOG_DBG << "now formatLocalTime: " << DateTime::formatLocalTime(localTime);
    REQUIRE(localTime == DateTime::parseISO8601DateTime(DateTime::formatISO8601Time(localTime), ""));

    // test different input parse
    auto testStr1 = "2021-12-08T21:00:00+08";
    auto testTimeP1 = DateTime::parseISO8601DateTime(testStr1, "");
    LOG_DBG << testStr1 << " formatLocalTime: " << DateTime::formatLocalTime(testTimeP1);

    auto testStr2 = "2021-12-08T21:00+08";
    auto testTimeP2 = DateTime::parseISO8601DateTime(testStr2, "");
    LOG_DBG << testStr2 << " formatLocalTime: " << DateTime::formatLocalTime(testTimeP2);
    REQUIRE(DateTime::formatLocalTime(testTimeP1) == DateTime::formatLocalTime(testTimeP2));

    REQUIRE(DateTime::parseISO8601DateTime("2021-12-08T17:05+09") == DateTime::parseISO8601DateTime("2021-12-08T16:05+08"));
    REQUIRE(DateTime::parseISO8601DateTime("2021-12-08T09:05+01:00") == DateTime::parseISO8601DateTime("2021-12-08T16:05+08"));

    // parseISO8601DateTime
    try
    {
        DateTime::parseISO8601DateTime("123");
    }
    catch (...)
    {
        REQUIRE(true);
    }
    REQUIRE(DateTime::parseISO8601DateTime("") == std::chrono::system_clock::from_time_t(0));
    auto iso8601 = "2020-10-07T21:19:00+08";
    auto iso8601TimePoint = DateTime::parseISO8601DateTime(iso8601, "");
    REQUIRE(iso8601TimePoint == DateTime::parseISO8601DateTime("2020-10-07T21:19:00+8", ""));
    REQUIRE_FALSE(DateTime::parseISO8601DateTime("2020-10-07T21:19:00", "") == DateTime::parseISO8601DateTime("2020-10-07T21:19:00+07", ""));

    // formatRFC3339Time
    auto rfc3339 = "2020-10-07T13:19:00Z";
    LOG_DBG << DateTime::formatRFC3339Time(iso8601TimePoint);
    REQUIRE(DateTime::formatRFC3339Time(iso8601TimePoint) == rfc3339);

    // getLocalZoneUTCOffset
    LOG_DBG << DateTime::getLocalZoneUTCOffset();
    LOG_DBG << "parseDayTimeUtcDuration:" << DateTime::parseDayTimeUtcDuration("20:33:00+08");
    REQUIRE(boost::posix_time::to_simple_string(DateTime::parseDayTimeUtcDuration("20:33:00+08")) == "12:33:00");

    // time in different zone
    REQUIRE(DateTime::parseISO8601DateTime("2020-10-07T21:19:00+07", "") == DateTime::parseISO8601DateTime("2020-10-07T22:19:00+08", ""));

    // Convert 1543 milliseconds to 1 second and 543,000 microseconds
    long milliseconds = 1543;
    ACE_Time_Value time_in_msec(milliseconds / 1000, (milliseconds % 1000) * 1000);
    REQUIRE(time_in_msec.sec() == 1);
    REQUIRE(time_in_msec.usec() == 543000);
}

TEST_CASE("Boost Date Time Test", "[Boost]")
{
    init();

    LOG_DBG << "get_std_zone_abbrev: " << machine_time_zone::get_std_zone_abbrev();
    LOG_DBG << "get_utc_offset: " << machine_time_zone::get_utc_offset();
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("-08:00")) == "-08:00:00");
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("08:00")) == "08:00:00");

    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("+20:01:00")) == "20:01:00");
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("-20:01")) == "-20:01:00");
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("8")) == "08:00:00");
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("+8")) == "08:00:00");
}
