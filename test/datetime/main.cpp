// test/datetime/main.cpp
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/common/DateTime.h"
#include "../../src/common/DurationParse.h"
#include "../../src/common/Utility.h"
#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <catch.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <set>
#include <stdexcept>
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
    LOG_DBG << DateTime::getLocalZoneUtcOffset();
    LOG_DBG << "parseDayTimeUtcDuration:" << DateTime::parseDayTimeUtcDuration("20:33:00+08");
    REQUIRE(boost::posix_time::to_simple_string(DateTime::parseDayTimeUtcDuration("20:33:00+08")) == "12:33:00");

    // time in different zone
    REQUIRE(DateTime::parseISO8601DateTime("2020-10-07T21:19:00+07", "") == DateTime::parseISO8601DateTime("2020-10-07T22:19:00+08", ""));

    // A trailing 'Z' is an explicit UTC designator: parse as UTC no matter the host timezone;
    // the local offset must never be appended to an already zoned string.
    REQUIRE(DateTime::parseISO8601DateTime("2026-11-15T09:46:40.123456789Z") ==
            DateTime::parseISO8601DateTime("2026-11-15T09:46:40.123456789+00:00"));
    REQUIRE(DateTime::parseISO8601DateTime("2026-11-15T09:46:40Z") ==
            DateTime::parseISO8601DateTime("2026-11-15T17:46:40+08:00"));

    // formatRFC3339Time keeps sub-second precision: the docker log cursor nudges one millisecond past
    // the last delivered line and relies on the fraction surviving the round trip.
    const auto stamped = DateTime::parseISO8601DateTime("2026-11-15T09:46:40.250Z");
    const auto nudged = stamped + std::chrono::milliseconds(1);
    REQUIRE(DateTime::formatRFC3339Time(nudged) == "2026-11-15T09:46:40.251000Z");
    REQUIRE(DateTime::formatRFC3339Time(stamped) == "2026-11-15T09:46:40.250000Z");

    // Convert 1543 milliseconds to 1 second and 543,000 microseconds
    long milliseconds = 1543;
    ACE_Time_Value time_in_msec(milliseconds / 1000, (milliseconds % 1000) * 1000);
    REQUIRE(time_in_msec.sec() == 1);
    REQUIRE(time_in_msec.usec() == 543000);
}

TEST_CASE("DurationParse numeric ranges", "[Duration]")
{
    init();
    // Negative numeric input returns negative seconds; callers own the sign check.
    REQUIRE(DurationParse::parse("-1") == -1);
    REQUIRE(DurationParse::parse("-90") == -90);
    REQUIRE_NOTHROW(DurationParse::parse("-2147483648"));
    REQUIRE_THROWS_AS(DurationParse::parse("2147483648"), std::invalid_argument); // beyond int
    REQUIRE_THROWS_AS(DurationParse::parse("-2147483649"), std::invalid_argument);
}

TEST_CASE("Boost Date Time Test", "[Boost]")
{
    init();

    LOG_DBG << "get_std_zone_abbrev: " << MachineTimeZone::getStdZoneAbbrev();
    LOG_DBG << "get_utc_offset: " << MachineTimeZone::getUtcOffset();
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("-08:00")) == "-08:00:00");
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("08:00")) == "08:00:00");

    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("+20:01:00")) == "20:01:00");
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("-20:01")) == "-20:01:00");
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("8")) == "08:00:00");
    REQUIRE(boost::posix_time::to_simple_string(boost::posix_time::duration_from_string("+8")) == "08:00:00");
}
