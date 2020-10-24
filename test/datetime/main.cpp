#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../catch.hpp"
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <time.h>
#include <set>
#include <fstream>
#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <log4cpp/Category.hh>
#include <log4cpp/Appender.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/Priority.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/RollingFileAppender.hh>
#include <log4cpp/OstreamAppender.hh>
#include "../../src/common/DateTime.h"
#include "../../src/common/Utility.h"

void init()
{
    static bool initialized = false;
    if (!initialized)
    {
        initialized = true;
        ACE::init();
        using namespace log4cpp;
        auto logDir = Utility::stringFormat("%s", Utility::getSelfDir().c_str());
        auto consoleLayout = new PatternLayout();
        consoleLayout->setConversionPattern("%d [%t] %p %c: %m%n");
        auto consoleAppender = new OstreamAppender("console", &std::cout);
        consoleAppender->setLayout(consoleLayout);

        auto rollingFileAppender = new RollingFileAppender(
            "rollingFileAppender",
            logDir.append("/unittest.log"),
            20 * 1024 * 1024,
            5,
            true,
            00664);

        auto pLayout = new PatternLayout();
        pLayout->setConversionPattern("%d [%t] %p %c: %m%n");
        rollingFileAppender->setLayout(pLayout);

        Category &root = Category::getRoot();
        root.addAppender(rollingFileAppender);
        root.addAppender(consoleAppender);

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
    LOG_DBG << "now: " << DateTime::formatISO8601Time(localTime);
    REQUIRE(localTime == DateTime::parseISO8601DateTime(DateTime::formatISO8601Time(localTime), ""));

    // parseISO8601DateTime
    auto iso8601 = "2020-10-07T21:19:00+08";
    auto iso8601TimePoint = DateTime::parseISO8601DateTime(iso8601, "");
    REQUIRE(iso8601TimePoint == DateTime::parseISO8601DateTime("2020-10-07T21:19:00+8", ""));
    REQUIRE_FALSE(DateTime::parseISO8601DateTime("2020-10-07T21:19:00", "") == DateTime::parseISO8601DateTime("2020-10-07T21:19:00+07", ""));

    // formatRFC3339Time
    auto rfc3339 = "2020-10-07T13:19:00Z";
    LOG_DBG << DateTime::formatRFC3339Time(iso8601TimePoint);
    REQUIRE(DateTime::formatRFC3339Time(iso8601TimePoint) == rfc3339);

    // getLocalUtcOffset
    LOG_DBG << DateTime::getLocalUtcOffset();
    REQUIRE(boost::posix_time::to_simple_string(DateTime::parseDayTimeUtcDuration("20:33:00", "+08")) == "12:33:00");

    // time in different zone
    REQUIRE(DateTime::parseISO8601DateTime("2020-10-07T21:19:00+07", "") == DateTime::parseISO8601DateTime("2020-10-07T22:19:00+08", ""));
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
