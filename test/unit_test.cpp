#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
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
#include "../src/common/DateTime.h"
#include "../src/common/Utility.h"

void init_logging()
{
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

TEST_CASE("DateTime Class Test", "[DateTime]")
{
    ACE::init();
    init_logging();
    REQUIRE_FALSE(false);

    char *tz = strdup("TZ=GMT-08:00");
    putenv(tz);
    tzset();

    // covert now to seconds
    auto now = std::chrono::system_clock::now();
    auto localTime = std::chrono::system_clock::from_time_t(std::chrono::system_clock::to_time_t(now));
    REQUIRE(localTime == DateTime::parseISO8601DateTime(DateTime::formatISO8601Time(localTime)));

    // parseISO8601DateTime
    auto iso8601 = "2020-10-07T21:19:00+08";
    auto iso8601TimePoint = DateTime::parseISO8601DateTime(iso8601);
    REQUIRE(iso8601TimePoint == DateTime::parseISO8601DateTime("2020-10-07T21:19:00+8"));
    REQUIRE_FALSE(DateTime::parseISO8601DateTime("2020-10-07T21:19:00") == DateTime::parseISO8601DateTime("2020-10-07T21:19:00+08"));

    // formatRFC3339Time
    auto rfc3339 = "2020-10-07T21:19:00.000Z";
    LOG_DBG << DateTime::formatRFC3339Time(iso8601TimePoint);
    REQUIRE(DateTime::formatRFC3339Time(iso8601TimePoint) == rfc3339);

    // getLocalUtcOffset
    REQUIRE(DateTime::getLocalUtcOffset() == "+08:00:00");

    // convertToZoneTime
    boost::posix_time::ptime ptime;
    boost::posix_time::time_input_facet *format = new boost::posix_time::time_input_facet();
    format->set_iso_extended_format();
    std::istringstream iss(iso8601);
    iss.imbue(std::locale(std::locale::classic(), format));
    (iss >> ptime);
    REQUIRE(DateTime::convertToZoneTime(ptime, "CST+08") == iso8601TimePoint);
}