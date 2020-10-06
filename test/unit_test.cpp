#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "catch.hpp"
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <set>
#include <fstream>
#include <ace/Init_ACE.h>
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

TEST_CASE("DateTime convertDayTime2Str convertStr2DayTime", "[DateTime]")
{
    ACE::init();
    init_logging();
    REQUIRE_FALSE(false);

    REQUIRE(DateTime::convertDayTime2Str(DateTime::convertStr2DayTime("08:00")) == "08:00:00");
    REQUIRE(DateTime::convertDayTime2Str(DateTime::convertStr2DayTime("08")) == "08:00:00");
}