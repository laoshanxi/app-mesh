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

TEST_CASE("Utility Test", "[Utility]")
{
    init();

    LOG_INF << "Utility::getSelfFullPath():" << Utility::getSelfFullPath();
    LOG_INF << "Utility::getSelfDir():" << Utility::getSelfDir();
    REQUIRE(Utility::getSelfFullPath().length() > Utility::getSelfDir().length());

    REQUIRE(Utility::isFileExist(Utility::getSelfFullPath()));
    REQUIRE_FALSE(Utility::isFileExist("/abc"));
}
