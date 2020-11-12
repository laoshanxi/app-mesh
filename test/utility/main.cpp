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

    // setup
    const std::string selfPath = Utility::getSelfFullPath();
    const std::string selfDir = Utility::getSelfDir();
    REQUIRE(selfPath.length() > selfDir.length());

    SECTION("File function test")
    {
        REQUIRE(Utility::isFileExist(selfPath));
        REQUIRE_FALSE(Utility::isFileExist("/abc"));
    }

    SECTION("Dir function test")
    {
        REQUIRE(Utility::isDirExist(selfDir));
        REQUIRE(Utility::isDirExist("/tmp"));
        auto testDir = "/tmp/test";
        if (Utility::isDirExist(testDir))
        {
            Utility::removeDir(testDir);
        }
        REQUIRE_FALSE(Utility::isFileExist(testDir));
        REQUIRE(Utility::createDirectory(testDir));
        REQUIRE(Utility::removeDir(testDir));
        REQUIRE_FALSE(Utility::isDirExist(testDir));
        REQUIRE_FALSE(Utility::isDirExist("/abc"));
    }

    SECTION("string operation function test")
    {
        const std::string testStr = "hello word";
        bool isNumber = Utility::isNumber(testStr);
        bool isStartWith = Utility::startWith(testStr, "he");
        std::vector<std::string> splitList = Utility::splitString(testStr, " ");
        REQUIRE_FALSE(isNumber);
        REQUIRE(isStartWith == true);
        REQUIRE(splitList.size() == 2);
        REQUIRE(splitList.at(0) == "hello");
        REQUIRE(splitList.at(1) == "word");

        REQUIRE_FALSE(Utility::isNumber("abc012"));
        REQUIRE_FALSE(Utility::isNumber("  "));
        REQUIRE_FALSE(Utility::isNumber(""));
        REQUIRE_FALSE(Utility::isNumber("0.123"));
        REQUIRE(Utility::isNumber("012"));
        REQUIRE(Utility::isNumber("-012"));
    }

    SECTION("string split function test")
    {
        std::string env = "APPMESH_Consul_url=https://127.0.0.1";
        auto pos = env.find('=');
        if (Utility::startWith(env, ENV_APPMESH_PREFIX) && (pos != std::string::npos))
        {
            LOG_INF << "pos:" << pos;
            auto envKey = env.substr(0, pos);
            REQUIRE(envKey == "APPMESH_Consul_url");
            auto envVal = env.substr(pos + 1);
            REQUIRE(envVal == "https://127.0.0.1");
            auto keys = Utility::splitString(envKey, "_");
        }
    }
    // teardown
}
