// test/utility/main.cpp
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/common/DateTime.h"
#include "../../src/common/Utility.h"
#include "../../src/common/json.h"
#include <ace/Init_ACE.h>
#include <ace/Map_Manager.h>
#include <ace/Message_Block.h>
#include <ace/OS.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/SOCK_Connector.h>
#include <ace/SOCK_Stream.h>
#include <boost/algorithm/string_regex.hpp>
#include <catch.hpp>
#include <chrono>
#include <fstream>
#include <iostream>
#include <nlohmann/json.hpp>
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

TEST_CASE("Utility Test", "[Utility]")
{
	init();

	LOG_INF << "Utility::getExecutablePath():" << Utility::getExecutablePath();
	LOG_INF << "Utility::getBinDir():" << Utility::getBinDir();

	// setup
	const std::string selfPath = Utility::getExecutablePath();
	const std::string selfDir = Utility::getBinDir();
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
		std::string env = "APPMESH_Consul_Url=https://127.0.0.1";
		auto pos = env.find('=');
		if (Utility::startWith(env, ENV_APPMESH_PREFIX) && (pos != std::string::npos))
		{
			LOG_INF << "pos:" << pos;
			auto envKey = env.substr(0, pos);
			REQUIRE(envKey == "APPMESH_Consul_Url");
			auto envVal = env.substr(pos + 1);
			REQUIRE(envVal == "https://127.0.0.1");
			auto keys = Utility::splitString(envKey, "_");
		}
		LOG_INF << "stdStringTrim:" << Utility::stdStringTrim(env, "APP");
		LOG_INF << "stdStringTrim:" << Utility::stdStringTrim(env, "0.1");
	}
	// teardown
}

TEST_CASE("json", "[Utility]")
{
	init();

	LOG_INF << "Utility::getExecutablePath():" << Utility::getExecutablePath();
	LOG_INF << "Utility::getBinDir():" << Utility::getBinDir();

	nlohmann::json a;
	LOG_INF << "nlohmann::json: " << a;

	REQUIRE(a.is_null());
	REQUIRE(a.dump() == "null");

	a = std::string("abc");
	REQUIRE_FALSE(a.dump() == "abc");
	REQUIRE(a.get<std::string>() == "abc");
	REQUIRE(a == std::string("abc"));

	a = nlohmann::json::parse("{\"a\":2, \"b\":2}");
	LOG_INF << "nlohmann::json: " << a;
	LOG_INF << "nlohmann::json: " << a.dump();

	nlohmann::json nullBody;
	REQUIRE(nullBody.is_null());
}

TEST_CASE("boost_regex", "[boost_regex]")
{
	constexpr auto REST_PATH_CLOUD_APP_OUT_VIEW = R"(/appmesh/cloud/app/([^/\*]+)/output/([^/\*]+))";
	// constexpr auto REST_PATH_CLOUD_APP_ADD = R"(/appmesh/cloud/app/([^/\*]+))";

	boost::regex expression(REST_PATH_CLOUD_APP_OUT_VIEW);
	boost::smatch what;
	REQUIRE((boost::regex_search(std::string("/appmesh/cloud/app/a1/output/2b"), what, expression) && what.size() > 1));
	{
		// NOTE: start from position 1, skip the REST patch prefix
		for (size_t i = 1; i < what.size(); ++i)
		{
			REQUIRE(what[i].matched);
			{
				auto result = Utility::stdStringTrim(what[i].str());
				LOG_INF << "regex_search matched: " << result;
			}
		}
	}
}

TEST_CASE("ACE_Map_Manager", "[ACE]")
{
	ACE_Map_Manager<std::string, int, ACE_Recursive_Thread_Mutex> aceMap;
	aceMap.bind("123", 123);
	REQUIRE(aceMap.current_size() == 1);
	REQUIRE(aceMap.unbind("321") != 0);
	REQUIRE(aceMap.unbind("123") == 0);
	REQUIRE(aceMap.current_size() == 0);

	auto start = std::chrono::system_clock::now();
	ACE_Time_Value waitTimeout = ACE_Time_Value(0, 1000L * 30);
	ACE_OS::sleep(waitTimeout);
	auto end = std::chrono::system_clock::now();
	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
	REQUIRE(duration.count() == 30);
}

TEST_CASE("JSON", "[nlohmann json]")
{
	nlohmann::json j("");
	std::string s = j;
	LOG_INF << "nlohmann::json empty json: " << j;
	LOG_INF << "nlohmann::json empty str: " << s;

	// nlohmann::json c = nlohmann::json::parse("");
	// LOG_INF << c;

	nlohmann::json b = nlohmann::json::parse("{\"abc\": {\"def\": 123}}");
	s = b.dump();
	LOG_INF << s;
	LOG_INF << b.type_name();
	REQUIRE(b["abc"]["def"].get<int>() == 123);
	// s = b["abc"].dump();
	// LOG_INF << b.at("abc") << " and string is: " << s;

	nlohmann::json test;
	test["chinese"] = "新加卷";
	test["english"] = "test";
	test["mixed"] = "test新加卷test";

	LOG_INF << "====== Unicode Debug ======";
	LOG_INF << "Raw output: " << test;
	LOG_INF << "Dumped: " << test.dump();

	// Check string lengths
	std::string chinese = "新加卷";
	LOG_INF << "Chinese string byte length: " << chinese.length();
	LOG_INF << "Chinese string content: " << chinese;
}
