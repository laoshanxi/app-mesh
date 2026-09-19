// test/utility/main.cpp
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/common/DateTime.h"
#include "../../src/common/Utility.h"
#include "../../src/common/json.h"
#include "../../src/daemon/rest/EventTypes.h"
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
#include <cstdio>
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

TEST_CASE("yaml-json conversion", "[Utility]")
{
	init();

	// Empty YAML collections must convert to empty JSON collections, not null:
	// authorization.yaml ships `service_principal_roles: {}` and `roles: []`, and the
	// AuthorizationStore rejects them with "must be an object/array" if they parse as null.
	const auto root = Utility::yamlToJson(YAML::Load(
		"Authorization:\n"
		"  service_principal_roles: {}\n"
		"  principals:\n"
		"    system:appmesh:\n"
		"      roles: []\n"));
	REQUIRE(root.is_object());
	REQUIRE(root.at("Authorization").is_object());
	REQUIRE(root.at("Authorization").at("service_principal_roles").is_object());
	REQUIRE(root.at("Authorization").at("principals").at("system:appmesh").at("roles").is_array());

	// AuthorizationStore::saveLocked() persists this shape via jsonToYaml and the next
	// daemon start reloads it via yamlToJson; the round-trip must be lossless.
	const auto reloaded = Utility::yamlToJson(YAML::Load(Utility::jsonToYaml(root)));
	REQUIRE(reloaded == root);

	// Null and scalar conversion behavior stays unchanged.
	const auto scalars = Utility::yamlToJson(YAML::Load("a: null\nb: true\nc: 3\nd: 1.5\ne: text\n"));
	REQUIRE(scalars.at("a").is_null());
	REQUIRE(scalars.at("b") == true);
	REQUIRE(scalars.at("c") == 3);
	REQUIRE(scalars.at("d") == 1.5);
	REQUIRE(scalars.at("e") == "text");

	// Quoted scalars stay strings even when the text looks like bool/number/null:
	// app env values (e.g. auth-dex DEX_CLIENT_CREDENTIAL_GRANT_ENABLED_BY_DEFAULT)
	// are read with get<std::string>() and a coerced boolean aborts daemon startup.
	const auto quoted = Utility::yamlToJson(YAML::Load(
		"a: \"true\"\nb: \"3\"\nc: \"null\"\nd: \"+08\"\n"));
	REQUIRE(quoted.at("a") == "true");
	REQUIRE(quoted.at("b") == "3");
	REQUIRE(quoted.at("c") == "null");
	REQUIRE(quoted.at("d") == "+08");

	// Application::save() persists app definitions via jsonToYaml and the next
	// daemon start reloads them via yamlToJson; bool/number-looking strings must
	// survive that round-trip or the app file becomes unloadable after an update.
	nlohmann::json appEnv;
	appEnv["env"]["DEX_CLIENT_CREDENTIAL_GRANT_ENABLED_BY_DEFAULT"] = "true";
	appEnv["env"]["PORT"] = "6062";
	REQUIRE(Utility::yamlToJson(YAML::Load(Utility::jsonToYaml(appEnv))) == appEnv);
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
	// Wall-clock sleep is "at least" the requested 30ms; scheduler jitter adds more under load.
	REQUIRE(duration.count() >= 30);
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

TEST_CASE("JSON::dump replaces invalid UTF-8", "[nlohmann json]")
{
	init();

	// A payload with invalid UTF-8 (e.g. non-UTF-8 argv in pstree) must not
	// fail the whole reply: strict dump() throws type_error.316 -> 500/417,
	// JSON::dump replaces the bad bytes with U+FFFD instead.
	const std::string invalid("ab\xE6\x96\xFF");
	nlohmann::json j = nlohmann::json{{"name", invalid}};
	REQUIRE_THROWS_AS(j.dump(), nlohmann::json::type_error);

	std::string body;
	REQUIRE_NOTHROW(body = JSON::dump(j));
	REQUIRE(body.find("\xEF\xBF\xBD") != std::string::npos); // U+FFFD
	REQUIRE(body.find("ab") != std::string::npos);
	REQUIRE(JSON::dump(j, -1, true) == body); // explicit sanitize gives the same result

	// Valid UTF-8 passes through unchanged
	nlohmann::json ok = nlohmann::json{{"name", "新加卷"}};
	REQUIRE(JSON::dump(ok) == ok.dump());
}

TEST_CASE("yamlToJson keeps overflow double text as string", "[Utility]")
{
	init();

	// A scalar whose magnitude exceeds DBL_MAX makes std::stod throw
	// std::out_of_range; uncaught it aborts daemon startup (config load).
	const std::string overflow(std::string(400, '9') + ".5");
	const auto j = Utility::yamlToJson(YAML::Load("overflow: " + overflow));
	REQUIRE(j["overflow"].is_string());
	REQUIRE(j["overflow"].get<std::string>() == overflow);

	// In-range doubles still become JSON numbers
	const auto fine = Utility::yamlToJson(YAML::Load("value: 150.5"));
	REQUIRE(fine["value"].is_number());
	REQUIRE(fine["value"].get<double>() == 150.5);
}

TEST_CASE("EventTypes - eventTypeToString", "[EventTypes]")
{
	REQUIRE(std::string(eventTypeToString(AppEventType::PROCESS_START)) == "START");
	REQUIRE(std::string(eventTypeToString(AppEventType::PROCESS_EXIT)) == "EXIT");
	REQUIRE(std::string(eventTypeToString(AppEventType::STDOUT_OUTPUT)) == "STDOUT");
	REQUIRE(std::string(eventTypeToString(AppEventType::HEALTH_CHANGE)) == "HEALTH");
	REQUIRE(std::string(eventTypeToString(AppEventType::STATUS_CHANGE)) == "STATUS");
	REQUIRE(std::string(eventTypeToString(AppEventType::APP_REMOVED)) == "REMOVED");
	REQUIRE(std::string(eventTypeToString(AppEventType::ALL_EVENTS)) == "unknown");
}

TEST_CASE("EventTypes - stringToEventBit", "[EventTypes]")
{
	REQUIRE(stringToEventBit("START") == static_cast<uint32_t>(AppEventType::PROCESS_START));
	REQUIRE(stringToEventBit("EXIT") == static_cast<uint32_t>(AppEventType::PROCESS_EXIT));
	REQUIRE(stringToEventBit("STDOUT") == static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT));
	REQUIRE(stringToEventBit("HEALTH") == static_cast<uint32_t>(AppEventType::HEALTH_CHANGE));
	REQUIRE(stringToEventBit("STATUS") == static_cast<uint32_t>(AppEventType::STATUS_CHANGE));
	REQUIRE(stringToEventBit("REMOVED") == static_cast<uint32_t>(AppEventType::APP_REMOVED));
	REQUIRE(stringToEventBit("ALL") == static_cast<uint32_t>(AppEventType::ALL_EVENTS));
	REQUIRE(stringToEventBit("unknown_junk") == 0);
	REQUIRE(stringToEventBit("") == 0);
}

TEST_CASE("fileBytesToUtf8", "[Utility]")
{
	// The daemon's stdout/log read path (Utility::readFileCpp) converts non-UTF-8
	// app output to UTF-8: a GBK-emitting app must render correctly on every
	// platform, and UTF-8 output must pass through byte-identical.

	SECTION("valid UTF-8 passes through unchanged")
	{
		const std::string ascii = "plain ascii output\n";
		REQUIRE(Utility::fileBytesToUtf8(ascii) == ascii);

		const std::string chinese = "output: \xE6\x96\xB0\xE5\x8A\xA0\xE5\x8D\xB7\n"; // 新加卷
		REQUIRE(Utility::fileBytesToUtf8(chinese) == chinese);
	}

	SECTION("UTF-8 BOM is stripped")
	{
		REQUIRE(Utility::fileBytesToUtf8("\xEF\xBB\xBFhello") == "hello");
	}

	SECTION("GBK converts to UTF-8")
	{
		// "中文" encoded in GBK
		REQUIRE(Utility::fileBytesToUtf8("\xD6\xD0\xCE\xC4") == "\xE4\xB8\xAD\xE6\x96\x87");
	}

	SECTION("Big5 and Shift-JIS candidates stay reachable")
	{
		// 0xA2 0xAB is valid Big5 but invalid GBK on both glibc and libiconv
		REQUIRE(Utility::fileBytesToUtf8("\xA2\xAB") == "\xE2\x97\xA4");

		// Half-width katakana separated by ASCII is invalid GBK/Big5 but valid Shift-JIS
		REQUIRE(Utility::fileBytesToUtf8("\xB1\x21\xB2\x21\xB3\x21") == "\xEF\xBD\xB1\x21\xEF\xBD\xB2\x21\xEF\xBD\xB3\x21");
	}

	SECTION("trailing incomplete multi-byte character splits cleanly")
	{
		// "中" (D6 D0) complete plus a dangling CE lead byte: the chunk boundary cut
		// the next character, the prefix converts and the tail passes through raw
		REQUIRE(Utility::fileBytesToUtf8("hi \xD6\xD0\xCE") == "hi \xE4\xB8\xAD\xCE");

		// Same for a cut UTF-8 character: the bytes stay untouched for the next chunk
		const std::string splitUtf8 = std::string("abc\xE6\x96", 5);
		REQUIRE(Utility::fileBytesToUtf8(splitUtf8) == splitUtf8);
	}

	SECTION("undetectable bytes pass through unchanged")
	{
		const std::string garbage = std::string("\xFF\x81\x98\x00\xDE\xAD\xBE\xEF", 8);
		REQUIRE(Utility::fileBytesToUtf8(garbage) == garbage);
	}

	SECTION("GB18030 four-byte sequences never degrade")
	{
		// U+289C0 as GB18030. The bytes also contain 0x98 (undefined in CP1251)
		// and 0x81 (undefined in CP1252), so no Latin code page can mangle them.
		// glibc iconv converts the sequence; libiconv lacks the plane-2 range and
		// rejects it, leaving the bytes unchanged: both outcomes beat mojibake,
		// so accept either from whatever iconv implementation runs the test.
		const std::string in = std::string("\x98\x30\x81\x30", 4);
		const std::string out = Utility::fileBytesToUtf8(in);
		REQUIRE((out == in || out == "\xF0\xA8\xA7\x80"));
	}

	SECTION("readFileCpp converts the file content it returns")
	{
		// Call-path smoke: the app output view and event tail reads go through
		// readFileCpp, so GBK bytes on disk must come back as UTF-8.
		const std::string path = "/tmp/appmesh_test_gbk.out";
		const std::string gbk = "out \xD6\xD0\xCE\xC4\n";
		{
			std::ofstream f(path.c_str(), std::ios::binary | std::ios::trunc);
			f << gbk;
		}
		long pos = 0;
		REQUIRE(Utility::readFileCpp(path, &pos, 1024) == "out \xE4\xB8\xAD\xE6\x96\x87\n");
		REQUIRE(pos == static_cast<long>(gbk.size()));
		std::remove(path.c_str());
	}

	SECTION("utf8IncompleteTailBytes reports cut characters only")
	{
		REQUIRE(Utility::utf8IncompleteTailBytes("abc") == 0);
		REQUIRE(Utility::utf8IncompleteTailBytes("abc\xE4\xB8\xAD") == 0); // complete character
		REQUIRE(Utility::utf8IncompleteTailBytes("abc\xE6\x96") == 2);	 // 3-byte char missing one byte
		REQUIRE(Utility::utf8IncompleteTailBytes("abc\xF0\x9F\x98") == 3); // 4-byte char missing one byte
		REQUIRE(Utility::utf8IncompleteTailBytes("abc\x96") == 0);		  // continuation byte without a lead
		REQUIRE(Utility::utf8IncompleteTailBytes(std::string("\x80\x80", 2)) == 0);
	}
}

TEST_CASE("EventTypes - parseEventMask", "[EventTypes]")
{
	// Empty string -> ALL
	REQUIRE(parseEventMask("") == static_cast<uint32_t>(AppEventType::ALL_EVENTS));

	// Single event
	REQUIRE(parseEventMask("STDOUT") == static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT));

	// Multiple events
	uint32_t expected = static_cast<uint32_t>(AppEventType::PROCESS_START) | static_cast<uint32_t>(AppEventType::PROCESS_EXIT);
	REQUIRE(parseEventMask("START,EXIT") == expected);

	// "ALL" keyword
	REQUIRE(parseEventMask("ALL") == static_cast<uint32_t>(AppEventType::ALL_EVENTS));

	// Unknown tokens are ignored (return 0), so "junk" alone returns 0 (caller rejects)
	REQUIRE(parseEventMask("junk") == 0);

	// Unknown mixed with valid: only valid bits set
	REQUIRE(parseEventMask("STDOUT,bogus") == static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT));

	// Bitmask correctness
	REQUIRE((static_cast<uint32_t>(AppEventType::ALL_EVENTS) & static_cast<uint32_t>(AppEventType::PROCESS_START)) != 0);
	REQUIRE((static_cast<uint32_t>(AppEventType::ALL_EVENTS) & static_cast<uint32_t>(AppEventType::APP_REMOVED)) != 0);
}
