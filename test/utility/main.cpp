// test/utility/main.cpp
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/common/DateTime.h"
#include "../../src/common/UriParser.hpp"
#include "../../src/common/Utility.h"
#include "../../src/common/json.h"
#include "../../src/common/os/proc.h"
#include "../../src/daemon/rest/EventTypes.h"
#include <boost/algorithm/string_regex.hpp>
#include <catch.hpp>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <time.h>
#if defined(_WIN32)
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

void init()
{
	static bool initialized = false;
	if (!initialized)
	{
		initialized = true;
		// Log level
		Utility::setLogLevel("DEBUG");

		LOG_INF << "Logging process ID:" << os::getpid();
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

TEST_CASE("Dependency-backed helpers regression", "[Utility]")
{
	SECTION("stdStringTrim")
	{
		REQUIRE(Utility::stdStringTrim("  ab \t\n") == "ab");
		REQUIRE(Utility::stdStringTrim("   ") == "");
		REQUIRE(Utility::stdStringTrim(std::string()) == "");
		// every occurrence on each side goes, not just one
		REQUIRE(Utility::stdStringTrim("--ab--", '-') == "ab");
		REQUIRE(Utility::stdStringTrim("---", '-') == "");
		REQUIRE(Utility::stdStringTrim("--ab--", '-', true, false) == "ab--");
		REQUIRE(Utility::stdStringTrim("--ab--", '-', false, true) == "--ab");
		REQUIRE(Utility::stdStringTrim("--ab--", '-', false, false) == "--ab--");
		// multi-character token, repeated
		REQUIRE(Utility::stdStringTrim("APPAPPmeshAPP", "APP") == "mesh");
		REQUIRE(Utility::stdStringTrim("ab/x/x", "/x") == "ab");
		REQUIRE(Utility::stdStringTrim("/x/x", "/x") == "");
		REQUIRE(Utility::stdStringTrim("abc", "ABC") == "abc");
	}

	SECTION("splitString keeps multi-character delimiters")
	{
		const auto parts = Utility::splitString("a:: b::::c", "::");
		REQUIRE(parts == std::vector<std::string>{"a", "b", "c"});
		// no delimiter: the whole (trimmed) string is one token
		REQUIRE(Utility::splitString(" ab ", "::") == std::vector<std::string>{"ab"});
		REQUIRE(Utility::splitString("", "::") == std::vector<std::string>{});
	}

	SECTION("startWith endWith")
	{
		REQUIRE(Utility::startWith("hello", ""));
		REQUIRE(Utility::startWith("hello", "hello"));
		REQUIRE_FALSE(Utility::startWith("hi", "hello"));
		REQUIRE(Utility::endWith("hello", ""));
		REQUIRE(Utility::endWith("hello", "hello"));
		REQUIRE_FALSE(Utility::endWith("lo", "hello"));
	}

	SECTION("stringFormat")
	{
		REQUIRE(Utility::stringFormat("%s=%d", "a", 42) == "a=42");
		// output far larger than the format string itself
		const std::string longStr(4096, 'x');
		REQUIRE(Utility::stringFormat("<%s>", longStr.c_str()) == "<" + longStr + ">");
		REQUIRE(Utility::stringFormat("%f", 1.5) == "1.500000");
	}

	SECTION("base64 round-trips")
	{
		REQUIRE(Utility::encode64("") == "");
		REQUIRE(Utility::decode64("") == "");
		REQUIRE(Utility::encode64("123") == "MTIz");
		REQUIRE(Utility::decode64("MTIz") == "123");
		// trailing NUL bytes must survive (32-byte keys can end in 0x00)
		const std::string nulTail = std::string("ab\0\0", 4);
		REQUIRE(Utility::decode64(Utility::encode64(nulTail)) == nulTail);
		REQUIRE(Utility::decode64(Utility::encode64(std::string("\0", 1))) == std::string("\0", 1));
		// embedded NUL anywhere
		const std::string nulMid = std::string("a\0b", 3);
		REQUIRE(Utility::decode64(Utility::encode64(nulMid)) == nulMid);
	}

	SECTION("toHex")
	{
		const unsigned char bytes[] = {0x00, 0x0f, 0xa5, 0xff};
		REQUIRE(Utility::toHex(bytes, 4) == "000fa5ff");
		REQUIRE(Utility::toHex(bytes, 0) == "");
	}

	SECTION("utf8LeadByteLength")
	{
		REQUIRE(Utility::utf8LeadByteLength(0x41) == 0); // ASCII is not a lead
		REQUIRE(Utility::utf8LeadByteLength(0x80) == 0); // continuation byte
		REQUIRE(Utility::utf8LeadByteLength(0xC0) == 0); // overlong lead
		REQUIRE(Utility::utf8LeadByteLength(0xC2) == 2);
		REQUIRE(Utility::utf8LeadByteLength(0xDF) == 2);
		REQUIRE(Utility::utf8LeadByteLength(0xE0) == 3);
		REQUIRE(Utility::utf8LeadByteLength(0xEF) == 3);
		REQUIRE(Utility::utf8LeadByteLength(0xF0) == 4);
		REQUIRE(Utility::utf8LeadByteLength(0xF4) == 4);
		REQUIRE(Utility::utf8LeadByteLength(0xF5) == 0); // above U+10FFFF
	}

	SECTION("Uri query decoding")
	{
		// '+' becomes space, %XX decodes
		const auto plus = Uri::parse("http://h/p?a+b=1").queryParams();
		REQUIRE(plus.begin()->first == "a b");
		const auto params = Uri::parse("http://h/p?a=%41&b=%42").queryParams();
		REQUIRE(params.at("a") == "A");
		REQUIRE(params.at("b") == "B");
	}
}

// The transports only accept numeric addresses (trantor::InetAddress never
// resolves; drogon aborts on a hostname listener), so the resolver must hand
// back a usable numeric IP and must never mangle address literals.
TEST_CASE("resolveHostAddress", "[Utility]")
{
	init();

	SECTION("address literals pass through unchanged")
	{
		std::string errorText;
		REQUIRE(Utility::resolveHostAddress("127.0.0.1", errorText) == "127.0.0.1");
		REQUIRE(errorText.empty());
		REQUIRE(Utility::resolveHostAddress("::1", errorText) == "::1");
		REQUIRE(errorText.empty());
	}

	SECTION("hostname resolves to a numeric address, IPv4 preferred")
	{
		std::string errorText;
		const auto resolved = Utility::resolveHostAddress("localhost", errorText);
		if (!errorText.empty())
		{
			// A resolver-less sandbox still proves the failure contract.
			LOG_INF << "resolveHostAddress(localhost) error: " << errorText;
			REQUIRE(resolved.empty());
		}
		else
		{
			REQUIRE_FALSE(resolved.empty());
			struct in_addr v4;
			struct in6_addr v6;
			const bool numeric = resolved.find(':') != std::string::npos ? inet_pton(AF_INET6, resolved.c_str(), &v6) == 1
																		 : inet_pton(AF_INET, resolved.c_str(), &v4) == 1;
			REQUIRE(numeric);
		}
	}

	SECTION("unknown name either resolves numerically or reports an error")
	{
		// Some sandboxes run a wildcard DNS (fake-IP proxies resolve anything),
		// so a hard failure cannot be forced; the contract is: never throws,
		// never returns a non-numeric non-empty string.
		std::string errorText;
		const auto resolved = Utility::resolveHostAddress("nonexistent.invalid.appmesh", errorText);
		if (resolved.empty())
		{
			REQUIRE_FALSE(errorText.empty());
		}
		else
		{
			struct in_addr v4;
			struct in6_addr v6;
			const bool numeric = resolved.find(':') != std::string::npos ? inet_pton(AF_INET6, resolved.c_str(), &v6) == 1
																		 : inet_pton(AF_INET, resolved.c_str(), &v4) == 1;
			REQUIRE(numeric);
		}
	}
}

TEST_CASE("json", "[Utility]")
{
	init();

	LOG_INF << "Utility::getExecutablePath():" << Utility::getExecutablePath();
	LOG_INF << "Utility::getBinDir():" << Utility::getBinDir();

	Json::Value a;
	LOG_INF << "jsoncpp: " << JSON::dump(a);

	REQUIRE(a.isNull());
	REQUIRE(JSON::dump(a) == "null");

	a = std::string("abc");
	REQUIRE_FALSE(JSON::dump(a) == "abc");
	REQUIRE(a.asString() == "abc");
	REQUIRE(a == std::string("abc"));

	a = JSON::parse("{\"a\":2, \"b\":2}");
	LOG_INF << "jsoncpp: " << JSON::dump(a);

	Json::Value nullBody;
	REQUIRE(nullBody.isNull());
}

TEST_CASE("yaml-json conversion", "[Utility]")
{
	init();

	// Empty YAML collections must convert to empty JSON collections, not null:
	// authorization.yaml ships `service_principal_roles: {}` and `roles: []`, and the
	// AuthorizationStore rejects them with "must be an object/array" if they parse as null.
	const auto root = Utility::yamlToJson(YAML::Load("Authorization:\n"
													 "  service_principal_roles: {}\n"
													 "  principals:\n"
													 "    system:appmesh:\n"
													 "      roles: []\n"));
	REQUIRE(root.isObject());
	REQUIRE(root["Authorization"].isObject());
	REQUIRE(root["Authorization"]["service_principal_roles"].isObject());
	REQUIRE(root["Authorization"]["principals"]["system:appmesh"]["roles"].isArray());

	// AuthorizationStore::saveLocked() persists this shape via jsonToYaml and the next
	// daemon start reloads it via yamlToJson; the round-trip must be lossless.
	const auto reloaded = Utility::yamlToJson(YAML::Load(Utility::jsonToYaml(root)));
	REQUIRE(reloaded == root);

	// Null and scalar conversion behavior stays unchanged.
	const auto scalars = Utility::yamlToJson(YAML::Load("a: null\nb: true\nc: 3\nd: 1.5\ne: text\n"));
	REQUIRE(scalars["a"].isNull());
	REQUIRE(scalars["b"].asBool());
	REQUIRE(scalars["c"].asInt() == 3);
	REQUIRE(scalars["d"].asDouble() == 1.5);
	REQUIRE(scalars["e"].asString() == "text");

	// Quoted scalars stay strings even when the text looks like bool/number/null:
	// app env values (e.g. auth-dex DEX_CLIENT_CREDENTIAL_GRANT_ENABLED_BY_DEFAULT)
	// are read with get<std::string>() and a coerced boolean aborts daemon startup.
	const auto quoted = Utility::yamlToJson(YAML::Load("a: \"true\"\nb: \"3\"\nc: \"null\"\nd: \"+08\"\n"));
	REQUIRE(quoted["a"].asString() == "true");
	REQUIRE(quoted["b"].asString() == "3");
	REQUIRE(quoted["c"].asString() == "null");
	REQUIRE(quoted["d"].asString() == "+08");

	// Application::save() persists app definitions via jsonToYaml and the next
	// daemon start reloads them via yamlToJson; bool/number-looking strings must
	// survive that round-trip or the app file becomes unloadable after an update.
	Json::Value appEnv;
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

TEST_CASE("JSON", "[json]")
{
	Json::Value b = JSON::parse("{\"abc\": {\"def\": 123}}");
	auto s = JSON::dump(b);
	LOG_INF << s;
	REQUIRE(b["abc"]["def"].asInt() == 123);

	Json::Value test;
	test["chinese"] = "新加卷";
	test["english"] = "test";
	test["mixed"] = "test新加卷test";

	LOG_INF << "====== Unicode Debug ======";
	LOG_INF << "Dumped: " << JSON::dump(test);

	std::string chinese = "新加卷";
	LOG_INF << "Chinese string byte length: " << chinese.length();
	LOG_INF << "Chinese string content: " << chinese;
}

TEST_CASE("JSON::dump replaces invalid UTF-8", "[json]")
{
	init();

	// A payload with invalid UTF-8 (e.g. non-UTF-8 argv in pstree) must not
	// fail the whole reply: JSON::dump replaces the bad bytes with U+FFFD.
	const std::string invalid("ab\xE6\x96\xFF");
	Json::Value j;
	j["name"] = invalid;

	std::string body;
	REQUIRE_NOTHROW(body = JSON::dump(j));
	REQUIRE(body.find("\xEF\xBF\xBD") != std::string::npos); // U+FFFD
	REQUIRE(body.find("ab") != std::string::npos);

	// Valid UTF-8 passes through unchanged
	Json::Value ok;
	ok["name"] = "\xE6\x96\xB0\xE5\x8A\xA0\xE5\x8D\xB7"; // 新加卷
	REQUIRE(JSON::dump(ok).find("\xE6\x96\xB0\xE5\x8A\xA0\xE5\x8D\xB7") != std::string::npos);
}

TEST_CASE("yamlToJson keeps overflow double text as string", "[Utility]")
{
	init();

	// A scalar whose magnitude exceeds DBL_MAX makes std::stod throw
	// std::out_of_range; uncaught it aborts daemon startup (config load).
	const std::string overflow(std::string(400, '9') + ".5");
	const auto j = Utility::yamlToJson(YAML::Load("overflow: " + overflow));
	REQUIRE(j["overflow"].isString());
	REQUIRE(j["overflow"].asString() == overflow);

	// In-range doubles still become JSON numbers
	const auto fine = Utility::yamlToJson(YAML::Load("value: 150.5"));
	REQUIRE(fine["value"].isNumeric());
	REQUIRE(fine["value"].asDouble() == 150.5);
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

	SECTION("UTF-8 BOM is stripped") { REQUIRE(Utility::fileBytesToUtf8("\xEF\xBB\xBFhello") == "hello"); }

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
		REQUIRE(Utility::utf8IncompleteTailBytes("abc\xE6\x96") == 2);     // 3-byte char missing one byte
		REQUIRE(Utility::utf8IncompleteTailBytes("abc\xF0\x9F\x98") == 3); // 4-byte char missing one byte
		REQUIRE(Utility::utf8IncompleteTailBytes("abc\x96") == 0);         // continuation byte without a lead
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
	uint32_t expected =
		static_cast<uint32_t>(AppEventType::PROCESS_START) | static_cast<uint32_t>(AppEventType::PROCESS_EXIT);
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

TEST_CASE("JSON dump golden baseline", "[json golden]")
{
	init();

	// Byte-exact wire contract for the reply body: key order (alphabetical),
	// separators, string escaping, and number formats. Any change to these
	// literals is a wire-format change and must be recorded in the JSON ADR.
	Json::Value j;
	j["chinese"] = "\xE6\x96\xB0\xE5\x8A\xA0\xE5\x8D\xB7"; // 新加卷
	j["int64"] = (Json::Int64)9223372036854775807LL;
	j["uint"] = (Json::UInt64)18446744073709551615ULL;
	j["dbl1"] = 0.1;
	j["dbl2"] = 99.0;
	j["dbl3"] = 12.34;
	j["esc"] = std::string("a\"b\\c\nd\te\001f");

	const std::string cn = "\xE6\x96\xB0\xE5\x8A\xA0\xE5\x8D\xB7"; // 新加卷
	REQUIRE(
		JSON::dump(j) ==
		R"({"chinese":")" + cn +
			R"(","dbl1":0.10000000000000001,"dbl2":99.0,"dbl3":12.34,"esc":"a\"b\\c\nd\te\u0001f","int64":9223372036854775807,"uint":18446744073709551615})"); // hex-escape: MSVC reads non-BOM sources as ACP and mis-lexes non-ASCII raw strings

	// Pretty format is jsoncpp native (only used for debug logging)
	REQUIRE(JSON::dump(j, 2) == "{\n"
								"  \"chinese\" : \"\xE6\x96\xB0\xE5\x8A\xA0\xE5\x8D\xB7\",\n"
								"  \"dbl1\" : 0.10000000000000001,\n"
								"  \"dbl2\" : 99.0,\n"
								"  \"dbl3\" : 12.34,\n"
								"  \"esc\" : \"a\\\"b\\\\c\\nd\\te\\u0001f\",\n"
								"  \"int64\" : 9223372036854775807,\n"
								"  \"uint\" : 18446744073709551615\n"
								"}");

	// EventDispatcher::dispatch splices ,"subscription_id":"..." before the
	// final '}' by raw string concat: compact output must stay single-line,
	// end with '}' and carry no trailing newline.
	const auto compact = JSON::dump(j);
	REQUIRE((!compact.empty() && compact.back() == '}'));
	REQUIRE(compact.find('\n') == std::string::npos);

	// Lossless round-trip: parse(dump(j)) renders identically again
	REQUIRE(JSON::dump(JSON::parse(compact)) == compact);
}

TEST_CASE("JSON::dump invalid UTF-8 golden baseline", "[json golden]")
{
	init();

	// A non-UTF-8 argv in pstree must not fail the whole reply. JSON::dump
	// replaces each invalid run with U+FFFD and always produces valid UTF-8.
	const std::string invalidInputs[] = {
		"ab\xE6\x96\xFF",   // truncated 3-byte sequence + bad byte
		"\xC0\xAF",         // overlong '/'
		"\xED\xA0\x80",     // surrogate D800
		"\xF5\x80\x80\x80", // above U+10FFFF
		"\x80",             // lone continuation
		"\xFF",             // bad lead byte
	};
	for (const auto &input : invalidInputs)
	{
		Json::Value payload;
		payload["v"] = input;
		std::string body;
		REQUIRE_NOTHROW(body = JSON::dump(payload));
		REQUIRE(body.find("\xEF\xBF\xBD") != std::string::npos); // U+FFFD present
		REQUIRE(Utility::isValidUTF8(body));                     // output is valid UTF-8
	}

	// Byte-exact run folding: one U+FFFD per invalid run (lead + continuations
	// consumed together; a bad lead and lone continuations are separate runs)
	Json::Value run;
	run["v"] = std::string("\xED\xA0\x80");
	REQUIRE(JSON::dump(run) == "{\"v\":\"\xEF\xBF\xBD\"}");
	run["v"] = std::string("\xF5\x80\x80\x80");
	REQUIRE(JSON::dump(run) == "{\"v\":\"\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\xEF\xBF\xBD\"}");
	run["v"] = std::string("ok\xE6\x96");
	REQUIRE(JSON::dump(run) == "{\"v\":\"ok\xEF\xBF\xBD\"}");

	// Valid multi-byte content around invalid bytes is preserved
	Json::Value mixed;
	mixed["v"] = std::string("ok\xE6\x96\x87 big\xFFtail");
	const auto body = JSON::dump(mixed);
	REQUIRE(body.find("ok\xE6\x96\x87 big") != std::string::npos);

	// Valid UTF-8 passes through byte-identical
	Json::Value ok;
	ok["v"] = "ok\xE6\x96\x87 big";
	REQUIRE(JSON::dump(ok) == "{\"v\":\"ok\xE6\x96\x87 big\"}");
}

TEST_CASE("JSON parse golden baseline", "[json golden]")
{
	init();

	// The 400 contract: a malformed or non-UTF-8 request body must fail the
	// parse (HttpRequest::extractJson maps the throw to HTTP 400).
	const std::string rejected[] = {
		"",
		"{",
		"{\"a\":1,}",      // trailing comma
		"{\"a\":1} xx",    // trailing garbage
		"// c\n{\"a\":1}", // comment
		"{\"a\":NaN}",     // not a JSON number
		"{\"a\":-Infinity}",
		std::string("{\"a\":\"\xE6\x96\xFF\"}"), // invalid UTF-8 raw
	};
	for (const auto &text : rejected)
		REQUIRE_THROWS_AS(JSON::parse(text), std::invalid_argument);

	// Non-throwing variant reports the error and returns null
	std::string error;
	REQUIRE(JSON::parse("{", &error).isNull());
	REQUIRE(!error.empty());
	REQUIRE(JSON::parse("{}", &error).isNull() == false);
	REQUIRE(error.empty());

	// Accepted shapes
	REQUIRE(JSON::parse("123").isNumeric());
	REQUIRE(JSON::parse("\"hi\"").isString());
	REQUIRE(JSON::parse("\"\\u0000\"").isString());
	REQUIRE(JSON::parse("{\"a\":1,\"a\":2}")["a"].asInt() == 2); // dup key: last wins

	// Deep nesting beyond the reader stack limit throws out of CharReader; both
	// overloads must honor their contract (throw invalid_argument / error path)
	std::string deep(1500, '[');
	deep.append(1500, ']');
	REQUIRE_THROWS_AS(JSON::parse(deep), std::invalid_argument);
	REQUIRE(JSON::parse(deep, &error).isNull());
	REQUIRE(!error.empty());
}

TEST_CASE("JSON merge-patch golden baseline", "[json golden]")
{
	init();

	// hotUpdate contract: nested objects merge, siblings survive, null deletes,
	// scalars replace the whole section
	Json::Value target;
	target["Labels"] = Json::Value(Json::objectValue);
	target["Labels"]["env"] = "dev";
	target["Labels"]["team"] = "x";
	target["name"] = "a";

	JSON::mergePatch(target, JSON::parse(R"({"Labels":{"env":"prod"}})"));
	REQUIRE(target["Labels"]["env"].asString() == "prod");
	REQUIRE(target["Labels"]["team"].asString() == "x");
	REQUIRE(target["name"].asString() == "a");

	JSON::mergePatch(target, JSON::parse(R"({"name":null})"));
	REQUIRE(!target.isMember("name"));

	JSON::mergePatch(target, JSON::parse(R"({"Labels":"reset"})"));
	REQUIRE(target["Labels"].asString() == "reset");

	// A non-object target is replaced by the patched object
	Json::Value scalar = Json::Value("str");
	JSON::mergePatch(scalar, JSON::parse(R"({"a":1})"));
	REQUIRE(scalar["a"].asInt() == 1);
}

TEST_CASE("yaml/json round-trip golden baseline", "[json golden]")
{
	init();

	// The config/app persistence path: quoted scalars keep their string type,
	// plain scalars infer bool/null/number, and jsonToYaml re-quotes strings
	// that would otherwise change type on reload (app env "true").
	const auto j = Utility::yamlToJson(YAML::Load("quoted: \"123\"\n"
												  "plain: 123\n"
												  "qtrue: \"true\"\n"
												  "plain_true: true\n"
												  "qnull: \"null\"\n"));
	REQUIRE(j["quoted"].isString());
	REQUIRE(j["quoted"].asString() == "123");
	REQUIRE(j["plain"].isIntegral());
	REQUIRE(j["qtrue"].isString());
	REQUIRE(j["plain_true"].isBool());
	REQUIRE(j["qnull"].isString());

	const auto yamlBack = Utility::jsonToYaml(j);
	const auto reloaded = Utility::yamlToJson(YAML::Load(yamlBack));
	REQUIRE(reloaded["quoted"].isString());
	REQUIRE(reloaded["quoted"].asString() == "123");
	REQUIRE(reloaded["qtrue"].isString());
	REQUIRE(reloaded["qtrue"].asString() == "true");
	REQUIRE(reloaded["plain"].isIntegral());
	REQUIRE(reloaded["plain_true"].isBool());

	// int64/uint64 boundaries survive the round trip
	Json::Value limits;
	limits["i64max"] = (Json::Int64)9223372036854775807LL;
	limits["u64max"] = (Json::UInt64)18446744073709551615ULL;
	const auto reloadedLimits = Utility::yamlToJson(YAML::Load(Utility::jsonToYaml(limits)));
	REQUIRE(reloadedLimits["i64max"].asInt64() == 9223372036854775807LL);
	REQUIRE(reloadedLimits["u64max"].asUInt64() == 18446744073709551615ULL);
}

TEST_CASE("JSON helper macro golden baseline", "[json golden]")
{
	init();

	// Reply/default contract of the macro layer: missing or null fields fall
	// back to type defaults, wrong-typed fields throw (surfaced as 4xx/5xx by
	// the request layer, never silently coerced beyond GET_JSON_STR_INT_TEXT).
	Json::Value obj;
	obj["str"] = "hi ";
	obj["int"] = 7;
	obj["int64"] = (Json::Int64)5000000000LL;
	obj["b"] = true;
	obj["nullv"] = Json::Value();

	REQUIRE(!HAS_JSON_FIELD(obj, "missing"));
	REQUIRE(!HAS_JSON_FIELD(obj, "nullv"));
	REQUIRE(HAS_JSON_FIELD(obj, "str"));
	REQUIRE(GET_JSON_STR_VALUE(obj, "str") == "hi"); // trimmed
	REQUIRE(GET_JSON_STR_VALUE(obj, "missing") == "");
	REQUIRE(GET_JSON_INT_VALUE(obj, "int") == 7);
	REQUIRE(GET_JSON_INT_VALUE(obj, "missing") == 0);
	REQUIRE(GET_JSON_INT64_VALUE(obj, "int64") == 5000000000LL);
	REQUIRE(GET_JSON_BOOL_VALUE(obj, "b") == true);
	REQUIRE(GET_JSON_BOOL_VALUE(obj, "missing") == false);
	REQUIRE_THROWS_AS(GET_JSON_INT_VALUE(obj, "str"), Json::Exception);

	// jsoncpp would coerce these ("7"/true); the strict getters keep the 400 contract
	REQUIRE_THROWS_AS(GET_JSON_STR_VALUE(obj, "int"), std::invalid_argument);
	REQUIRE_THROWS_AS(GET_JSON_BOOL_VALUE(obj, "int"), std::invalid_argument);
	REQUIRE_THROWS_AS(GET_JSON_BOOL_VALUE(obj, "str"), std::invalid_argument);

	// Text-or-integer fields accept both shapes
	Json::Value mixed;
	mixed["asText"] = "42";
	mixed["asNum"] = 42;
	REQUIRE(GET_JSON_STR_INT_TEXT(mixed, "asText") == "42");
	REQUIRE(GET_JSON_STR_INT_TEXT(mixed, "asNum") == "42");

	// text2json error body shape
	REQUIRE(JSON::dump(Utility::text2json("boom")) == R"({"message":"boom"})");
}

// jsonStringField keeps wrong-typed client fields a 400 instead of jsoncpp coercion.
TEST_CASE("jsonStringField rejects coerced scalars", "[json]")
{
	const auto json = JSON::parse(R"({"name":"ok","num":42,"flag":true})");

	REQUIRE(Utility::jsonStringField(json, "name") == "ok");
	REQUIRE_THROWS_AS(Utility::jsonStringField(json, "num"), std::invalid_argument);
	REQUIRE_THROWS_AS(Utility::jsonStringField(json, "flag"), std::invalid_argument);
	REQUIRE_THROWS_AS(Utility::jsonStringField(json, "missing"), std::invalid_argument);

	// The coercion this guards against (jsoncpp silently stringifies scalars):
	REQUIRE(json["num"].asString() == "42");
}

// resolveHostAddress(timeout): literal fast path and bounded failure.
TEST_CASE("resolveHostAddress literal fast path and bounded failure", "[network]")
{
	std::string error;

	SECTION("address literals never touch the resolver")
	{
		REQUIRE(Utility::resolveHostAddress("127.0.0.1", error, 5) == "127.0.0.1");
		REQUIRE(error.empty());
		REQUIRE(Utility::resolveHostAddress("::1", error, 5) == "::1");
		REQUIRE(error.empty());
	}

	SECTION("a locally invalid name fails with a diagnostic")
	{
		// >63-char labels are rejected by getaddrinfo itself (RFC 1035):
		// deterministic even behind a hijacking resolver.
		const std::string invalidLabel(64, 'a');
		const auto ip = Utility::resolveHostAddress(invalidLabel + ".example.com", error, 5);
		REQUIRE(ip.empty());
		REQUIRE_FALSE(error.empty());
		REQUIRE(error.find("example.com") != std::string::npos);
	}

	SECTION("a zero timeout keeps the legacy blocking behavior")
	{
		REQUIRE(Utility::resolveHostAddress("127.0.0.1", error) == "127.0.0.1");
	}
}
