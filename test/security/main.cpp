// test/security/main.cpp
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/daemon/security/SecretProtector.h"
#include <catch.hpp>
#include <string>

// The decoder silently skips invalid characters; corrupt key material must
// fail here, not later at GCM time.
TEST_CASE("SecretProtector::decodeBase64 strict alphabet", "[security]")
{
	const auto asString = [](const std::vector<unsigned char> &bytes)
	{
		return std::string(bytes.begin(), bytes.end());
	};

	SECTION("valid base64 decodes")
	{
		REQUIRE(asString(SecretProtector::decodeBase64("QUJDREVG")) == "ABCDEF");
		REQUIRE(asString(SecretProtector::decodeBase64("QUJD")) == "ABC");
		REQUIRE(asString(SecretProtector::decodeBase64("QUI=")) == "AB");
	}

	SECTION("invalid characters are rejected at decode time")
	{
		// Length % 4 == 0: rejection must come from the alphabet guard.
		REQUIRE_THROWS_AS(SecretProtector::decodeBase64("AB$D"), std::invalid_argument);
		REQUIRE_THROWS_AS(SecretProtector::decodeBase64("AB D"), std::invalid_argument);
		REQUIRE_THROWS_AS(SecretProtector::decodeBase64("AB-D"), std::invalid_argument);
		REQUIRE_THROWS_AS(SecretProtector::decodeBase64("AB_D"), std::invalid_argument);
	}

	SECTION("non-multiple-of-4 and empty input are rejected")
	{
		REQUIRE_THROWS_AS(SecretProtector::decodeBase64("QUJ"), std::invalid_argument);
		REQUIRE_THROWS_AS(SecretProtector::decodeBase64(""), std::invalid_argument);
	}
}
