// test/security/main.cpp
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/security/SecretProtector.h"
#include <catch.hpp>
#include <memory>
#include <stdexcept>
#include <string>

// The decoder silently skips invalid characters; corrupt key material must
// fail here, not later at GCM time.
TEST_CASE("SecretProtector::decodeBase64 strict alphabet", "[security]")
{
	const auto asString = [](const std::vector<unsigned char> &bytes) { return std::string(bytes.begin(), bytes.end()); };

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

// Workflow slots use a prefix that no App name can contain, so the namespaces
// cannot collide even if an App key contains a NUL.
TEST_CASE("SecretProtector workflow secret context is namespaced", "[security]")
{
	const auto context = SecretProtector::workflowSecretContext("wf", "TOKEN");
	REQUIRE(context == std::string("workflow:\0wf\0TOKEN", 18));
	REQUIRE(context != std::string("wf") + '\0' + "TOKEN");
}

TEST_CASE("SecretProtector workflow secret round trip", "[security]")
{
	Configuration::instance(std::make_shared<Configuration>());
	const auto context = SecretProtector::workflowSecretContext("wf", "TOKEN");
	auto &protector = SecretProtector::instance();
	const auto ciphertext = protector.protect("value", context);
	REQUIRE(protector.unprotect(ciphertext, context) == "value");
	REQUIRE_THROWS_AS(protector.unprotect(ciphertext, SecretProtector::workflowSecretContext("other", "TOKEN")),
					  std::domain_error);
	REQUIRE_THROWS_AS(protector.unprotect(ciphertext, std::string("wf") + '\0' + "TOKEN"), std::domain_error);
}
