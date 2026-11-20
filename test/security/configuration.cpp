// test/security/configuration.cpp
// Configuration defaults that are security posture, not mechanics: the file
// API jail default and the CORS origin allow-list default. Uses the same
// install-Configuration-plus-hot-update pattern as the hardening tests.
#include "../../src/daemon/Configuration.h"
#include <catch.hpp>
#include <cstdlib>
#include <string>

TEST_CASE("FileAllowedBaseDir defaults to the work tree and honors an explicit value", "[security][config]")
{
	Configuration::instance(std::make_shared<Configuration>());
	SECTION("unset means the daemon work directory, not the whole filesystem")
	{
		REQUIRE(Configuration::instance()->getFileAllowedBaseDir() ==
				Configuration::instance()->getWorkDir());
	}
	SECTION("an explicit setting passes through unchanged")
	{
		Json::Value rest;
		rest["FileAllowedBaseDir"] = "/srv/exchange";
		Json::Value root;
		root["REST"] = rest;
		Configuration::instance()->hotUpdate(root);
		REQUIRE(Configuration::instance()->getFileAllowedBaseDir() == "/srv/exchange");
	}
	// Leave a default configuration behind for any later test.
	Configuration::instance(std::make_shared<Configuration>());
}

TEST_CASE("CorsAllowOrigins defaults to empty and hot-reloads", "[security][config]")
{
	Configuration::instance(std::make_shared<Configuration>());
	SECTION("default is empty: no origin is echoed, no wildcard is possible")
	{
		REQUIRE(Configuration::instance()->getCorsAllowOrigins().empty());
	}
	SECTION("an explicit allowlist passes through")
	{
		Json::Value origins(Json::arrayValue);
		origins.append("https://ui.example.com");
		Json::Value rest;
		rest["CorsAllowOrigins"] = origins;
		Json::Value root;
		root["REST"] = rest;
		Configuration::instance()->hotUpdate(root);
		const auto allowed = Configuration::instance()->getCorsAllowOrigins();
		REQUIRE(allowed.size() == 1);
		REQUIRE(allowed.count("https://ui.example.com") == 1);
	}
	// Leave a default configuration behind for any later test.
	Configuration::instance(std::make_shared<Configuration>());
}

// The metrics endpoints expose host internals (host name, PID, fd counts,
// per-route counters); an unauthenticated default would leak them to anyone
// who can reach the port (S-4).
TEST_CASE("MetricsRequireAuth defaults to true and hot-reloads", "[security][config]")
{
	Configuration::instance(std::make_shared<Configuration>());
	SECTION("default requires bearer auth + config-view on both metrics paths")
	{
		REQUIRE(Configuration::instance()->metricsRequireAuth() == true);
	}
	SECTION("the config view echoes the key so PUT /appmesh/config accepts it")
	{
		const auto view = Configuration::instance()->AsJson();
		REQUIRE(view["REST"]["MetricsRequireAuth"].asBool() == true);
	}
	SECTION("a trusted-network scraper disables it through the same hot-update SIGHUP uses")
	{
		Json::Value rest;
		rest["MetricsRequireAuth"] = false;
		Json::Value root;
		root["REST"] = rest;
		Configuration::instance()->hotUpdate(root);
		REQUIRE(Configuration::instance()->metricsRequireAuth() == false);
	}
	// Leave a default configuration behind for any later test.
	Configuration::instance(std::make_shared<Configuration>());
}

// A SIGHUP reload with a typo in a hardening mode must keep the running
// setting; resetting a hardened daemon to the boot default (off) would
// silently drop the protection the operator configured.
TEST_CASE("Invalid hardening mode values keep the running setting on reload", "[security][config]")
{
	Configuration::instance(std::make_shared<Configuration>());
	{
		Json::Value rest;
		rest["RequestSignature"] = "enforce";
		rest["RequestReplayProtection"] = "audit";
		Json::Value root;
		root["REST"] = rest;
		Configuration::instance()->hotUpdate(root);
		REQUIRE(Configuration::instance()->getRequestSignature() == "enforce");
		REQUIRE(Configuration::instance()->getRequestReplayProtection() == "audit");
	}
	{
		Json::Value rest;
		rest["RequestSignature"] = "strict"; // not off | audit | enforce
		rest["RequestReplayProtection"] = "yes";
		Json::Value root;
		root["REST"] = rest;
		Configuration::instance()->hotUpdate(root);
		REQUIRE(Configuration::instance()->getRequestSignature() == "enforce");
		REQUIRE(Configuration::instance()->getRequestReplayProtection() == "audit");
	}
	// A fresh boot has no previous setting: invalid stays at the safe default.
	{
		Json::Value rest;
		rest["RequestSignature"] = "strict";
		Json::Value root;
		root["REST"] = rest;
		const auto boot = Configuration::FromJson(root);
		REQUIRE(boot->getRequestSignature() == "off");
	}
	// Leave a default configuration behind for any later test.
	Configuration::instance(std::make_shared<Configuration>());
}

TEST_CASE("RequestReplayWindowSeconds clamps into range instead of falling back", "[security][config]")
{
	const auto windowFrom = [](int value) {
		Json::Value rest;
		rest["RequestReplayWindowSeconds"] = value;
		Json::Value root;
		root["REST"] = rest;
		return Configuration::FromJson(root)->getRequestReplayWindowSeconds();
	};
	REQUIRE(windowFrom(5) == 10);       // clamped up, not reset to the default
	REQUIRE(windowFrom(99999) == 3600); // clamped down
	REQUIRE(windowFrom(120) == 120);    // in range passes through
	// An absent key keeps the default; only explicit values clamp.
	Json::Value root;
	root["REST"] = Json::Value(Json::objectValue);
	REQUIRE(Configuration::FromJson(root)->getRequestReplayWindowSeconds() == 300);
}

// An older config.yaml without REST.SSL.SSLEnabled must still honor
// APPMESH_REST_SSL_SSLEnabled instead of silently skipping the override.
TEST_CASE("Environment overrides create a missing scalar leaf", "[security][config]")
{
	struct EnvGuard
	{
		std::string name;
		~EnvGuard() { ::unsetenv(name.c_str()); }
	};
	EnvGuard leaf{"APPMESH_REST_SSL_SSLEnabled"};
	EnvGuard deep{"APPMESH_MISSING_MIDDLE_VALUE"};
	::setenv(leaf.name.c_str(), "false", 1);
	::setenv(deep.name.c_str(), "1", 1);

	Json::Value root;
	root["REST"] = Json::Value(Json::objectValue);
	root["REST"]["RequestSignature"] = "audit";
	// The old config predates the SSLEnabled key but has the SSL section.
	root["REST"]["SSL"]["SSLCertificateFile"] = "cert.pem";
	REQUIRE(Configuration::overrideConfigWithEnv(root));
	REQUIRE(root["REST"]["SSL"]["SSLEnabled"].isBool());
	REQUIRE(root["REST"]["SSL"]["SSLEnabled"].asBool() == false);
	REQUIRE(root["REST"]["SSL"]["SSLCertificateFile"].asString() == "cert.pem"); // untouched sibling
	// A missing intermediate object is never synthesized, even for a scalar
	// value: only the leaf of an existing branch is created.
	REQUIRE_FALSE(root.isMember("MISSING"));
}
