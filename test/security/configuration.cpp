// test/security/configuration.cpp
// Configuration defaults that are security posture, not mechanics: the file
// API jail default and the CORS origin allow-list default. Uses the same
// install-Configuration-plus-hot-update pattern as the hardening tests.
#include "../../src/daemon/Configuration.h"
#include <catch.hpp>
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
