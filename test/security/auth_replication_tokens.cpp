// test/security/auth_replication_tokens.cpp
// Replication token file parsing and the accept-side match: the writer side
// (appmesh-auth.sh issue_replication_token) emits bare 64-char tokens, so a
// single-column line must be accepted as a token — the file-source topology
// dies with an empty accept list otherwise.
#include "../../src/daemon/security/AuthReplicationTokens.h"
#include <catch.hpp>
#include <string>

namespace
{
	constexpr const char *TOKEN_A = "5f8a1d2c3e4b5a69708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7";
	constexpr const char *TOKEN_B = "0f1e2d3c4b5a69788796a5b4c3d2e1f0091827364554637281920a1b2c3d4e5f";
} // namespace

TEST_CASE("parseTokenFile accepts the bare-token and labeled file shapes", "[security][replication]")
{
	SECTION("a bare token line is the whole entry, audited as shared")
	{
		const auto tokens = AuthReplication::parseTokenFile(std::string(TOKEN_A) + "\n");
		REQUIRE(tokens.size() == 1);
		REQUIRE(tokens[0].token == TOKEN_A);
		REQUIRE(tokens[0].label == "shared");
	}

	SECTION("a labeled line keeps token and label")
	{
		const auto tokens = AuthReplication::parseTokenFile(std::string(TOKEN_A) + " slave1\n");
		REQUIRE(tokens.size() == 1);
		REQUIRE(tokens[0].token == TOKEN_A);
		REQUIRE(tokens[0].label == "slave1");
	}

	SECTION("a tab-separated line keeps token and label")
	{
		const auto tokens = AuthReplication::parseTokenFile(std::string(TOKEN_A) + "\tslave2\n");
		REQUIRE(tokens.size() == 1);
		REQUIRE(tokens[0].token == TOKEN_A);
		REQUIRE(tokens[0].label == "slave2");
	}

	SECTION("comments, blank lines, and surrounding whitespace are ignored")
	{
		const auto content = std::string("\n") + "   \n" + "# revoked slave1\n" + "  " + TOKEN_A + "  \n" + "\t\n";
		const auto tokens = AuthReplication::parseTokenFile(content);
		REQUIRE(tokens.size() == 1);
		REQUIRE(tokens[0].token == TOKEN_A);
	}

	SECTION("a mixed file keeps every entry in file order")
	{
		const auto content = std::string("# per-follower tokens\n") + TOKEN_A + " slave1\n" + TOKEN_B + "\n";
		const auto tokens = AuthReplication::parseTokenFile(content);
		REQUIRE(tokens.size() == 2);
		REQUIRE(tokens[0].token == TOKEN_A);
		REQUIRE(tokens[0].label == "slave1");
		REQUIRE(tokens[1].token == TOKEN_B);
		REQUIRE(tokens[1].label == "shared");
	}

	SECTION("an empty file yields no entries")
	{
		REQUIRE(AuthReplication::parseTokenFile("").empty());
		REQUIRE(AuthReplication::parseTokenFile("# only a comment\n\n").empty());
	}
}

TEST_CASE("matchToken matches bare and labeled entries in constant time", "[security][replication]")
{
	const auto tokens = AuthReplication::parseTokenFile(std::string(TOKEN_A) + " slave1\n" + TOKEN_B + "\n");

	SECTION("a labeled entry matches to its audit label")
	{
		REQUIRE(AuthReplication::matchToken(tokens, TOKEN_A) == "slave1");
	}

	SECTION("a bare entry matches to its non-empty fallback label")
	{
		// The replication endpoint keys its 401 on an empty return, so a matched
		// bare token must surface a label, never the sentinel.
		REQUIRE(AuthReplication::matchToken(tokens, TOKEN_B) == "shared");
		REQUIRE_FALSE(AuthReplication::matchToken(tokens, TOKEN_B).empty());
	}

	SECTION("a wrong bearer of equal length matches nothing")
	{
		std::string wrong = TOKEN_A;
		wrong[0] = wrong[0] == '5' ? '6' : '5';
		REQUIRE(AuthReplication::matchToken(tokens, wrong).empty());
	}

	SECTION("the file-content wrapper matches the shared single-token file")
	{
		REQUIRE(AuthReplication::matchToken(std::string(TOKEN_B) + "\n", TOKEN_B) == "shared");
		REQUIRE(AuthReplication::matchToken(std::string(TOKEN_B) + "\n", TOKEN_A).empty());
	}
}

TEST_CASE("isValidLabel keeps the follower label whitelist", "[security][replication]")
{
	REQUIRE(AuthReplication::isValidLabel("slave1"));
	REQUIRE(AuthReplication::isValidLabel("appmesh_slave1.local"));
	REQUIRE_FALSE(AuthReplication::isValidLabel(""));
	REQUIRE_FALSE(AuthReplication::isValidLabel("../kv/path"));
	REQUIRE_FALSE(AuthReplication::isValidLabel("slave 1"));
}
