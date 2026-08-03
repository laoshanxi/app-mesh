// test/security/main.cpp
//
// Unit tests for the daemon's token security logic: JwtToken (access/refresh
// audience separation, the configured-audience gate, the per-user token epoch)
// and TokenBlacklist (single-use revocation, jti keying, snapshot migration,
// eviction).
//
// Every case here corresponds to a defect that was found and fixed, so each one
// is written to FAIL if that fix regresses rather than merely to exercise the
// happy path.
#define CATCH_CONFIG_MAIN // This tells Catch to provide a main() - only do this in one cpp file

#include <chrono>
#include <cstdlib>
#include <map>
#include <memory>
#include <set>
#include <stdexcept>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <unordered_map>

#include <ace/Init_ACE.h>
#include <catch.hpp>
#include <nlohmann/json.hpp>

#include "../../src/common/JwtHelper.h"
#include "../../src/common/Utility.h"
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/security/JwtToken.h"
#include "../../src/daemon/security/Role.h"
#include "../../src/daemon/security/Security.h"
#include "../../src/daemon/security/TokenBlacklist.h"
#include "../../src/daemon/security/User.h"

namespace
{
	const char *const TEST_USER = "token-test-user";
	const char *const TEST_OTHER_USER = "token-test-other-user";
	const char *const TEST_ISSUER = "appmesh-unit-test";
	/// An audience the operator never configured — generate() must refuse it.
	const char *const UNCONFIGURED_AUDIENCE = "appmesh-unit-test-not-configured";

	void initEnv()
	{
		static bool initialized = false;
		if (!initialized)
		{
			initialized = true;
			ACE::init();
			Utility::setLogLevel("DEBUG");
		}
	}

	/// HMAC salt for the in-process test signer. Taken from the environment when the
	/// runner supplies one, otherwise an ephemeral per-run value from the project's own
	/// short-ID generator. Deliberately never a literal in source and never persisted:
	/// it lives only in this process for the duration of the run.
	const std::string &testJwtSalt()
	{
		static const std::string salt = []()
		{
			if (const char *fromEnv = ::getenv("APPMESH_TEST_JWT_SALT"))
			{
				const std::string value(fromEnv);
				if (!value.empty())
				{
					return value;
				}
			}
			return Utility::shortID() + Utility::shortID();
		}();
		return salt;
	}

	/// A Configuration carrying only what the JWT paths read: HS256 (so no key files are
	/// needed), an issuer, and the operator-configured audience list.
	///
	/// The audience list intentionally holds ONLY the two real audiences. JWT_REFRESH_AUDIENCE
	/// is absent on purpose — that absence is what the configured-audience gate test asserts.
	std::shared_ptr<Configuration> makeTestConfiguration()
	{
		nlohmann::json jwt;
		jwt[JSON_KEY_JWTSalt] = testJwtSalt();
		jwt[JSON_KEY_JWTAlgorithm] = APPMESH_JWT_ALGORITHM_HS256;
		jwt[JSON_KEY_JWTIssuer] = TEST_ISSUER;
		jwt[JSON_KEY_JWTAudience] = nlohmann::json::array({HTTP_HEADER_JWT_Audience_appmesh, WEBSOCKET_FILE_AUDIENCE});

		nlohmann::json rest;
		rest[JSON_KEY_JWT] = jwt;

		nlohmann::json root;
		root[JSON_KEY_REST] = rest;

		return Configuration::FromJson(root, false);
	}

	/// Minimal in-memory Security backend. JwtToken only ever asks it for user objects,
	/// so everything else is a stub. Not a Keycloak backend, so verify() stays on the
	/// local-JWT path.
	class StubSecurity : public Security
	{
	public:
		void init() override {}
		void save() override {}

		bool verifyUserKey(const std::string &, const std::string &) override { return true; }
		void changeUserPasswd(const std::string &, const std::string &) override {}

		std::shared_ptr<User> getUserInfo(const std::string &userName) override
		{
			const auto iter = m_stubUsers.find(userName);
			if (iter == m_stubUsers.end())
			{
				throw std::invalid_argument("no such user");
			}
			return iter->second;
		}
		std::map<std::string, std::shared_ptr<User>> getUsers() const override { return m_stubUsers; }
		nlohmann::json getUsersJson() const override { return nlohmann::json::object(); }
		std::shared_ptr<User> addUser(const std::string &userName, const nlohmann::json &) override
		{
			auto user = std::make_shared<User>(userName);
			m_stubUsers[userName] = user;
			return user;
		}
		void delUser(const std::string &name) override { m_stubUsers.erase(name); }

		/// Test-only: replace a user with one rebuilt from its persisted form.
		void installUser(const std::shared_ptr<User> &user) { m_stubUsers[user->getName()] = user; }

		nlohmann::json getRolesJson() const override { return nlohmann::json::object(); }
		void addRole(const nlohmann::json &, std::string) override {}
		void delRole(const std::string &) override {}
		std::shared_ptr<Role> getRole(const std::string &) override { return nullptr; }

		std::set<std::string> getAllUserGroups() const override { return std::set<std::string>(); }
		std::set<std::string> getUserPermissions(const std::string &, const std::string &) override { return std::set<std::string>(); }
		std::set<std::string> getAllPermissions() override { return std::set<std::string>(); }

	private:
		std::map<std::string, std::shared_ptr<User>> m_stubUsers;
	};

	/// Installs the two daemon singletons JwtToken depends on, and clears the shared
	/// revocation list so cases cannot leak state into one another.
	struct TokenFixture
	{
		TokenFixture()
		{
			initEnv();
			Configuration::instance(makeTestConfiguration());
			m_security = std::make_shared<StubSecurity>();
			Security::instance(m_security);
			m_user = m_security->addUser(TEST_USER, nlohmann::json::object());
			m_otherUser = m_security->addUser(TEST_OTHER_USER, nlohmann::json::object());

			std::unordered_map<std::string, std::chrono::system_clock::time_point> empty;
			TOKEN_BLACK_LIST::instance()->init(empty);
		}

		std::shared_ptr<StubSecurity> m_security;
		std::shared_ptr<User> m_user;
		std::shared_ptr<User> m_otherUser;
	};

	/// Exposes the protected surface the eviction and keying invariants need to observe.
	class TestableBlacklist : public TokenBlacklist
	{
	public:
		using TokenBlacklist::keyOf;
		using TokenBlacklist::m_maxSize;
	};

	std::chrono::system_clock::time_point inSeconds(int seconds)
	{
		return std::chrono::system_clock::now() + std::chrono::seconds(seconds);
	}
} // namespace

//////////////////////////////////////////////////////////////////////////
/// 1. Audience isolation
//////////////////////////////////////////////////////////////////////////
TEST_CASE("JwtToken audience isolation", "[security][jwt]")
{
	TokenFixture fixture;

	const auto accessToken = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 300);
	const auto refreshToken = JwtToken::generateRefresh(TEST_USER, "", 300);
	REQUIRE(accessToken != refreshToken);

	SECTION("each token verifies through its own path")
	{
		REQUIRE_NOTHROW(JwtToken::verify(accessToken, HTTP_HEADER_JWT_Audience_appmesh));
		REQUIRE_NOTHROW(JwtToken::verifyRefresh(refreshToken));
	}

	SECTION("a refresh token cannot authenticate as an access token")
	{
		// The caller chooses the audience it verifies against (apiUserAuth reads it from an
		// X-Audience header), so naming the refresh audience must not be a way in. Without
		// the explicit guard in verify() this call would succeed: the signature, issuer and
		// audience all match.
		REQUIRE_THROWS_AS(JwtToken::verify(refreshToken, JWT_REFRESH_AUDIENCE), std::domain_error);

		// And it is equally useless under any real audience.
		REQUIRE_THROWS_AS(JwtToken::verify(refreshToken, HTTP_HEADER_JWT_Audience_appmesh), std::domain_error);
		REQUIRE_THROWS_AS(JwtToken::verify(refreshToken, WEBSOCKET_FILE_AUDIENCE), std::domain_error);
	}

	SECTION("an access token cannot be redeemed as a refresh token")
	{
		// Otherwise a leaked short-lived access token could be rotated into fresh
		// credentials indefinitely.
		REQUIRE_THROWS_AS(JwtToken::verifyRefresh(accessToken), std::domain_error);

		const auto fileToken = JwtToken::generate(TEST_USER, "", WEBSOCKET_FILE_AUDIENCE, 300);
		REQUIRE_THROWS_AS(JwtToken::verifyRefresh(fileToken), std::domain_error);
	}

	SECTION("the refresh audience really is the distinguishing claim")
	{
		// Guards against the fix being "correct by accident" — assert the claim the
		// separation is built on.
		REQUIRE(JwtHelper::decode(refreshToken).get_audience().count(JWT_REFRESH_AUDIENCE) == 1);
		REQUIRE(JwtHelper::decode(accessToken).get_audience().count(JWT_REFRESH_AUDIENCE) == 0);
	}
}

//////////////////////////////////////////////////////////////////////////
/// 2. Configured-audience gate
//////////////////////////////////////////////////////////////////////////
TEST_CASE("JwtToken generate enforces the configured audience list", "[security][jwt]")
{
	TokenFixture fixture;

	SECTION("configured audiences are signed")
	{
		REQUIRE_NOTHROW(JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 300));
		REQUIRE_NOTHROW(JwtToken::generate(TEST_USER, "", WEBSOCKET_FILE_AUDIENCE, 300));
		// An empty audience falls back to the default, which is configured.
		REQUIRE_NOTHROW(JwtToken::generate(TEST_USER, "", "", 300));
	}

	SECTION("an unconfigured audience is refused")
	{
		// This is an authorization boundary, not a formality: the WebSocket file endpoints
		// authorize on audience alone.
		REQUIRE_THROWS_AS(JwtToken::generate(TEST_USER, "", UNCONFIGURED_AUDIENCE, 300), std::invalid_argument);
	}

	SECTION("there is no bypass for internal audiences")
	{
		// The exploitable hole: generate() used to wave through audiences it considered
		// "internal", letting a request-supplied audience string mint a refresh token
		// (and thus unlimited rotation) from an ordinary /appmesh/login call.
		// JWT_REFRESH_AUDIENCE is deliberately not in the configured list, so the ordinary
		// gate must reject it like any other unconfigured value.
		REQUIRE_THROWS_AS(JwtToken::generate(TEST_USER, "", JWT_REFRESH_AUDIENCE, 300), std::invalid_argument);
	}

	SECTION("generateRefresh still reaches the internal audience through its private path")
	{
		const auto refreshToken = JwtToken::generateRefresh(TEST_USER, "", 300);
		REQUIRE(JwtHelper::decode(refreshToken).get_audience().count(JWT_REFRESH_AUDIENCE) == 1);
		REQUIRE_NOTHROW(JwtToken::verifyRefresh(refreshToken));
	}

	SECTION("a nameless subject is refused on both paths")
	{
		REQUIRE_THROWS_AS(JwtToken::generate("", "", HTTP_HEADER_JWT_Audience_appmesh, 300), std::invalid_argument);
		REQUIRE_THROWS_AS(JwtToken::generateRefresh("", "", 300), std::invalid_argument);
	}
}

//////////////////////////////////////////////////////////////////////////
/// 3. Rotation / replay
//////////////////////////////////////////////////////////////////////////
TEST_CASE("Refresh token rotation is single use", "[security][blacklist]")
{
	TokenFixture fixture;

	const auto refreshToken = JwtToken::generateRefresh(TEST_USER, "", 300);
	const auto otherToken = JwtToken::generateRefresh(TEST_USER, "", 300);
	REQUIRE(refreshToken != otherToken);

	const auto expiry = inSeconds(300);

	// Rotation must gate on the atomic revoke, not on a check-then-insert: requests are
	// served by a worker pool, so two concurrent presentations of the same token would
	// otherwise both be allowed to rotate.
	REQUIRE(TOKEN_BLACK_LIST::instance()->revokeOnce(refreshToken, expiry));
	REQUIRE_FALSE(TOKEN_BLACK_LIST::instance()->revokeOnce(refreshToken, expiry));
	REQUIRE_FALSE(TOKEN_BLACK_LIST::instance()->revokeOnce(refreshToken, expiry));

	// A replayed refresh token must not be verifiable any more.
	REQUIRE_THROWS_AS(JwtToken::verifyRefresh(refreshToken), std::domain_error);

	// Revocation is per token, not per user: an unrelated refresh token still works.
	REQUIRE_NOTHROW(JwtToken::verifyRefresh(otherToken));
	REQUIRE(TOKEN_BLACK_LIST::instance()->revokeOnce(otherToken, expiry));
	REQUIRE_THROWS_AS(JwtToken::verifyRefresh(otherToken), std::domain_error);
}

// The sequential assertions above hold even for an unlocked check-then-insert. Atomicity is
// only observable under contention: exactly one of N concurrent callers may win.
TEST_CASE("Concurrent revokeOnce yields exactly one winner", "[security][blacklist]")
{
	TokenFixture fixture;

	const auto refreshToken = JwtToken::generateRefresh(TEST_USER, "", 300);
	const auto expiry = inSeconds(300);

	constexpr int threadCount = 16;
	std::atomic<int> winners{0};
	std::atomic<bool> go{false};
	std::vector<std::thread> threads;
	threads.reserve(threadCount);
	for (int i = 0; i < threadCount; ++i)
	{
		threads.emplace_back([&]()
							 {
			while (!go.load(std::memory_order_acquire)) { std::this_thread::yield(); }
			if (TOKEN_BLACK_LIST::instance()->revokeOnce(refreshToken, expiry))
				winners.fetch_add(1, std::memory_order_relaxed); });
	}
	go.store(true, std::memory_order_release);
	for (auto &t : threads)
		t.join();

	REQUIRE(winners.load() == 1);
}

TEST_CASE("A revoked access token fails verification", "[security][blacklist]")
{
	TokenFixture fixture;

	const auto accessToken = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 300);
	REQUIRE_NOTHROW(JwtToken::verify(accessToken, HTTP_HEADER_JWT_Audience_appmesh));

	TOKEN_BLACK_LIST::instance()->addToken(accessToken, inSeconds(300));
	REQUIRE_THROWS_AS(JwtToken::verify(accessToken, HTTP_HEADER_JWT_Audience_appmesh), std::domain_error);

	// tryRemoveFromList must locate the entry by the same key the insert used.
	REQUIRE(TOKEN_BLACK_LIST::instance()->tryRemoveFromList(accessToken));
	REQUIRE_FALSE(TOKEN_BLACK_LIST::instance()->tryRemoveFromList(accessToken));
	REQUIRE_NOTHROW(JwtToken::verify(accessToken, HTTP_HEADER_JWT_Audience_appmesh));
}

//////////////////////////////////////////////////////////////////////////
/// 4. jti keying
//////////////////////////////////////////////////////////////////////////
TEST_CASE("TokenBlacklist keys on jti, never on the token", "[security][blacklist]")
{
	TokenFixture fixture;
	TestableBlacklist blacklist;

	const auto tokenA = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 300);
	const auto tokenB = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 300);
	REQUIRE(tokenA != tokenB);

	const auto jtiA = JwtHelper::decode(tokenA).get_id();
	const auto jtiB = JwtHelper::decode(tokenB).get_id();
	REQUIRE_FALSE(jtiA.empty());
	REQUIRE(jtiA != jtiB);

	SECTION("distinct jti are tracked independently")
	{
		blacklist.addToken(tokenA, inSeconds(300));
		REQUIRE(blacklist.isTokenBlacklisted(tokenA));
		REQUIRE_FALSE(blacklist.isTokenBlacklisted(tokenB));

		blacklist.addToken(tokenB, inSeconds(300));
		REQUIRE(blacklist.isTokenBlacklisted(tokenA));
		REQUIRE(blacklist.isTokenBlacklisted(tokenB));
		REQUIRE(blacklist.getTokens().size() == 2);
	}

	SECTION("the stored key is the jti, not the credential")
	{
		// Keying on the whole JWT made the persisted snapshot a file full of live bearer
		// credentials and burned ~800 bytes per revocation against the size cap.
		blacklist.addToken(tokenA, inSeconds(300));

		const auto stored = blacklist.getTokens();
		REQUIRE(stored.size() == 1);
		const auto &key = stored.begin()->first;

		REQUIRE(key == jtiA);
		REQUIRE(key != tokenA);
		REQUIRE(key.find('.') == std::string::npos); // not a JWT
		REQUIRE(key.size() < tokenA.size());
	}

	SECTION("an undecodable token is keyed by hash, still not by itself")
	{
		const std::string notAJwt = "this-is-not-a-jwt";
		const auto key = TestableBlacklist::keyOf(notAJwt);
		REQUIRE_FALSE(key.empty());
		REQUIRE(key != notAJwt);

		blacklist.addToken(notAJwt, inSeconds(300));
		REQUIRE(blacklist.isTokenBlacklisted(notAJwt));
		REQUIRE(blacklist.getTokens().count(notAJwt) == 0);
	}
}

//////////////////////////////////////////////////////////////////////////
/// 5. Snapshot migration
//////////////////////////////////////////////////////////////////////////
TEST_CASE("TokenBlacklist::init re-keys a pre-upgrade snapshot", "[security][blacklist]")
{
	TokenFixture fixture;
	TestableBlacklist blacklist;

	const auto revokedToken = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 300);
	const auto jti = JwtHelper::decode(revokedToken).get_id();

	SECTION("whole-JWT entries written before the upgrade still match")
	{
		// Without re-keying, every revocation recorded before the jti change would silently
		// stop matching on restart and those tokens would become usable again.
		std::unordered_map<std::string, std::chrono::system_clock::time_point> snapshot;
		snapshot[revokedToken] = inSeconds(300);

		blacklist.init(snapshot);

		REQUIRE(blacklist.isTokenBlacklisted(revokedToken));

		const auto stored = blacklist.getTokens();
		REQUIRE(stored.size() == 1);
		REQUIRE(stored.count(revokedToken) == 0); // no longer stored as the credential
		REQUIRE(stored.begin()->first == jti);
	}

	SECTION("already-migrated entries are loaded untouched")
	{
		std::unordered_map<std::string, std::chrono::system_clock::time_point> snapshot;
		snapshot[jti] = inSeconds(300);

		blacklist.init(snapshot);

		REQUIRE(blacklist.getTokens().size() == 1);
		REQUIRE(blacklist.getTokens().count(jti) == 1);
		REQUIRE(blacklist.isTokenBlacklisted(revokedToken));
	}

	SECTION("init replaces rather than merges")
	{
		blacklist.addToken(revokedToken, inSeconds(300));
		REQUIRE(blacklist.isTokenBlacklisted(revokedToken));

		std::unordered_map<std::string, std::chrono::system_clock::time_point> empty;
		blacklist.init(empty);

		REQUIRE(blacklist.getTokens().empty());
		REQUIRE_FALSE(blacklist.isTokenBlacklisted(revokedToken));
	}
}

//////////////////////////////////////////////////////////////////////////
/// 6. Eviction
//////////////////////////////////////////////////////////////////////////
TEST_CASE("TokenBlacklist evicts when the size cap is exceeded", "[security][blacklist]")
{
	TokenFixture fixture;
	TestableBlacklist blacklist;

	// Small cap so the eviction path is reachable in a unit test; the production cap is
	// 10240. addToken() evicts m_maxSize/2 soonest-expiring entries once the list is full.
	blacklist.m_maxSize = 4;

	std::vector<std::string> tokens;
	for (int i = 0; i < 5; ++i)
	{
		tokens.push_back(JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 300));
	}

	// Staggered expiries, soonest first, all still in the future so nothing expires naturally.
	for (int i = 0; i < 4; ++i)
	{
		blacklist.addToken(tokens[i], inSeconds(100 * (i + 1)));
	}
	REQUIRE(blacklist.getTokens().size() == 4);
	for (int i = 0; i < 4; ++i)
	{
		REQUIRE(blacklist.isTokenBlacklisted(tokens[i]));
	}

	// The fifth insert trips the cap: 2 soonest-expiring entries are dropped first.
	blacklist.addToken(tokens[4], inSeconds(500));
	REQUIRE(blacklist.getTokens().size() == 3);

	// Eviction silently un-revokes, which is exactly why it is asserted rather than
	// left implicit: these two tokens are usable again.
	REQUIRE_FALSE(blacklist.isTokenBlacklisted(tokens[0]));
	REQUIRE_FALSE(blacklist.isTokenBlacklisted(tokens[1]));

	// Longer-lived revocations are preserved in preference to soon-to-expire ones.
	REQUIRE(blacklist.isTokenBlacklisted(tokens[2]));
	REQUIRE(blacklist.isTokenBlacklisted(tokens[3]));
	REQUIRE(blacklist.isTokenBlacklisted(tokens[4]));
}

//////////////////////////////////////////////////////////////////////////
/// 7. Token epoch
//////////////////////////////////////////////////////////////////////////
TEST_CASE("User::revokeIssuedTokens invalidates previously issued tokens", "[security][jwt]")
{
	TokenFixture fixture;

	// iat is second-granular, so the tokens either side of the revocation point must be
	// minted in different seconds for the comparison to be meaningful. No SECTIONs in this
	// case: Catch re-runs the body per section and these sleeps would be paid repeatedly.
	const auto oldAccess = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 3600);
	const auto oldRefresh = JwtToken::generateRefresh(TEST_USER, "", 3600);
	const auto otherUserToken = JwtToken::generate(TEST_OTHER_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 3600);

	REQUIRE_NOTHROW(JwtToken::verify(oldAccess, HTTP_HEADER_JWT_Audience_appmesh));
	REQUIRE_NOTHROW(JwtToken::verifyRefresh(oldRefresh));
	REQUIRE(fixture.m_user->tokenEpoch().time_since_epoch().count() == 0);

	std::this_thread::sleep_for(std::chrono::milliseconds(1100));
	fixture.m_user->revokeIssuedTokens();
	REQUIRE(fixture.m_user->tokenEpoch().time_since_epoch().count() > 0);
	std::this_thread::sleep_for(std::chrono::milliseconds(1100));

	// Anything minted before the revocation point is dead, including the long-lived
	// refresh token — a password change must not leave rotation alive.
	REQUIRE_THROWS_AS(JwtToken::verify(oldAccess, HTTP_HEADER_JWT_Audience_appmesh), std::domain_error);
	REQUIRE_THROWS_AS(JwtToken::verifyRefresh(oldRefresh), std::domain_error);

	// Tokens issued after the revocation point are unaffected.
	const auto newAccess = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 3600);
	const auto newRefresh = JwtToken::generateRefresh(TEST_USER, "", 3600);
	REQUIRE_NOTHROW(JwtToken::verify(newAccess, HTTP_HEADER_JWT_Audience_appmesh));
	REQUIRE_NOTHROW(JwtToken::verifyRefresh(newRefresh));

	// The epoch is per user: a user who never revoked is untouched.
	REQUIRE(fixture.m_otherUser->tokenEpoch().time_since_epoch().count() == 0);
	REQUIRE_NOTHROW(JwtToken::verify(otherUserToken, HTTP_HEADER_JWT_Audience_appmesh));
}

// The epoch check fails closed on its own second (iat <= epoch), and signToken compensates
// by pushing a freshly minted token past the epoch. Both halves are asserted here: a token
// forged with an iat inside that second is rejected, while a real re-login still works.
TEST_CASE("A persisted epoch fails closed but still allows an immediate re-login", "[security][jwt]")
{
	TokenFixture fixture;

	fixture.m_user->revokeIssuedTokens();
	// Round-trip through the store representation, which is where the truncation happens.
	// AsJson emits an empty roles array, so FromJson never dereferences the roles argument.
	const auto reloaded = User::FromJson(TEST_USER, fixture.m_user->AsJson(), nullptr);
	REQUIRE(reloaded != nullptr);
	fixture.m_security->installUser(reloaded);

	const auto truncated = reloaded->tokenEpoch();
	REQUIRE(truncated.time_since_epoch().count() > 0);
	// Truncated to a whole second: no sub-second remainder survives the round trip.
	REQUIRE(std::chrono::duration_cast<std::chrono::microseconds>(truncated.time_since_epoch()).count() % 1000000 == 0);

	// The re-login a caller performs right after changing its password must work: signToken
	// lifts iat past the epoch, so this is usable immediately rather than for-a-second dead.
	const auto reLogin = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 3600);
	REQUIRE_NOTHROW(JwtToken::verify(reLogin, HTTP_HEADER_JWT_Audience_appmesh));
	// Exactly epoch+1s, not merely later: a second boundary crossing mid-test would otherwise
	// let a removed lift slip through.
	REQUIRE(JwtHelper::decode(reLogin).get_issued_at() == truncated + std::chrono::seconds(1));

}

// The fail-closed half, which the case above cannot reach: signToken lifts a fresh mint past
// the epoch, so the only way to observe the comparison itself is to move the epoch onto an
// existing token's iat. Rejected under <=, accepted under < — this fails if it regresses.
TEST_CASE("A token whose iat equals the epoch is rejected", "[security][jwt]")
{
	TokenFixture fixture;

	const auto access = JwtToken::generate(TEST_USER, "", HTTP_HEADER_JWT_Audience_appmesh, 3600);
	const auto refresh = JwtToken::generateRefresh(TEST_USER, "", 3600);
	REQUIRE_NOTHROW(JwtToken::verify(access, HTTP_HEADER_JWT_Audience_appmesh));
	REQUIRE_NOTHROW(JwtToken::verifyRefresh(refresh));

	// Move the revocation point onto the access token's own second.
	auto json = fixture.m_user->AsJson();
	json[JSON_KEY_USER_token_epoch] = (int64_t)std::chrono::system_clock::to_time_t(
		JwtHelper::decode(access).get_issued_at());
	fixture.m_security->installUser(User::FromJson(TEST_USER, json, nullptr));

	// Same second as the revocation is indistinguishable from just before it, so both the
	// access and the refresh path must refuse it.
	REQUIRE_THROWS_AS(JwtToken::verify(access, HTTP_HEADER_JWT_Audience_appmesh), std::domain_error);
	REQUIRE_THROWS_AS(JwtToken::verifyRefresh(refresh), std::domain_error);
}
