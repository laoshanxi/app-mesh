// test/security/request_hardening.cpp
// Request replay protection and HMAC request signature unit tests. The
// signature crypto runs against verifyWithSecret so no Security instance is
// needed; RequestHardening::evaluate is exercised with an installed default
// Configuration plus hot-update, the same mechanism the daemon uses.
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/security/InternalCapability.h"
#include "../../src/daemon/security/ReplayGuard.h"
#include "../../src/daemon/security/RequestHardening.h"
#include "../../src/daemon/security/RequestSignature.h"
#include <atomic>
#include <catch.hpp>
#include <chrono>
#include <string>
#include <thread>

namespace
{
	std::int64_t nowSeconds()
	{
		return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
			.count();
	}

	std::string nowTimestamp()
	{
		return std::to_string(nowSeconds());
	}

	// RequestHardening is a singleton whose nonce cache survives across test
	// cases; fresh nonces per evaluation keep sections independent.
	std::string freshNonce(const char *prefix)
	{
		static std::atomic<unsigned long> counter{0};
		return std::string(prefix) + "-" + std::to_string(counter++);
	}

	/// Installs a fresh default Configuration and selects the hardening modes
	/// through the public hot-update path, like SIGHUP reload in the daemon.
	struct HardeningConfigGuard
	{
		HardeningConfigGuard(const std::string &replay, const std::string &signature, int windowSeconds = 300)
		{
			Configuration::instance(std::make_shared<Configuration>());
			nlohmann::json rest;
			rest["RequestReplayProtection"] = replay;
			rest["RequestSignature"] = signature;
			rest["RequestReplayWindowSeconds"] = windowSeconds;
			nlohmann::json root;
			root["REST"] = rest;
			Configuration::instance()->hotUpdate(root);
		}
		~HardeningConfigGuard()
		{
			// Leave a default configuration behind for any later test.
			Configuration::instance(std::make_shared<Configuration>());
		}
	};
} // namespace

TEST_CASE("ReplayGuard dedups within the window and forgets after it", "[security][hardening]")
{
	ReplayGuard guard;
	REQUIRE(guard.check("user-a", "n1", std::chrono::seconds(60)) == ReplayGuard::Verdict::First);
	REQUIRE(guard.check("user-a", "n1", std::chrono::seconds(60)) == ReplayGuard::Verdict::Duplicate);
	// Namespaces are isolated: the same nonce from another identity is fresh.
	REQUIRE(guard.check("user-b", "n1", std::chrono::seconds(60)) == ReplayGuard::Verdict::First);
	// After the window passes the entry no longer reports duplicate.
	REQUIRE(guard.check("user-a", "n1", std::chrono::seconds(0)) == ReplayGuard::Verdict::First);
}

TEST_CASE("ReplayGuard flood eviction drops the oldest tenth, not nine tenths", "[security][hardening]")
{
	ReplayGuard guard;
	const auto window = std::chrono::seconds(300);
	for (std::size_t i = 0; i <= ReplayGuard::MAX_ENTRIES; ++i)
		guard.check("flood", "nonce-" + std::to_string(i), window);
	// Crossing the cap sweeps the oldest tenth away; nine tenths of the fresh
	// flood must survive it.
	REQUIRE(guard.size() >= ReplayGuard::MAX_ENTRIES * 9 / 10);
	REQUIRE(guard.size() < ReplayGuard::MAX_ENTRIES);
	// The evicted oldest nonce is deduped as new again; the newest one is not.
	REQUIRE(guard.check("flood", "nonce-0", window) == ReplayGuard::Verdict::First);
	REQUIRE(guard.check("flood", "nonce-" + std::to_string(ReplayGuard::MAX_ENTRIES), window) ==
			ReplayGuard::Verdict::Duplicate);
	guard.clear();
}

TEST_CASE("RequestSignature canonical string is exact and stable", "[security][hardening]")
{
	SECTION("canonical query sorts by key")
	{
		REQUIRE(RequestSignature::canonicalQuery({{"b", "2"}, {"a", "1"}}) == "a=1&b=2");
		REQUIRE(RequestSignature::canonicalQuery({}) == "");
	}

	SECTION("known-answer vector fixes the wire format")
	{
		const auto bodyHash = RequestSignature::sha256Hex("", 0);
		REQUIRE(bodyHash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		REQUIRE(RequestSignature::canonicalString("GET", "/appmesh/applications", "a=1&b=2", bodyHash, "1000",
												  "nonce-1") ==
				"GET\n/appmesh/applications\na=1&b=2\n" + bodyHash + "\n1000\nnonce-1");
	}

	SECTION("file routes sign the stripped path and the empty-body hash")
	{
		const std::uint8_t fakeBody[] = {1, 2, 3};
		const auto *body = fakeBody;
		std::size_t size = sizeof(fakeBody);
		REQUIRE(RequestHardening::canonicalFileRoute("/appmesh/file/download/ws", body, size) ==
				"/appmesh/file/download");
		REQUIRE(body == nullptr);
		REQUIRE(size == 0);
		body = fakeBody;
		size = sizeof(fakeBody);
		REQUIRE(RequestHardening::canonicalFileRoute("/appmesh/file/upload", body, size) == "/appmesh/file/upload");
		REQUIRE(body == nullptr);
		REQUIRE(size == 0);
		// Non-file paths keep the body bound and the path untouched.
		body = fakeBody;
		size = sizeof(fakeBody);
		REQUIRE(RequestHardening::canonicalFileRoute("/appmesh/app/my app", body, size) == "/appmesh/app/my app");
		REQUIRE(body == fakeBody);
		REQUIRE(size == sizeof(fakeBody));
	}
}

TEST_CASE("RequestSignature verifyWithSecret accepts a correct signature and rejects tampering", "[security][hardening]")
{
	const std::string secret = "test-secret";
	const std::string method = "PUT";
	const std::string path = "/appmesh/app/example";
	const std::string query = "k=v";
	const std::string body = R"({"command":"echo hi"})";
	const auto timestamp = nowTimestamp();
	const std::string nonce = "abc123";

	const auto signFor = [&](const std::string &bodyValue, const std::string &ts, const std::string &n)
	{
		return RequestSignature::sign(secret, RequestSignature::canonicalString(
												   method, path, query,
												   RequestSignature::sha256Hex(bodyValue.data(), bodyValue.size()),
												   ts, n));
	};
	const auto signature = signFor(body, timestamp, nonce);

	SECTION("valid signature passes")
	{
		const auto result =
			RequestSignature::verifyWithSecret(secret, method, path, query,
											   reinterpret_cast<const std::uint8_t *>(body.data()), body.size(),
											   timestamp, nonce, signature, std::chrono::seconds(300));
		REQUIRE(result.valid);
		REQUIRE(result.signedRequest);
	}

	SECTION("tampered body is rejected")
	{
		const std::string evil = R"({"command":"rm -rf /"})";
		REQUIRE_FALSE(RequestSignature::verifyWithSecret(
						  secret, method, path, query, reinterpret_cast<const std::uint8_t *>(evil.data()), evil.size(),
						  timestamp, nonce, signature, std::chrono::seconds(300))
						  .valid);
	}

	SECTION("tampered method is rejected")
	{
		REQUIRE_FALSE(RequestSignature::verifyWithSecret(
						  secret, "DELETE", path, query, reinterpret_cast<const std::uint8_t *>(body.data()), body.size(),
						  timestamp, nonce, signature, std::chrono::seconds(300))
						  .valid);
	}

	SECTION("nonce substitution is rejected (nonce is signed material)")
	{
		REQUIRE_FALSE(RequestSignature::verifyWithSecret(
						  secret, method, path, query, reinterpret_cast<const std::uint8_t *>(body.data()), body.size(),
						  timestamp, "other-nonce", signature, std::chrono::seconds(300))
						  .valid);
	}

	SECTION("stale timestamp is rejected")
	{
		const auto stale = std::to_string(nowSeconds() - 4000);
		const auto staleSignature = signFor(body, stale, nonce);
		REQUIRE_FALSE(RequestSignature::verifyWithSecret(
						  secret, method, path, query, reinterpret_cast<const std::uint8_t *>(body.data()), body.size(),
						  stale, nonce, staleSignature, std::chrono::seconds(300))
						  .valid);
	}

	SECTION("wrong secret is rejected")
	{
		REQUIRE_FALSE(RequestSignature::verifyWithSecret(
						  "other-secret", method, path, query,
						  reinterpret_cast<const std::uint8_t *>(body.data()), body.size(), timestamp, nonce,
						  signature, std::chrono::seconds(300))
						  .valid);
	}

	SECTION("incomplete and malformed headers are rejected")
	{
		REQUIRE_FALSE(RequestSignature::verifyWithSecret(secret, method, path, query, nullptr, 0, "", nonce, signature,
														 std::chrono::seconds(300))
						  .valid);
		REQUIRE_FALSE(RequestSignature::verifyWithSecret(secret, method, path, query, nullptr, 0, timestamp, nonce,
														 "not-hex-!!", std::chrono::seconds(300))
						  .valid);
	}
}

TEST_CASE("RequestHardening enforces replay protection per mode", "[security][hardening]")
{
	const auto makeInput = []
	{
		RequestHardening::Input input;
		input.method = "GET";
		input.path = "/appmesh/applications";
		input.bearer = "Bearer some.jwt.token";
		return input;
	};

	SECTION("off mode allows everything without touching the guard")
	{
		HardeningConfigGuard guard("off", "off");
		const auto decision = RequestHardening::instance().evaluate(makeInput());
		REQUIRE(decision.action == RequestHardening::Decision::Action::Allow);
		REQUIRE_FALSE(decision.audit);
	}

	SECTION("unauthenticated requests are exempt (public routes)")
	{
		HardeningConfigGuard guard("enforce", "enforce");
		auto input = makeInput();
		input.bearer.clear();
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
	}

	SECTION("internal capability bearers are exempt")
	{
		HardeningConfigGuard guard("enforce", "enforce");
		auto input = makeInput();
		// Every scheme casing and spacing the authenticators accept.
		const char *capabilityBearers[] = {"Bearer amcap1.abc.def", "bearer amcap1.abc.def", "  Bearer   amcap1.abc.def"};
		for (const auto *bearer : capabilityBearers)
		{
			input.bearer = bearer;
			REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		}
		// A client JWT and the bare prefix are not capabilities.
		input.bearer = "Bearer eyJhbGciOiJSUzI1NiJ9.payload.sig";
		const auto jwt = RequestHardening::instance().evaluate(input);
		REQUIRE(jwt.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(jwt.status == 401);
		input.bearer = "Bearer amcap1.";
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Reject);
	}

	SECTION("the replay namespace ignores bearer scheme casing")
	{
		// Scheme variants of one credential are one principal: a nonce burned
		// under one spelling is a duplicate under the other.
		HardeningConfigGuard guard("enforce", "off");
		auto input = makeInput();
		input.nonce = "ns-nonce-1";
		input.bearer = "Bearer some.jwt.token";
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		input.bearer = "bearer some.jwt.token";
		const auto replayed = RequestHardening::instance().evaluate(input);
		REQUIRE(replayed.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(replayed.status == 409);
	}

	SECTION("unauthenticated signed-looking traffic never feeds the guard")
	{
		// Replay-only deployments have no verification result to trust, so
		// dedup applies to authenticated traffic only: an anonymous flood of
		// key ids and nonces must not allocate (or churn) guard entries.
		HardeningConfigGuard guard("enforce", "off");
		auto input = makeInput();
		input.bearer.clear();
		input.keyId = "key-one";
		input.nonce = "anon-nonce";
		const auto sizeBefore = RequestHardening::instance().guard().size();
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		// The same nonce replays as new: nothing was recorded to reject it.
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		REQUIRE(RequestHardening::instance().guard().size() == sizeBefore);
	}

	SECTION("authenticated requests with an oversized key id stay bounded")
	{
		// A hostile 256MB-frame X-Request-Key must not bloat guard state; the
		// namespace hashes it, and Worker drops values over 256 bytes anyway.
		HardeningConfigGuard guard("enforce", "off");
		auto input = makeInput();
		input.keyId = std::string(4096, 'k');
		input.nonce = freshNonce("oversized");
		const auto sizeBefore = RequestHardening::instance().guard().size();
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		REQUIRE(RequestHardening::instance().guard().size() == sizeBefore + 1);
	}

	SECTION("cluster replication pulls are exempt (own token auth)")
	{
		HardeningConfigGuard guard("enforce", "enforce");
		auto input = makeInput();
		input.path = "/appmesh/auth/replication/policy";
		input.bearer = "Bearer shared-replication-token";
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
	}

	SECTION("enforce: WSS/TCP uuid is the nonce; replay is rejected 409")
	{
		HardeningConfigGuard guard("enforce", "off");
		auto input = makeInput();
		input.transportPrincipal = "oidc:1234";
		input.persistentTransport = true;
		input.fallbackNonce = freshNonce("uuid");
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		const auto replay = RequestHardening::instance().evaluate(input);
		REQUIRE(replay.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(replay.status == 409);
	}

	SECTION("enforce: HTTP without a nonce is rejected 401")
	{
		HardeningConfigGuard guard("enforce", "off");
		auto input = makeInput();
		input.persistentTransport = false;
		const auto decision = RequestHardening::instance().evaluate(input);
		REQUIRE(decision.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(decision.status == 401);
	}

	SECTION("audit: replay is tolerated and flagged")
	{
		HardeningConfigGuard guard("audit", "off");
		auto input = makeInput();
		input.transportPrincipal = "oidc:audit";
		input.persistentTransport = true;
		input.fallbackNonce = freshNonce("audit");
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		const auto decision = RequestHardening::instance().evaluate(input);
		REQUIRE(decision.action == RequestHardening::Decision::Action::Allow);
		REQUIRE(decision.audit);
	}

	SECTION("enforce signature mode: authenticated request without headers is rejected")
	{
		HardeningConfigGuard guard("off", "enforce");
		auto input = makeInput();
		input.persistentTransport = true;
		input.fallbackNonce = freshNonce("sig");
		const auto decision = RequestHardening::instance().evaluate(input);
		REQUIRE(decision.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(decision.status == 401);
		REQUIRE(decision.reason.find("signature required") != std::string::npos);
	}

	SECTION("audit signature mode: unsigned authenticated traffic is flagged too")
	{
		HardeningConfigGuard guard("off", "audit");
		auto input = makeInput();
		input.persistentTransport = true;
		input.fallbackNonce = freshNonce("sig-audit");
		const auto decision = RequestHardening::instance().evaluate(input);
		REQUIRE(decision.action == RequestHardening::Decision::Action::Allow);
		REQUIRE(decision.audit);
		REQUIRE(decision.reason.find("signature required") != std::string::npos);
	}

	SECTION("replay layer: a malformed nonce is treated as missing, never stored")
	{
		HardeningConfigGuard guard("enforce", "off");
		auto input = makeInput();
		input.transportPrincipal = "oidc:malformed";
		input.persistentTransport = false;
		input.nonce = std::string(200, 'x');
		const auto decision = RequestHardening::instance().evaluate(input);
		REQUIRE(decision.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(decision.reason.find("nonce required") != std::string::npos);
	}

	SECTION("enforce: stale X-Timestamp is rejected when present")
	{
		HardeningConfigGuard guard("enforce", "off");
		auto input = makeInput();
		input.persistentTransport = true;
		input.fallbackNonce = freshNonce("stale");
		input.timestamp = std::to_string(nowSeconds() - 4000);
		const auto decision = RequestHardening::instance().evaluate(input);
		REQUIRE(decision.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(decision.reason.find("timestamp") != std::string::npos);
	}
}

TEST_CASE("RequestHardening exempts the agent forwarding precheck from the signature requirement", "[security][hardening]")
{
	const auto precheckInput = []
	{
		RequestHardening::Input input;
		input.method = "GET";
		input.path = "/appmesh/principal/self";
		input.bearer = "Bearer some.jwt.token";
		input.agentPrecheck = true;
		return input;
	};

	SECTION("enforce: the marked bearer-only precheck passes, not even audited")
	{
		HardeningConfigGuard guard("off", "enforce");
		const auto decision = RequestHardening::instance().evaluate(precheckInput());
		REQUIRE(decision.action == RequestHardening::Decision::Action::Allow);
		REQUIRE_FALSE(decision.audit); // exempt by design, not a tolerated violation
	}

	SECTION("enforce: the exemption is exactly that one request shape")
	{
		HardeningConfigGuard guard("off", "enforce");
		const auto rejected = [](const RequestHardening::Input &input)
		{
			const auto decision = RequestHardening::instance().evaluate(input);
			REQUIRE(decision.action == RequestHardening::Decision::Action::Reject);
			REQUIRE(decision.status == 401);
			REQUIRE(decision.reason.find("signature required") != std::string::npos);
		};
		auto input = precheckInput();
		input.agentPrecheck = false;
		rejected(input); // no marker header
		input = precheckInput();
		input.method = "POST";
		rejected(input); // wrong method
		input = precheckInput();
		input.path = "/appmesh/applications";
		rejected(input); // wrong path
	}
}

TEST_CASE("RequestHardening replay memory matches the timestamp acceptance window", "[security][hardening]")
{
	const auto makeEdgeInput = [](const char *noncePrefix, std::int64_t timestamp)
	{
		RequestHardening::Input input;
		input.method = "GET";
		input.path = "/appmesh/applications";
		input.bearer = "Bearer some.jwt.token";
		input.nonce = freshNonce(noncePrefix);
		input.timestamp = std::to_string(timestamp);
		return input;
	};

	SECTION("a timestamp at window+29 is accepted and the nonce is still a duplicate")
	{
		HardeningConfigGuard guard("enforce", "off", 10);
		const auto input = makeEdgeInput("edge29", nowSeconds() - (10 + 29));
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		const auto replayed = RequestHardening::instance().evaluate(input);
		REQUIRE(replayed.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(replayed.status == 409);
	}

	SECTION("a timestamp at window+31 is rejected by the timestamp layer first")
	{
		HardeningConfigGuard guard("enforce", "off", 10);
		const auto input = makeEdgeInput("edge31", nowSeconds() - (10 + 31));
		const auto decision = RequestHardening::instance().evaluate(input);
		REQUIRE(decision.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(decision.status == 401);
		REQUIRE(decision.reason.find("timestamp") != std::string::npos);
	}

	SECTION("a nonce first seen `window` seconds ago is still a duplicate")
	{
		// The memory window runs to window+30 like the acceptance window;
		// without that alignment this replay at window+epsilon would pass
		// both layers. Slow on purpose: real time must cross the window.
		HardeningConfigGuard guard("enforce", "off", 10);
		const auto input = makeEdgeInput("edge-slow", nowSeconds());
		REQUIRE(RequestHardening::instance().evaluate(input).action == RequestHardening::Decision::Action::Allow);
		std::this_thread::sleep_for(std::chrono::milliseconds(10300));
		const auto replayed = RequestHardening::instance().evaluate(input);
		REQUIRE(replayed.action == RequestHardening::Decision::Action::Reject);
		REQUIRE(replayed.status == 409);
	}
}

TEST_CASE("RequestSignature golden vectors fix the cross-language wire format", "[security][hardening]")
{
	// The same constants five SDK test suites assert against; the fixed
	// timestamp keeps this on the canonicalString+sign layer, under no time
	// window. key_id "ak-golden", secret "golden-secret".
	struct Vector
	{
		const char *method;
		const char *path;
		const char *query;
		const char *body;
		const char *timestamp;
		const char *nonce;
		const char *signature;
	};
	const Vector vectors[] = {
		{"GET", "/appmesh/app/100%25", "", "", "1700000000", "nonce-golden-0001",
		 "1036298fce978dab3ca5393a17c8dbeafcd22e8394585a96ce5a60ad39694d8c"},
		{"GET", "/appmesh/app/list", "flag=true&name=dh-bot", "", "1700000001", "nonce-golden-0002",
		 "0c9287088c6ca609fad7436f3f4646451faa8e180733e28e10e4eee11f34a9c5"},
		{"POST", "/appmesh/file/download", "", "", "1700000002", "nonce-golden-0003",
		 "dea6aa318b1fc84f8ffaadc859e4b36a90a9d6c5619f737dd037c78e5d17ac7d"},
		{"GET", "/appmesh/app/%E4%B8%AD%E6%96%87", "a=1%26b%3D2", "", "1700000003", "nonce-golden-0004",
		 "6cf618bfb9264d61d5b23dbaa42d366f59054bce99b9addab3253f98aaadb0ab"},
		{"POST", "/appmesh/appmesh/run", "", "{\"command\":\"echo hi\"}", "1700000004", "nonce-golden-0005",
		 "0a8de849eda2abf6389d40f11299aaf09e7b440615a6ee0c7e01012a92a1f876"},
	};
	const std::string secret = "golden-secret";
	for (const auto &vector : vectors)
	{
		INFO("golden vector nonce <" << vector.nonce << ">");
		const auto bodyHash = RequestSignature::sha256Hex(vector.body, std::char_traits<char>::length(vector.body));
		if (*vector.body == '\0')
			REQUIRE(bodyHash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
		const auto canonical =
			RequestSignature::canonicalString(vector.method, vector.path, vector.query, bodyHash, vector.timestamp,
											  vector.nonce);
		REQUIRE(RequestSignature::sign(secret, canonical) == vector.signature);
	}
}
