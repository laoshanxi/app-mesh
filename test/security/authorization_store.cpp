// test/security/authorization_store.cpp
// Request-signing API key lifecycle invariants: the key's validity is bound
// to its owner's principal status, the system principal never gets one, and
// the secret is encrypted at rest while the replication snapshot (the wire
// format followers verify against) stays plaintext.
#include "../../src/common/Utility.h"
#include "../../src/common/json.h"
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/security/AuthorizationStore.h"
#include "../../src/daemon/security/Principal.h"
#include "../../src/daemon/security/Security.h"
#include <catch.hpp>
#include <fstream>
#include <string>

namespace
{
	// AuthorizationStore persists under the test binary's home tree (build/)
	// and SecretProtector needs an installed Configuration for its key path;
	// both mirror how the daemon wires these singletons at boot.
	struct ConfigGuard
	{
		ConfigGuard() { Configuration::instance(std::make_shared<Configuration>()); }
		~ConfigGuard() { Configuration::instance(std::make_shared<Configuration>()); }
	};

	constexpr const char *ISSUER = "https://issuer.example";
	constexpr const char *SUBJECT = "subject-store-test";

	Json::Value policyRoot(const std::string &principalId)
	{
		Json::Value root;
		root["Authorization"]["roles"]["appmesh-admin"] = Json::Value(Json::arrayValue);
		Json::Value principal;
		principal["kind"] = "user";
		principal["issuer"] = ISSUER;
		principal["subject"] = SUBJECT;
		root["Authorization"]["principals"][principalId] = principal;
		return root;
	}

	std::string readFile(const std::string &path)
	{
		std::ifstream in(path, std::ios::binary);
		REQUIRE(in);
		return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	}
} // namespace

TEST_CASE("API keys are bound to their owner's principal status", "[security][authorization]")
{
	ConfigGuard guard;
	AuthorizationStore store;
	const auto principalId = Principal::stableId(ISSUER, SUBJECT);
	REQUIRE(store.applyReplicatedPolicy(policyRoot(principalId)));

	const auto issued = store.issueApiKey(principalId);
	const auto keyId = issued["key_id"].asString();
	REQUIRE_FALSE(keyId.empty());
	std::string owner, secret;
	REQUIRE(store.apiKeySecret(keyId, owner, secret));
	REQUIRE(owner == principalId);
	REQUIRE_FALSE(secret.empty());

	SECTION("disabling the owner revokes the key: verification fails closed")
	{
		Json::Value disabled;
		disabled["status"] = "disabled";
		store.updatePrincipal(principalId, disabled);
		REQUIRE_FALSE(store.apiKeySecret(keyId, owner, secret));
		// Reviving the owner restores the same key material.
		Json::Value active;
		active["status"] = "active";
		store.updatePrincipal(principalId, active);
		REQUIRE(store.apiKeySecret(keyId, owner, secret));
		REQUIRE(secret == issued["secret"].asString());
	}

	SECTION("revoking deletes the key outright")
	{
		REQUIRE(store.deleteApiKey(keyId, principalId, false));
		REQUIRE_FALSE(store.apiKeySecret(keyId, owner, secret));
	}
}

TEST_CASE("API keys are never issued for the system principal", "[security][authorization]")
{
	ConfigGuard guard;
	AuthorizationStore store;
	REQUIRE_THROWS_AS(store.issueApiKey(AuthorizationStore::systemPrincipalId()), AuthorizationException);
}

TEST_CASE("api key secrets are encrypted at rest and plaintext on the wire", "[security][authorization]")
{
	ConfigGuard guard;
	AuthorizationStore store;
	const auto principalId = Principal::stableId(ISSUER, SUBJECT);
	REQUIRE(store.applyReplicatedPolicy(policyRoot(principalId)));
	const auto issued = store.issueApiKey(principalId);
	const auto keyId = issued["key_id"].asString();
	const auto plaintext = issued["secret"].asString();

	SECTION("the replication snapshot is the plaintext wire format")
	{
		const auto snapshot = store.replicationSnapshotJson();
		REQUIRE(snapshot["Authorization"]["api_keys"][keyId]["secret"].asString() == plaintext);
	}

	SECTION("the persisted file encrypts and reloads through the public API")
	{
		store.save();
		const auto path = Utility::getConfigFilePath(APPMESH_AUTHORIZATION_CONFIG_FILE, true);
		const auto onDisk = readFile(path);
		REQUIRE(onDisk.find(plaintext) == std::string::npos);
		REQUIRE(onDisk.find("sp1:") != std::string::npos);

		// A store reloaded from that file decrypts back to the same secret.
		AuthorizationStore reloaded;
		reloaded.applyReplicatedPolicy(Utility::yamlToJson(YAML::LoadFile(path)));
		std::string owner, secret;
		REQUIRE(reloaded.apiKeySecret(keyId, owner, secret));
		REQUIRE(secret == plaintext);
	}

	SECTION("a plaintext secret is dropped")
	{
		Json::Value root = policyRoot(principalId);
		Json::Value entry;
		entry["principal"] = principalId;
		entry["secret"] = "plaintext-secret";
		entry["created_at"] = 1700000000;
		root["Authorization"]["api_keys"]["ak-plain"] = entry;
		AuthorizationStore plain;
		REQUIRE(plain.applyReplicatedPolicy(root));
		std::string owner, secret;
		REQUIRE_FALSE(plain.apiKeySecret("ak-plain", owner, secret));
	}

	SECTION("an undecryptable stored secret drops that key only")
	{
		Json::Value root = policyRoot(principalId);
		Json::Value entry;
		entry["principal"] = principalId;
		entry["secret"] = "sp1:AAAA"; // valid prefix, truncated payload
		entry["created_at"] = 1700000000;
		root["Authorization"]["api_keys"]["ak-broken"] = entry;
		AuthorizationStore broken;
		REQUIRE(broken.applyReplicatedPolicy(root));
		std::string owner, secret;
		REQUIRE_FALSE(broken.apiKeySecret("ak-broken", owner, secret));
	}
}
