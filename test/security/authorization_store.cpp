// test/security/authorization_store.cpp
// Request-signing API key lifecycle invariants: the key's validity is bound
// to its owner's principal status, the system principal never gets one, the
// secret is encrypted at rest, and a plaintext leftover on disk is never
// adopted. Policies install through the AuthorizationStoreTestAccess seam:
// load() stays private, and the replication line's applyReplicatedPolicy has
// no legacy counterpart.
#include "../../src/common/Utility.h"
#include "../../src/common/json.h"
#include "../../src/daemon/Configuration.h"
#include "../../src/daemon/security/AuthorizationStore.h"
#include "../../src/daemon/security/Principal.h"
#include "../../src/daemon/security/Security.h"
#include <yaml-cpp/yaml.h>
#include <catch.hpp>
#include <fstream>
#include <string>

// Narrow test seam over the private policy loader (see file header).
struct AuthorizationStoreTestAccess
{
	static void install(AuthorizationStore &store, const nlohmann::json &root) { store.load(root); }
};

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

	nlohmann::json policyRoot(const std::string &principalId)
	{
		nlohmann::json root;
		root["Authorization"]["roles"]["appmesh-admin"] = nlohmann::json::array();
		nlohmann::json principal;
		principal["kind"] = "user";
		principal["issuer"] = ISSUER;
		principal["subject"] = SUBJECT;
		root["Authorization"]["principals"][principalId] = principal;
		return root;
	}

	std::string readFile(const std::string &path)
	{
		std::ifstream in(path.c_str(), std::ios::binary);
		REQUIRE(in.is_open());
		return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	}
} // namespace

TEST_CASE("API keys are bound to their owner's principal status", "[security][authorization]")
{
	ConfigGuard guard;
	AuthorizationStore store;
	const auto principalId = Principal::stableId(ISSUER, SUBJECT);
	AuthorizationStoreTestAccess::install(store, policyRoot(principalId));

	const auto issued = store.issueApiKey(principalId);
	const auto keyId = GET_JSON_STR_VALUE(issued, "key_id");
	REQUIRE_FALSE(keyId.empty());
	std::string owner, secret;
	REQUIRE(store.apiKeySecret(keyId, owner, secret));
	REQUIRE(owner == principalId);
	REQUIRE_FALSE(secret.empty());

	SECTION("disabling the owner revokes the key: verification fails closed")
	{
		nlohmann::json disabled;
		disabled["status"] = "disabled";
		store.updatePrincipal(principalId, disabled);
		REQUIRE_FALSE(store.apiKeySecret(keyId, owner, secret));
		// Reviving the owner restores the same key material.
		nlohmann::json active;
		active["status"] = "active";
		store.updatePrincipal(principalId, active);
		REQUIRE(store.apiKeySecret(keyId, owner, secret));
		REQUIRE(secret == GET_JSON_STR_VALUE(issued, "secret"));
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

// The REST run_task gate for the system workflow App admits callers holding the
// packaged runner role or the workflow-admin permission; pin that both resolve
// through the same store lookups the gate performs (principal roles + flattened
// permissions) and that they stay distinct.
TEST_CASE("workflow gate roles resolve through the policy store", "[security][authorization]")
{
	ConfigGuard guard;
	AuthorizationStore store;
	const auto runnerId = Principal::stableId(ISSUER, "subject-wf-runner");
	const auto adminId = Principal::stableId(ISSUER, "subject-wf-admin");

	nlohmann::json root;
	root["Authorization"]["roles"]["appmesh-workflow-runner"] = nlohmann::json::array();
	root["Authorization"]["roles"]["appmesh-workflow-runner"].push_back("app-reg");
	root["Authorization"]["roles"]["appmesh-workflow-runner"].push_back("app-run-task");
	root["Authorization"]["roles"]["appmesh-admin"] = nlohmann::json::array();
	root["Authorization"]["roles"]["appmesh-admin"].push_back("workflow-admin");
	const char *bindings[][2] = {{"subject-wf-runner", "appmesh-workflow-runner"}, {"subject-wf-admin", "appmesh-admin"}};
	for (const auto &binding : bindings)
	{
		const auto principalId = Principal::stableId(ISSUER, binding[0]);
		nlohmann::json principal;
		principal["kind"] = "user";
		principal["issuer"] = ISSUER;
		principal["subject"] = binding[0];
		principal["roles"] = nlohmann::json::array();
		principal["roles"].push_back(binding[1]);
		root["Authorization"]["principals"][principalId] = principal;
	}
	AuthorizationStoreTestAccess::install(store, root);

	// Runner: role membership on the principal, run_task among flattened permissions,
	// and no admin permission.
	const auto runner = store.get(runnerId);
	REQUIRE(runner->roles().count("appmesh-workflow-runner") == 1);
	const auto runnerPermissions = store.permissions(runnerId);
	REQUIRE(runnerPermissions.count("app-run-task") == 1);
	REQUIRE(runnerPermissions.count("workflow-admin") == 0);

	// Admin: workflow-admin surfaces through the flattened permission set only.
	const auto admin = store.get(adminId);
	REQUIRE(admin->roles().count("appmesh-workflow-runner") == 0);
	REQUIRE(store.permissions(adminId).count("workflow-admin") == 1);

	// A principal absent from the policy throws on both lookups; the gate reads
	// that as "no workflow role" and keeps the owner/EDIT requirement.
	REQUIRE_THROWS(store.get(Principal::stableId(ISSUER, "subject-unknown")));
	REQUIRE_THROWS(store.permissions(Principal::stableId(ISSUER, "subject-unknown")));
}

// saveLocked persists the secret protected with the SecretProtector context
// bound to the key id; a reload decrypts it back to the same material, and a
// plaintext leftover (a pre-hardening file, or a ciphertext moved between
// entries) is dropped instead of adopted.
TEST_CASE("the stored API key secret is encrypted at rest", "[security][authorization]")
{
	ConfigGuard guard;
	AuthorizationStore store;
	const auto principalId = Principal::stableId(ISSUER, SUBJECT);
	AuthorizationStoreTestAccess::install(store, policyRoot(principalId));

	const auto issued = store.issueApiKey(principalId);
	const auto keyId = GET_JSON_STR_VALUE(issued, "key_id");
	const auto plaintext = GET_JSON_STR_VALUE(issued, "secret");
	store.save();

	const auto persistedPath = Utility::getConfigFilePath(APPMESH_AUTHORIZATION_CONFIG_FILE, true);
	const auto persisted = readFile(persistedPath);
	// The ciphertext marker rides the saved entry; the plaintext secret must not.
	REQUIRE(persisted.find("sp1:") != std::string::npos);
	REQUIRE(persisted.find(plaintext) == std::string::npos);

	// A reload decrypts the stored secret back to the issued material.
	AuthorizationStore reloaded;
	AuthorizationStoreTestAccess::install(reloaded, Utility::yamlToJson(YAML::LoadFile(persistedPath)));
	std::string owner, secret;
	REQUIRE(reloaded.apiKeySecret(keyId, owner, secret));
	REQUIRE(secret == plaintext);

	// A policy carrying a plaintext secret (or a ciphertext stolen from another
	// key id) fails decryption and is dropped, not adopted.
	nlohmann::json plaintextPolicy = policyRoot(principalId);
	plaintextPolicy["Authorization"]["api_keys"][keyId] = {
		{"principal", principalId}, {"secret", plaintext}, {"created_at", 1700000000}};
	AuthorizationStore plaintextStore;
	AuthorizationStoreTestAccess::install(plaintextStore, plaintextPolicy);
	REQUIRE_FALSE(plaintextStore.apiKeySecret(keyId, owner, secret));
}
