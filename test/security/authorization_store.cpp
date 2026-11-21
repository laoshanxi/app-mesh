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
#include <cstdlib>
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

TEST_CASE("a replicated policy hot-applies to permission checks without a restart", "[security][authorization]")
{
	ConfigGuard guard;
	AuthorizationStore store;
	const auto principalId = Principal::stableId(ISSUER, SUBJECT);

	// Follower boot without a replica cache: the packaged policy defines roles
	// but no principal binding, like authorization.yaml shipped in the image.
	Json::Value boot = policyRoot(principalId);
	boot["Authorization"].removeMember("principals");
	REQUIRE(store.applyReplicatedPolicy(boot));

	// First forwarded request ahead of the pull: the principal resolves to a
	// role-less in-memory shadow and the pull is requested promptly.
	const Principal verified(ISSUER, SUBJECT, Principal::Kind::User);
	const auto shadow = store.resolve(verified);
	REQUIRE(shadow->roles().empty());
	REQUIRE(store.permissions(principalId).empty());

	// The owner snapshot lands; the very next request must see the binding.
	Json::Value snapshot = policyRoot(principalId);
	Json::Value permissions(Json::arrayValue);
	permissions.append("host-resource-view");
	snapshot["Authorization"]["roles"]["appmesh-admin"] = permissions;
	snapshot["Authorization"]["principals"][principalId]["roles"] = Json::Value(Json::arrayValue);
	snapshot["Authorization"]["principals"][principalId]["roles"].append("appmesh-admin");
	REQUIRE(store.applyReplicatedPolicy(snapshot));
	const auto granted = store.permissions(principalId);
	REQUIRE(granted.count("host-resource-view") == 1);

	// Re-applying an identical snapshot is a no-op change test.
	REQUIRE_FALSE(store.applyReplicatedPolicy(snapshot));
}

// The live F-C2 shape: a follower boots from a pre-enrollment replica cache,
// the owner enrolls a brand-new principal, the next pull applies it, and the
// forwarded request for that principal must pass WITHOUT any restart and
// without the principal ever having been resolved on this node before.
TEST_CASE("a follower boot snapshot hot-applies a newly enrolled principal", "[security][authorization][replica]")
{
	ConfigGuard guard;

	// Boot fidelity: replica mode comes from the env at init(), the cache file
	// is the follower-local replica-policy.yaml, and the auth role is follower.
	const char *fromEnv = std::getenv("APPMESH_AUTH_REPLICATION_FROM");
	const char *roleEnv = std::getenv("APPMESH_AUTH_ROLE");
	setenv("APPMESH_AUTH_REPLICATION_FROM", "https://appmesh-master:6058", 1);
	setenv("APPMESH_AUTH_ROLE", "follower", 1);
	const auto cacheFile = Utility::getWorkConfigFilePath("replica-policy.yaml");
	const auto adminId = Principal::stableId(ISSUER, SUBJECT);
	const auto writeBootCache = [&cacheFile]() {
		// Pre-enrollment boot snapshot: roles defined, no admin principal bound.
		Json::Value boot;
		boot["Authorization"]["provisioning"] = "explicit-or-minimal";
		boot["Authorization"]["first_admin_role"] = "appmesh-admin";
		boot["Authorization"]["first_admin_enrolled"] = false;
		boot["Authorization"]["roles"]["appmesh-admin"] = Json::Value(Json::arrayValue);
		boot["Authorization"]["roles"]["appmesh-viewer"] = Json::Value(Json::arrayValue);
		boot["Authorization"]["principals"]["system:appmesh"]["kind"] = "system";
		boot["Authorization"]["principals"]["system:appmesh"]["issuer"] = "appmesh-internal";
		boot["Authorization"]["principals"]["system:appmesh"]["subject"] = "appmesh";
		Utility::createDirectory(fs::path(cacheFile).parent_path().string());
		std::ofstream out(cacheFile, std::ios::binary | std::ios::trunc);
		REQUIRE(out);
		out << Utility::jsonToYaml(boot);
	};
	writeBootCache();
	{
		AuthorizationStore store;
		store.init();
		// The boot state: the admin is absent (a check for it fails closed).
		REQUIRE_THROWS_AS(store.get(adminId), NotFoundException);
		REQUIRE_THROWS_AS(store.permissions(adminId), NotFoundException);

		// The owner snapshot lands with the freshly enrolled admin. The next
		// forwarded request authenticates and checks WITHOUT any prior resolve
		// of this principal on the follower.
		Json::Value snapshot;
		snapshot["Authorization"]["provisioning"] = "explicit-or-minimal";
		snapshot["Authorization"]["first_admin_role"] = "appmesh-admin";
		snapshot["Authorization"]["first_admin_enrolled"] = true;
		snapshot["Authorization"]["roles"]["appmesh-admin"] = Json::Value(Json::arrayValue);
		snapshot["Authorization"]["roles"]["appmesh-admin"].append("host-resource-view");
		snapshot["Authorization"]["roles"]["appmesh-admin"].append("host-forward");
		snapshot["Authorization"]["roles"]["appmesh-viewer"] = Json::Value(Json::arrayValue);
		snapshot["Authorization"]["principals"]["system:appmesh"]["kind"] = "system";
		snapshot["Authorization"]["principals"]["system:appmesh"]["issuer"] = "appmesh-internal";
		snapshot["Authorization"]["principals"]["system:appmesh"]["subject"] = "appmesh";
		snapshot["Authorization"]["principals"][adminId]["kind"] = "user";
		snapshot["Authorization"]["principals"][adminId]["issuer"] = ISSUER;
		snapshot["Authorization"]["principals"][adminId]["subject"] = SUBJECT;
		snapshot["Authorization"]["principals"][adminId]["roles"] = Json::Value(Json::arrayValue);
		snapshot["Authorization"]["principals"][adminId]["roles"].append("appmesh-admin");
		REQUIRE(store.applyReplicatedPolicy(snapshot));

		// The very next request: the new principal's binding is live.
		const auto granted = store.permissions(adminId);
		REQUIRE(granted.count("host-resource-view") == 1);
		REQUIRE(granted.count("host-forward") == 1);

		// And the follow-up authentications of the same request flow resolve
		// the principal afterwards without clobbering the binding.
		const Principal verified(ISSUER, SUBJECT, Principal::Kind::User);
		store.resolve(verified);
		REQUIRE(store.permissions(adminId).count("host-resource-view") == 1);
	}

	{
		// The pre-resolve variant: a 403'd request created the role-less shadow
		// ahead of the pull (the notifyPolicyMiss path); the pull must replace it.
		writeBootCache(); // block 1's replica save overwrote the boot cache
		AuthorizationStore store;
		store.init();
		const Principal verified(ISSUER, SUBJECT, Principal::Kind::User);
		REQUIRE(store.resolve(verified)->roles().empty());

		Json::Value snapshot;
		snapshot["Authorization"]["provisioning"] = "explicit-or-minimal";
		snapshot["Authorization"]["first_admin_role"] = "appmesh-admin";
		snapshot["Authorization"]["first_admin_enrolled"] = true;
		snapshot["Authorization"]["roles"]["appmesh-admin"] = Json::Value(Json::arrayValue);
		snapshot["Authorization"]["roles"]["appmesh-admin"].append("host-resource-view");
		snapshot["Authorization"]["roles"]["appmesh-viewer"] = Json::Value(Json::arrayValue);
		snapshot["Authorization"]["principals"]["system:appmesh"]["kind"] = "system";
		snapshot["Authorization"]["principals"]["system:appmesh"]["issuer"] = "appmesh-internal";
		snapshot["Authorization"]["principals"]["system:appmesh"]["subject"] = "appmesh";
		snapshot["Authorization"]["principals"][adminId]["kind"] = "user";
		snapshot["Authorization"]["principals"][adminId]["issuer"] = ISSUER;
		snapshot["Authorization"]["principals"][adminId]["subject"] = SUBJECT;
		snapshot["Authorization"]["principals"][adminId]["roles"] = Json::Value(Json::arrayValue);
		snapshot["Authorization"]["principals"][adminId]["roles"].append("appmesh-admin");
		REQUIRE(store.applyReplicatedPolicy(snapshot));
		REQUIRE(store.permissions(adminId).count("host-resource-view") == 1);
	}

	// Restore the process environment and shared cache file for later tests.
	fromEnv == nullptr ? unsetenv("APPMESH_AUTH_REPLICATION_FROM") : setenv("APPMESH_AUTH_REPLICATION_FROM", fromEnv, 1);
	roleEnv == nullptr ? unsetenv("APPMESH_AUTH_ROLE") : setenv("APPMESH_AUTH_ROLE", roleEnv, 1);
	Utility::removeFile(cacheFile);
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

	Json::Value root;
	root["Authorization"]["roles"]["appmesh-workflow-runner"] = Json::Value(Json::arrayValue);
	root["Authorization"]["roles"]["appmesh-workflow-runner"].append("app-reg");
	root["Authorization"]["roles"]["appmesh-workflow-runner"].append("app-run-task");
	root["Authorization"]["roles"]["appmesh-admin"] = Json::Value(Json::arrayValue);
	root["Authorization"]["roles"]["appmesh-admin"].append("workflow-admin");
	struct Binding
	{
		const char *subject;
		const char *role;
	};
	for (const auto &binding : std::vector<Binding>{{"subject-wf-runner", "appmesh-workflow-runner"},
												   {"subject-wf-admin", "appmesh-admin"}})
	{
		const auto principalId = Principal::stableId(ISSUER, binding.subject);
		Json::Value principal;
		principal["kind"] = "user";
		principal["issuer"] = ISSUER;
		principal["subject"] = binding.subject;
		principal["roles"] = Json::Value(Json::arrayValue);
		principal["roles"].append(binding.role);
		root["Authorization"]["principals"][principalId] = principal;
	}
	REQUIRE(store.applyReplicatedPolicy(root));

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

	// Restore the shared base policy: the store persists under the build tree
	// and later test cases re-apply policyRoot() expecting that base.
	REQUIRE(store.applyReplicatedPolicy(policyRoot(Principal::stableId(ISSUER, SUBJECT))));
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
