#pragma once

#include <string>
#include <vector>

#include "AuthReplicationTokens.h"

/// Thin Vault KV-v2 reader for the replication token source.
///
/// The daemon never writes: issuing and revoking happen through the operator
/// tooling (appmesh-auth.sh) against the same API, so Vault is the single
/// source of truth and its own audit log records every change. Every call
/// fails closed — a Vault outage rejects pulls instead of opening them.
///
/// Production notes (the compose cluster runs the documented dev posture):
/// TLS on the listener, per-follower AppRole auth instead of delivered
/// service tokens, and periodic tokens are the hardening steps.
class VaultClient
{
public:
	struct Config
	{
		std::string address;   // scheme://host:port, e.g. http://appmesh_vault:8200
		std::string tokenFile; // access credential file: one line = static service
							   // token; two lines = AppRole (role_id, secret_id)
		/// https verification, on by default; APPMESH_VAULT_TLS_SKIP_VERIFY opts out,
		/// an empty caPath falls back to APPMESH_VAULT_CACERT then the system store.
		bool verifyServer = true;
		std::string caPath;
	};

	/// Lists every follower token as (token, label): one KV entry per label.
	/// Throws std::runtime_error on transport or HTTP failure; an entry whose
	/// data was deleted (revoked) is skipped, an empty store lists as none.
	static std::vector<AuthReplication::AcceptedToken> listReplicationTokens(const Config &config);

	/// Reads one follower's own token (label = KV key). Throws on transport
	/// or HTTP failure; a missing entry returns an empty token.
	static std::string readReplicationToken(const Config &config, const std::string &label);

	/// AppRole machine login: exchanges (role_id, secret_id) for a Vault
	/// client token. The standard issuance path for non-human identities.
	/// TLS posture follows `config` (https verifies by default).
	static std::string loginAppRole(const Config &config, const std::string &roleId, const std::string &secretId);

	/// KV v2 mount and path prefix used by both the engine and the tooling.
	static constexpr const char *KV_MOUNT = "secret";
	static constexpr const char *KV_PATH = "appmesh/replication";
};
