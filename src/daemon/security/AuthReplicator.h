#pragma once

#include <atomic>
#include <string>

/// Pull-based authorization policy replication (single-writer replica model).
///
/// A follower periodically fetches the owner's policy snapshot and applies it
/// to its local AuthorizationStore, which also persists it to the replica
/// cache. This replaces the manual copy-the-file procedure: the owner is the
/// only writer, followers converge like read replicas, and a follower-local
/// auto-provisioned record cannot shadow the owner's binding.
///
/// No thread of its own: the daemon's schedule loop drives onScheduleTick(),
/// the same pattern the JWKS refresh uses.
class AuthReplicator
{
public:
	static AuthReplicator &instance();

	/// Reads the replication env config; on the owner side (token file only)
	/// publishes the shared token. No-op without APPMESH_AUTH_REPLICATION_TOKEN_FILE.
	void start();

	/// Called from the daemon schedule loop every stepSeconds. Pulls once per
	/// interval, and immediately when notifyPolicyMiss() fired in between.
	void onScheduleTick(int stepSeconds);

	/// Ask for a prompt pull: a login resolved a principal this node has never
	/// seen, so the owner's binding for it should arrive before the interval.
	void notifyPolicyMiss();

	AuthReplicator(const AuthReplicator &) = delete;
	AuthReplicator &operator=(const AuthReplicator &) = delete;

private:
	AuthReplicator() = default;
	void pullOnce();
	/// Owner side: create the shared token file with random content when absent.
	void ensureOwnerTokenFile();

	std::string m_source;    // scheme://host[:port] of the owner engine listener
	std::string m_tokenFile; // shared replication bearer token file
	std::string m_caPath;    // optional CA to verify the owner TLS certificate
	int m_intervalSeconds = 30;
	int m_elapsedSeconds = 0;
	std::atomic<bool> m_enabled{false};
	std::atomic<bool> m_missPending{false};
};
