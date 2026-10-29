#pragma once

#include <condition_variable>
#include <mutex>
#include <string>
#include <thread>

/// Pull-based authorization policy replication (single-writer replica model).
///
/// A follower periodically fetches the owner's policy snapshot and applies it
/// to its local AuthorizationStore, which also persists it to the replica
/// cache. This replaces the manual copy-the-file procedure: the owner is the
/// only writer, followers converge like read replicas, and a follower-local
/// auto-provisioned record cannot shadow the owner's binding.
///
/// A resident worker thread owns the pull cadence (the HealthCheckTask
/// pattern): a pull can block on a slow or gone owner, so the scheduler loop
/// must never run it inline.
class AuthReplicator
{
public:
	static AuthReplicator &instance();

	/// Reads the replication env config; on the owner side (token file only)
	/// publishes the shared token. No-op without APPMESH_AUTH_REPLICATION_TOKEN_FILE.
	void start();

	/// Ask for a prompt pull: a login resolved a principal this node has never
	/// seen, so the owner's binding for it should arrive before the interval.
	void notifyPolicyMiss();

	AuthReplicator(const AuthReplicator &) = delete;
	AuthReplicator &operator=(const AuthReplicator &) = delete;

private:
	AuthReplicator() = default;
	~AuthReplicator();
	void run();
	void pullOnce();
	/// Owner side: create the shared token file with random content when absent.
	void ensureOwnerTokenFile();

	std::string m_source;    // scheme://host[:port] of the owner engine listener
	std::string m_tokenFile; // shared replication bearer token file
	std::string m_caPath;    // optional CA to verify the owner TLS certificate
	int m_intervalSeconds = 30;
	std::mutex m_mutex;
	std::condition_variable m_wakeup;
	std::thread m_worker;
	bool m_missPending = false; // guarded by m_mutex
	bool m_stopped = false;     // guarded by m_mutex
};
