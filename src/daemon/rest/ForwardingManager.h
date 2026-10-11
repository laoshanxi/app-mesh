// src/daemon/rest/ForwardingManager.h
#pragma once

#include <atomic>
#include <memory>
#include <string>

#include <boost/unordered/concurrent_flat_map.hpp>

class ForwardingStream;
class HttpRequest;
class Response;

/// Represents a single forwarding connection to a remote host, with a map
/// of pending requests awaiting responses (correlated by UUID).
struct ForwardingConnection
{
	std::shared_ptr<ForwardingStream> stream;
	// Both maps lock internally per operation; whoever erases a request owns
	// its reply (addRequest vs failAll race rule).
	using PendingRequestMap = boost::concurrent_flat_map<std::string, std::shared_ptr<HttpRequest>>;
	PendingRequestMap pending_requests;
	using SubscriptionMap = boost::concurrent_flat_map<std::string, std::shared_ptr<HttpRequest>>;
	SubscriptionMap subscriptions;
	std::atomic<bool> closed{false};
	// Time of the last accepted connect or received response.
	std::atomic<int64_t> lastResponseTime{0};

	// Identity of the hop, so the pool key never has to be parsed apart.
	std::string host;
	int port = 0;
	std::string bearerFingerprint; // empty when the transport pins no principal

	/// Atomically checks closed flag and binds request under pending_requests lock.
	/// Returns false if the connection is closed or bind fails.
	bool addRequest(const std::string &uuid, std::shared_ptr<HttpRequest> request);

	std::shared_ptr<HttpRequest> findRequest(const std::string &uuid);
	std::shared_ptr<HttpRequest> takeRequest(const std::string &uuid);
	void rememberSubscription(const std::string &subscriptionId, std::shared_ptr<HttpRequest> request);
	std::shared_ptr<HttpRequest> findSubscription(const std::string &subscriptionId);
	void removeSubscription(const std::string &subscriptionId);
	void handleResponse(Response &response);
	void failAll(const std::string &msg);

	/// True when requests wait while the peer stayed silent past the stale bound.
	bool hasStaleRequests();

	/// True when the hop carries no work and stayed silent past the idle bound.
	bool idleReapable();
};

/// Manages a pool of forwarding connections to remote hosts.
///
/// Key rule: getOrCreateConnection() must not touch the pool map while the
/// blocking connect/TLS handshake runs — map operations are internally
/// locked, so a connect inside a visitation would stall the event loop's
/// close/unbind path.
class ForwardingManager
{
public:
	ForwardingManager() = default;
	~ForwardingManager() = default;

	ForwardingManager(const ForwardingManager &) = delete;
	ForwardingManager &operator=(const ForwardingManager &) = delete;

	static ForwardingManager &instance();

	/// Forward an HTTP request to a remote host. Returns true if the request
	/// was handled (even if forwarding failed — the request gets a 502 reply).
	bool forward(const std::string &host, int port, const std::shared_ptr<HttpRequest> &request);

private:
	std::shared_ptr<ForwardingConnection> getOrCreateConnection(const std::string &host, int port, const std::string &bearer);

	using ForwardingClientMap = boost::concurrent_flat_map<std::string, std::shared_ptr<ForwardingConnection>>;
	ForwardingClientMap m_connections;
};
