// src/daemon/rest/ForwardingManager.h
#pragma once

#include "SocketStream.h"

#include <ace/Map_Manager.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/Thread_Mutex.h>

#include <atomic>
#include <memory>
#include <string>

class HttpRequest;

/// Represents a single forwarding connection to a remote host, with a map
/// of pending requests awaiting responses (correlated by UUID).
struct ForwardingConnection
{
	SocketStreamPtr stream;
	using PendingRequestMap = ACE_Map_Manager<std::string, std::shared_ptr<HttpRequest>, ACE_Thread_Mutex>;
	PendingRequestMap pending_requests;
	std::atomic<bool> closed{false};

	/// Atomically checks closed flag and binds request under pending_requests lock.
	/// Returns false if the connection is closed or bind fails.
	bool addRequest(const std::string &uuid, std::shared_ptr<HttpRequest> request);

	std::shared_ptr<HttpRequest> takeRequest(const std::string &uuid);
	void failAll(const std::string &msg);
};

/// Manages a pool of forwarding connections to remote hosts.
///
/// Key rule: getOrCreateConnection() MUST NOT hold m_connections lock while calling
/// createConnection() — that would block the reactor's onClose unbind path → deadlock.
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
	std::shared_ptr<ForwardingConnection> getOrCreateConnection(const std::string &host, int port);

	using ForwardingClientMap = ACE_Map_Manager<std::string, std::shared_ptr<ForwardingConnection>, ACE_Recursive_Thread_Mutex>;
	ForwardingClientMap m_connections;
};
