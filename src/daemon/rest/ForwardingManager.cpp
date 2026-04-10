// src/daemon/rest/ForwardingManager.cpp
#include "ForwardingManager.h"
#include "Data.h"
#include "HttpRequest.h"

bool ForwardingConnection::addRequest(const std::string &uuid, std::shared_ptr<HttpRequest> request)
{
	// TOCTOU fix: check closed and bind atomically under the same lock
	ACE_GUARD_RETURN(ACE_Thread_Mutex, guard, pending_requests.mutex(), false);
	if (closed.load(std::memory_order_acquire))
		return false;
	return pending_requests.bind(uuid, std::move(request)) == 0;
}

std::shared_ptr<HttpRequest> ForwardingConnection::takeRequest(const std::string &uuid)
{
	std::shared_ptr<HttpRequest> req;
	pending_requests.unbind(uuid, req);
	return req;
}

void ForwardingConnection::failAll(const std::string &msg)
{
	std::vector<std::string> keys;
	{
		ACE_GUARD(ACE_Thread_Mutex, guard, pending_requests.mutex());
		closed.store(true, std::memory_order_release);
		for (auto iter = pending_requests.begin(); iter != pending_requests.end(); ++iter)
		{
			keys.push_back((*iter).ext_id_);
		}
	}
	for (auto &uuid : keys)
	{
		std::shared_ptr<HttpRequest> req;
		if (pending_requests.unbind(uuid, req) == 0 && req)
		{
			req->reply(web::http::status_codes::BadGateway, msg);
		}
	}
}

ForwardingManager &ForwardingManager::instance()
{
	static ForwardingManager mgr;
	return mgr;
}

std::shared_ptr<ForwardingConnection> ForwardingManager::getOrCreateConnection(const std::string &host, int port)
{
	static const char fname[] = "ForwardingManager::getOrCreateConnection() ";

	std::shared_ptr<ForwardingConnection> conn;

	// Phase 1: check under lock, remove stale
	{
		ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, guard, m_connections.mutex(), nullptr);

		if (m_connections.find(host, conn) == 0)
		{
			if (!conn->closed.load(std::memory_order_acquire))
				return conn;
			m_connections.unbind(host);
			conn.reset();
		}
	}

	// Phase 2: create connection outside lock (avoids holding map lock during connect)
	// IMPORTANT: set callbacks BEFORE connect(), because connect() calls open() which
	// registers with the reactor — after that, handle_input/handle_close can fire immediately.
	conn = std::make_shared<ForwardingConnection>();
	std::weak_ptr<ForwardingConnection> weakConn = conn;

	SocketStreamPtr stream(new SocketStream(Global::getClientSSL()));

	stream->onData(
		[weakConn](std::vector<std::uint8_t> &&data)
		{
			auto c = weakConn.lock();
			if (!c)
				return;
			Response r;
			if (r.deserialize(data.data(), data.size()))
			{
				auto req = c->takeRequest(r.uuid);
				if (req)
				{
					req->reply(r.request_uri, r.uuid, r.body, r.headers, r.http_status, r.body_msg_type);
				}
				else
				{
					LOG_WAR << "ForwardingManager: Received response for unknown UUID: " << r.uuid;
				}
			}
			else
			{
				LOG_ERR << "ForwardingManager: Failed to deserialize forwarded response";
				c->failAll("Corrupted response from forwarding host");
			}
		});

	// Safe: ForwardingManager is a process-lifetime singleton
	stream->onClose(
		[this, weakConn, host]()
		{
			LOG_WAR << "ForwardingManager: Forwarding connection to " << host << " closed";
			if (auto c = weakConn.lock())
			{
				c->failAll("Forwarding host connection closed");
			}
			// Only unbind if the mapped connection is this one (not a race winner)
			ACE_GUARD(ACE_Recursive_Thread_Mutex, guard, m_connections.mutex());
			std::shared_ptr<ForwardingConnection> current;
			if (m_connections.find(host, current) == 0 && current == weakConn.lock())
				m_connections.unbind(host);
		});

	// Now connect (this calls open() which registers with reactor)
	if (!stream->connect(ACE_INET_Addr(port, host.c_str())))
	{
		LOG_ERR << fname << "Failed to connect to forwarding host: " << host;
		return nullptr;
	}
	conn->stream = std::move(stream);

	// Phase 3: bind under lock, handle race where another thread created the same connection
	{
		ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, guard, m_connections.mutex(), nullptr);
		std::shared_ptr<ForwardingConnection> existing;
		if (m_connections.find(host, existing) == 0 && !existing->closed.load(std::memory_order_acquire))
		{
			// Another thread won the race — close our connection and use theirs
			conn->stream->shutdown();
			return existing;
		}
		m_connections.unbind(host); // Remove any stale entry
		m_connections.bind(host, conn);
	}

	return conn;
}

bool ForwardingManager::forward(const std::string &host, int port, const std::shared_ptr<HttpRequest> &request)
{
	static const char fname[] = "ForwardingManager::forward() ";
	LOG_DBG << fname << "Forwarding to host: " << host;

	auto conn = getOrCreateConnection(host, port);
	if (!conn)
	{
		request->reply(web::http::status_codes::BadGateway, "Failed to connect to forwarding host");
		return true;
	}

	// Register request before sending so the response callback can find it
	if (!conn->addRequest(request->m_uuid, request))
	{
		request->reply(web::http::status_codes::BadGateway, "Forwarding connection closed");
		return true;
	}

	auto data = request->serialize();
	if (!conn->stream->send(std::move(data)))
	{
		// Send failed — remove pending request and notify caller
		auto req = conn->takeRequest(request->m_uuid);
		if (req)
		{
			req->reply(web::http::status_codes::BadGateway, "Failed to send to forwarding host");
		}
	}

	return true;
}
