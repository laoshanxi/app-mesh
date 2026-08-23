// src/daemon/rest/ForwardingManager.cpp
#include "ForwardingManager.h"
#include "Data.h"
#include "HttpRequest.h"

namespace
{
	constexpr auto EVENT_URI = "/appmesh/event";
	constexpr auto SUBSCRIPTION_HEADER = "X-Subscription-Id";

	bool isPersistentClient(const std::shared_ptr<HttpRequest> &request)
	{
		return request && request->isPersistentClientTransport();
	}

	std::string responseSubscriptionId(const Response &response)
	{
		if (response.http_status < 200 || response.http_status >= 300 || response.body.empty())
			return {};
		const auto value = nlohmann::json::parse(response.body.begin(), response.body.end(), nullptr, false);
		if (!value.is_object() || !value.contains("subscription_id") ||
			!value.at("subscription_id").is_string())
			return {};
		return value.at("subscription_id").get<std::string>();
	}
}

// Bounds the blocking TCP connect + TLS handshake to a forwarding peer, so an
// unreachable host cannot pin a worker thread for the OS connect timeout (minutes).
constexpr int FORWARD_CONNECT_TIMEOUT_SECONDS = 10;

bool ForwardingConnection::addRequest(const std::string &uuid, std::shared_ptr<HttpRequest> request)
{
	// TOCTOU fix: check closed and bind atomically under the same lock
	ACE_GUARD_RETURN(ACE_Thread_Mutex, guard, pending_requests.mutex(), false);
	if (closed.load(std::memory_order_acquire))
		return false;
	return pending_requests.bind(uuid, std::move(request)) == 0;
}

std::shared_ptr<HttpRequest> ForwardingConnection::findRequest(const std::string &uuid)
{
	ACE_GUARD_RETURN(ACE_Thread_Mutex, guard, pending_requests.mutex(), nullptr);
	std::shared_ptr<HttpRequest> request;
	pending_requests.find(uuid, request);
	return request;
}

std::shared_ptr<HttpRequest> ForwardingConnection::takeRequest(const std::string &uuid)
{
	std::shared_ptr<HttpRequest> req;
	pending_requests.unbind(uuid, req);
	return req;
}

void ForwardingConnection::rememberSubscription(const std::string &subscriptionId,
	std::shared_ptr<HttpRequest> request)
{
	if (subscriptionId.empty() || !isPersistentClient(request))
		return;
	ACE_GUARD(ACE_Thread_Mutex, guard, subscriptions.mutex());
	std::shared_ptr<HttpRequest> previous;
	subscriptions.unbind(subscriptionId, previous);
	subscriptions.bind(subscriptionId, std::move(request));
}

std::shared_ptr<HttpRequest> ForwardingConnection::findSubscription(const std::string &subscriptionId)
{
	ACE_GUARD_RETURN(ACE_Thread_Mutex, guard, subscriptions.mutex(), nullptr);
	std::shared_ptr<HttpRequest> request;
	subscriptions.find(subscriptionId, request);
	return request;
}

void ForwardingConnection::removeSubscription(const std::string &subscriptionId)
{
	if (subscriptionId.empty())
		return;
	std::shared_ptr<HttpRequest> request;
	subscriptions.unbind(subscriptionId, request);
}

void ForwardingConnection::handleResponse(Response &response)
{
	if (response.request_uri == EVENT_URI)
	{
		std::string routeId;
		auto route = response.headers.find(HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE);
		if (route != response.headers.end())
		{
			routeId = route->second;
			response.headers.erase(route);
		}
		std::string subscriptionId;
		auto subscription = response.headers.find(SUBSCRIPTION_HEADER);
		if (subscription != response.headers.end())
			subscriptionId = subscription->second;

		auto request = routeId.empty() ? nullptr : findRequest(routeId);
		if (!request && !subscriptionId.empty())
			request = findSubscription(subscriptionId);
		if (request && request->reply(response.request_uri, response.uuid, response.body,
			response.headers, response.http_status, response.body_msg_type))
			return;
		removeSubscription(subscriptionId);
		LOG_WAR << "ForwardingManager: Received event without an active frontend route";
		return;
	}

	auto request = takeRequest(response.uuid);
	if (!request)
	{
		LOG_WAR << "ForwardingManager: Received response for unknown UUID: " << response.uuid;
		return;
	}
	rememberSubscription(responseSubscriptionId(response), request);
	request->reply(response.request_uri, response.uuid, response.body,
		response.headers, response.http_status, response.body_msg_type);
	if (request->m_method == web::http::methods::DEL)
	{
		auto subscription = request->m_query.find("subscription_id");
		if (subscription != request->m_query.end())
			removeSubscription(subscription->second);
	}
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

	std::vector<std::pair<std::string, std::shared_ptr<HttpRequest>>> activeSubscriptions;
	{
		ACE_GUARD(ACE_Thread_Mutex, guard, subscriptions.mutex());
		for (auto iter = subscriptions.begin(); iter != subscriptions.end(); ++iter)
			activeSubscriptions.emplace_back((*iter).ext_id_, (*iter).int_id_);
		subscriptions.unbind_all();
	}
	for (const auto &entry : activeSubscriptions)
	{
		nlohmann::json event = {
			{"subscription_id", entry.first},
			{"event_type", "__disconnected__"},
			{"app_name", ""},
			{"timestamp", 0},
			{"sequence", 0},
			{"data", {{"message", msg}}}};
		const auto text = event.dump();
		entry.second->reply(EVENT_URI, Utility::shortID(),
			std::vector<std::uint8_t>(text.begin(), text.end()),
			{{SUBSCRIPTION_HEADER, entry.first}}, web::http::status_codes::OK,
			web::http::mime_types::application_json);
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
	const std::string key = host + ":" + std::to_string(port); // same host may serve different ports

	// Phase 1: check under lock, remove stale
	{
		ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, guard, m_connections.mutex(), nullptr);

		if (m_connections.find(key, conn) == 0)
		{
			if (!conn->closed.load(std::memory_order_acquire))
				return conn;
			m_connections.unbind(key);
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
					c->handleResponse(r);
			}
			else
			{
				LOG_ERR << "ForwardingManager: Failed to deserialize forwarded response";
				c->failAll("Corrupted response from forwarding host");
			}
		});

	// Safe: ForwardingManager is a process-lifetime singleton
	stream->onClose(
		[this, weakConn, key]()
		{
			LOG_WAR << "ForwardingManager: Forwarding connection to " << key << " closed";
			if (auto c = weakConn.lock())
			{
				c->failAll("Forwarding host connection closed");
			}
			// Only unbind if the mapped connection is this one (not a race winner)
			ACE_GUARD(ACE_Recursive_Thread_Mutex, guard, m_connections.mutex());
			std::shared_ptr<ForwardingConnection> current;
			if (m_connections.find(key, current) == 0 && current == weakConn.lock())
				m_connections.unbind(key);
		});

	// Now connect (this calls open() which registers with reactor)
	ACE_Time_Value connectTimeout(FORWARD_CONNECT_TIMEOUT_SECONDS);
	if (!stream->connect(ACE_INET_Addr(port, host.c_str()), &connectTimeout))
	{
		LOG_ERR << fname << "Failed to connect to forwarding host: " << key;
		return nullptr;
	}
	conn->stream = std::move(stream);

	// Phase 3: bind under lock, handle race where another thread created the same connection
	{
		ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, guard, m_connections.mutex(), nullptr);
		std::shared_ptr<ForwardingConnection> existing;
		if (m_connections.find(key, existing) == 0 && !existing->closed.load(std::memory_order_acquire))
		{
			// Another thread won the race — close our connection and use theirs
			conn->stream->shutdown();
			return existing;
		}
		m_connections.unbind(key); // Remove any stale entry
		m_connections.bind(key, conn);
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
