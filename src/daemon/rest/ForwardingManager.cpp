// src/daemon/rest/ForwardingManager.cpp
#include "ForwardingManager.h"

#include <chrono>
#include <iomanip>
#include <sstream>
#include <vector>

#include <openssl/evp.h>

#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/json.h"
#include "../Configuration.h"
#include "Data.h"
#include "ForwardingStream.h"
#include "HttpRequest.h"
#include "drogon/TcpClientStream.h"

namespace
{
	constexpr auto EVENT_URI = "/appmesh/event";
	constexpr auto SUBSCRIPTION_HEADER = HTTP_HEADER_KEY_X_Subscription_Id;

	bool isPersistentClient(const std::shared_ptr<HttpRequest> &request)
	{
		return request && request->isPersistentClientTransport();
	}

	std::string responseSubscriptionId(const Response &response)
	{
		if (response.http_status < 200 || response.http_status >= 300 || response.body.empty())
			return {};
		std::string parseError;
		const auto value = JSON::parse(std::string(response.body.begin(), response.body.end()), &parseError);
		if (!value.isObject() || !value.isMember("subscription_id") || !value["subscription_id"].isString())
			return {};
		return value["subscription_id"].asString();
	}

	/// Transport of this build: the TCP API.
	std::shared_ptr<ForwardingStream> createForwardingStream() { return std::make_shared<TcpClientStream>(); }

	/// Fingerprint of the bearer a peer pins at the upgrade; the raw token never
	/// becomes a pool key.
	std::string bearerFingerprint(const std::string &bearer)
	{
		if (bearer.empty())
			return {};

		unsigned char digest[EVP_MAX_MD_SIZE];
		unsigned int length = 0;
		if (EVP_Digest(bearer.data(), bearer.size(), digest, &length, EVP_sha256(), nullptr) != 1)
			throw std::runtime_error("cannot fingerprint the forwarding bearer");

		std::ostringstream encoded;
		encoded << std::hex << std::setfill('0');
		for (unsigned int i = 0; i < length; ++i)
			encoded << std::setw(2) << static_cast<unsigned int>(digest[i]);
		return encoded.str();
	}

	/// Resolves the port a forwarding target is reached on; the API port is
	/// transport specific.
	int normalizeForwardPort(int port)
	{
		auto config = Configuration::instance();
		return port <= 1024 ? config->getTcpApiPort() : port;
	}

	int64_t steadyNowMs()
	{
		return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch())
			.count();
	}
}

// Bounds the blocking connect + TLS handshake to a forwarding peer.
constexpr int FORWARD_CONNECT_TIMEOUT_SECONDS = 10;

// A silent peer keeps its pooled connection open forever; drop it on reuse once
// a request waited this long without a single inbound byte.
constexpr int64_t FORWARD_STALE_RESPONSE_MS = 30 * 1000;

// A rotated-away bearer leaves its connection behind, so drop silent, unused ones.
constexpr int64_t FORWARD_IDLE_REAP_MS = 600 * 1000;

bool ForwardingConnection::addRequest(const std::string &uuid, std::shared_ptr<HttpRequest> request)
{
	if (closed.load(std::memory_order_acquire))
		return false;
	if (!pending_requests.emplace(uuid, std::move(request)))
		return false;
	// failAll() may have swept between insert and this check. Whoever erases
	// the entry owns the reply: if failAll got it, it replies and we report
	// success; if we erase it here, the caller answers with a 502.
	if (closed.load(std::memory_order_acquire) && pending_requests.erase(uuid))
		return false;
	return true;
}

bool ForwardingConnection::hasStaleRequests()
{
	const auto lastResponse = lastResponseTime.load(std::memory_order_relaxed);
	if (lastResponse == 0 || steadyNowMs() - lastResponse <= FORWARD_STALE_RESPONSE_MS)
		return false;
	return !pending_requests.empty();
}

bool ForwardingConnection::idleReapable()
{
	if (closed.load(std::memory_order_acquire))
		return false;
	const auto lastResponse = lastResponseTime.load(std::memory_order_relaxed);
	if (lastResponse == 0 || steadyNowMs() - lastResponse <= FORWARD_IDLE_REAP_MS)
		return false;

	return pending_requests.empty() && subscriptions.empty();
}

std::shared_ptr<HttpRequest> ForwardingConnection::findRequest(const std::string &uuid)
{
	std::shared_ptr<HttpRequest> request;
	pending_requests.visit(uuid, [&request](auto &entry) { request = entry.second; });
	return request;
}

std::shared_ptr<HttpRequest> ForwardingConnection::takeRequest(const std::string &uuid)
{
	std::shared_ptr<HttpRequest> req;
	pending_requests.erase_if(uuid,
							  [&req](auto &entry)
							  {
								  req = entry.second;
								  return true;
							  });
	return req;
}

void ForwardingConnection::rememberSubscription(const std::string &subscriptionId, std::shared_ptr<HttpRequest> request)
{
	if (subscriptionId.empty() || !isPersistentClient(request))
		return;
	subscriptions.insert_or_assign(subscriptionId, std::move(request));
}

std::shared_ptr<HttpRequest> ForwardingConnection::findSubscription(const std::string &subscriptionId)
{
	std::shared_ptr<HttpRequest> request;
	subscriptions.visit(subscriptionId, [&request](auto &entry) { request = entry.second; });
	return request;
}

void ForwardingConnection::removeSubscription(const std::string &subscriptionId)
{
	if (subscriptionId.empty())
		return;
	subscriptions.erase(subscriptionId);
}

void ForwardingConnection::handleResponse(Response &response)
{
	lastResponseTime.store(steadyNowMs(), std::memory_order_relaxed);
	if (response.request_uri == EVENT_URI)
	{
		std::string routeId;
		if (auto route = response.headers.find(HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE); route != response.headers.end())
		{
			routeId = route->second;
			response.headers.erase(route);
		}
		std::string subscriptionId;
		if (auto subscription = response.headers.find(SUBSCRIPTION_HEADER); subscription != response.headers.end())
			subscriptionId = subscription->second;

		auto request = routeId.empty() ? nullptr : findRequest(routeId);
		if (!request && !subscriptionId.empty())
			request = findSubscription(subscriptionId);
		if (request && request->reply(response.request_uri, response.uuid, response.body, response.headers,
									  response.http_status, response.body_msg_type))
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
	request->reply(response.request_uri, response.uuid, response.body, response.headers, response.http_status,
				   response.body_msg_type);
	if (request->m_method == web::http::methods::DEL)
	{
		if (auto subscription = request->m_query.find("subscription_id"); subscription != request->m_query.end())
			removeSubscription(subscription->second);
	}
}

void ForwardingConnection::failAll(const std::string &msg)
{
	// The store orders before the sweep, so a request that inserts afterwards
	// either lands in the sweep or self-erases in addRequest().
	closed.store(true, std::memory_order_release);
	std::vector<std::string> keys;
	pending_requests.visit_all([&keys](auto &entry) { keys.push_back(entry.first); });
	for (auto &uuid : keys)
	{
		std::shared_ptr<HttpRequest> req;
		pending_requests.erase_if(uuid,
								  [&req](auto &entry)
								  {
									  req = entry.second;
									  return true;
								  });
		if (req)
		{
			req->reply(web::http::status_codes::BadGateway, msg);
		}
	}

	std::vector<std::pair<std::string, std::shared_ptr<HttpRequest>>> activeSubscriptions;
	subscriptions.visit_all([&activeSubscriptions](auto &entry)
							{ activeSubscriptions.emplace_back(entry.first, entry.second); });
	subscriptions.clear();
	for (const auto &entry : activeSubscriptions)
	{
		Json::Value eventData;
		eventData["message"] = msg;
		Json::Value event;
		event["subscription_id"] = entry.first;
		event["event_type"] = "__disconnected__";
		event["app_name"] = "";
		event["timestamp"] = 0;
		event["sequence"] = 0;
		event["data"] = eventData;
		const auto text = JSON::dump(event);
		entry.second->reply(EVENT_URI, Utility::shortID(), std::vector<std::uint8_t>(text.begin(), text.end()),
							{{SUBSCRIPTION_HEADER, entry.first}}, web::http::status_codes::OK,
							web::http::mime_types::application_json);
	}
}

ForwardingManager &ForwardingManager::instance()
{
	static ForwardingManager mgr;
	return mgr;
}

std::shared_ptr<ForwardingConnection> ForwardingManager::getOrCreateConnection(const std::string &host, int port,
																			   const std::string &bearer)
{
	static const char fname[] = "ForwardingManager::getOrCreateConnection() ";

	auto stream = createForwardingStream();
	// An upgrade-authenticated peer pins the identity, so the bearer is part of
	// the connection identity.
	const bool pinsPrincipal = stream->pinsHandshakePrincipal();
	std::string fingerprint = pinsPrincipal ? bearerFingerprint(bearer) : std::string();
	std::string key = host + ":" + std::to_string(port); // same host may serve different ports
	if (pinsPrincipal)
		key += "|" + fingerprint;

	std::shared_ptr<ForwardingConnection> conn;
	// Phase 1: check the pool, evict stale
	std::shared_ptr<ForwardingConnection> deadConn;
	std::vector<std::pair<std::string, std::shared_ptr<ForwardingConnection>>> idleConns;
	m_connections.visit(key, [&conn](auto &entry) { conn = entry.second; });
	if (conn)
	{
		// A pooled entry can outlive its socket: validate the stream's own
		// state first or every request would be queued on a dead connection.
		if (!conn->closed.load(std::memory_order_acquire))
		{
			if (conn->stream && conn->stream->connected() && !conn->hasStaleRequests())
				return conn;
			LOG_WAR << fname << "Pooled connection to " << key << " is dead or not answering; evicting and reconnecting";
			deadConn = conn;
		}
		// Erase only the visited entry; a racing thread may have published a new one.
		m_connections.erase_if(key, [&conn](auto &entry) { return entry.second == conn; });
		conn.reset();
	}

	// Only a transport that pins the upgrade identity accumulates per-bearer
	// connections.
	if (pinsPrincipal)
	{
		m_connections.visit_all(
			[&idleConns](auto &entry)
			{
				if (entry.second->idleReapable())
					idleConns.emplace_back(entry.first, entry.second);
			});
		for (const auto &entry : idleConns)
			m_connections.erase_if(entry.first, [&entry](auto &e) { return e.second == entry.second; });
	}
	// Outside m_connections: failAll touches client replies — keep the lock
	// order stream-internal locks → m_connections.
	if (deadConn)
	{
		deadConn->failAll("Forwarding host connection lost");
		if (deadConn->stream)
			deadConn->stream->shutdown();
	}
	for (auto &[extId, conn] : idleConns)
	{
		LOG_INF << fname << "Closing idle forwarding connection to " << extId;
		conn->failAll("Forwarding connection idle");
		if (conn->stream)
			conn->stream->shutdown();
	}

	// Phase 2: create connection outside lock (avoids holding map lock during connect).
	// IMPORTANT: set callbacks BEFORE connect() — the connection/message callbacks
	// can fire as soon as the event loop starts dialing.
	conn = std::make_shared<ForwardingConnection>();
	conn->host = host;
	conn->port = port;
	conn->bearerFingerprint = std::move(fingerprint);
	std::weak_ptr<ForwardingConnection> weakConn = conn;

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
			m_connections.erase_if(key, [&weakConn](auto &entry) { return entry.second == weakConn.lock(); });
		});

	const bool verifyServer = Configuration::instance()->getSslVerifyServer();
	ForwardingConnectOptions options;
	options.host = host;
	options.port = port;
	options.ca = verifyServer
					 ? ClientSSLConfig::resolveAbsolutePath(Utility::getHomeDir(), Configuration::instance()->getSSLCaPath())
					 : std::string();
	options.verifyPeer = verifyServer;
	options.bearer = bearer;
	// A peer that requires client certificates cannot be reached without them.
	auto config = Configuration::instance();
	const auto clientCert = config->getSSLClientCertificateFile();
	if (!clientCert.empty())
	{
		options.clientCert = ClientSSLConfig::resolveAbsolutePath(Utility::getHomeDir(), clientCert);
		options.clientKey =
			ClientSSLConfig::resolveAbsolutePath(Utility::getHomeDir(), config->getSSLClientCertificateKeyFile());
	}
	options.timeoutSeconds = FORWARD_CONNECT_TIMEOUT_SECONDS;
	if (bearer.empty() && pinsPrincipal)
	{
		// A bearer-less hop only works against a loopback peer.
		LOG_WAR << fname << "Forwarding to " << key << " without a bearer; only a loopback peer accepts that upgrade";
	}
	if (!stream->connect(options))
	{
		LOG_ERR << fname << "Failed to connect to forwarding host: " << key;
		return nullptr;
	}
	conn->stream = std::move(stream);
	conn->lastResponseTime.store(steadyNowMs(), std::memory_order_relaxed);

	// Phase 3: publish, handling the race where another thread created the
	// same connection. insert_or_visit runs atomically per key, so exactly one
	// creator wins; a losing creator finds the winner's entry here.
	while (true)
	{
		std::shared_ptr<ForwardingConnection> existing;
		const bool inserted =
			m_connections.insert_or_visit(std::make_pair(key, conn), [&existing](auto &entry) { existing = entry.second; });
		if (inserted)
			return conn;
		if (!existing->closed.load(std::memory_order_acquire))
		{
			// Another thread won the race — close our connection and use theirs
			conn->stream->shutdown();
			return existing;
		}
		// Stale entry: remove only that exact entry and retry.
		m_connections.erase_if(key, [&existing](auto &entry) { return entry.second == existing; });
	}

	return conn;
}

bool ForwardingManager::forward(const std::string &host, int port, const std::shared_ptr<HttpRequest> &request)
{
	static const char fname[] = "ForwardingManager::forward() ";
	LOG_DBG << fname << "Forwarding to host: " << host;

	const int targetPort = normalizeForwardPort(port);
	if (targetPort <= 0)
	{
		request->reply(web::http::status_codes::BadGateway,
					   "Forwarding to other hosts is not available: the target port is not configured");
		return true;
	}

	// Any outbound failure must end as a 502, not as an uncaught exception.
	try
	{
		const auto bearer = request->m_headers.get(HTTP_HEADER_JWT_Authorization);
		auto conn = getOrCreateConnection(host, targetPort, bearer);
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
		if (data.empty() || !conn->stream->send(data.data(), data.size()))
		{
			// Refused send: drop the connection and fail its pending requests now.
			conn->stream->shutdown();
			conn->failAll("Failed to send to forwarding host");
		}

		return true;
	}
	catch (const std::exception &ex)
	{
		LOG_ERR << fname << "Forwarding to <" << host << ":" << targetPort << "> failed: " << ex.what();
	}
	catch (...)
	{
		LOG_ERR << fname << "Forwarding to <" << host << ":" << targetPort << "> failed";
	}
	request->reply(web::http::status_codes::BadGateway, "Forwarding to host failed");
	return true;
}
