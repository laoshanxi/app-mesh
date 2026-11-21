// src/daemon/rest/Worker.cpp

#include "Worker.h"

#include "../../common/QuitHandler.h"
#include "../../common/UriParser.hpp"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../security/HMACVerifier.h"
#include "../security/RequestHardening.h"
#include "../security/Security.h"
#include "Data.h"
#include "ForwardingManager.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "SocketServer.h"
#include "../../common/lwsservice/WebSocketService.h"

#include <memory>
#include <set>
#include <utility>

// Global backpressure cap on the shared inbound queue (TCP + lws). Bounds a
// request-flood DoS: a client sending faster than workers drain is shed, not buffered.
static constexpr size_t MAX_PENDING_REQUESTS = 10000;

namespace
{
	bool isSubscriptionRequest(const std::shared_ptr<HttpRequest> &request)
	{
		const auto &path = request->m_relative_uri;
		return path == "/appmesh/subscribe" ||
			(path.size() > 10 && path.compare(path.size() - 10, 10, "/subscribe") == 0) ||
			request->m_query.count("subscribe_events") != 0;
	}

	// Request hardening (replay protection + signature) shared by every
	// transport that funnels through the worker pool.
	bool enforceRequestHardening(const std::shared_ptr<HttpRequest> &request)
	{
		const static char fname[] = "enforceRequestHardening() ";
		RequestHardening::Input input;
		input.method = request->m_method;
		const auto queryAt = request->m_relative_uri.find('?');
		input.path = queryAt == std::string::npos ? request->m_relative_uri
												  : request->m_relative_uri.substr(0, queryAt);
		input.query = request->m_query;
		if (request->m_body && !request->m_body->empty())
		{
			input.body = request->m_body->data();
			input.bodySize = request->m_body->size();
		}
		// File routes verify against the documented exemption: the "/ws"
		// channel suffix is stripped and the body hashes empty, so a signed
		// request verifies identically direct and through forwarding.
		input.path = RequestHardening::canonicalFileRoute(input.path, input.body, input.bodySize);
		input.bearer = request->m_headers.get(HTTP_HEADER_JWT_Authorization);
		input.transportPrincipal = request->transportPrincipalId();
		input.persistentTransport = request->isPersistentClientTransport();
		input.fallbackNonce = request->m_uuid;
		input.keyId = request->m_headers.get(HTTP_HEADER_KEY_X_Request_Key);
		// An oversized key id is hostile input, not a signing key.
		if (input.keyId.size() > 256)
			input.keyId.clear();
		input.timestamp = request->m_headers.get(HTTP_HEADER_KEY_X_Timestamp);
		input.nonce = request->m_headers.get(HTTP_HEADER_KEY_X_Nonce);
		input.signature = request->m_headers.get(HTTP_HEADER_KEY_X_Signature);
		input.agentPrecheck = request->m_headers.get(HTTP_HEADER_KEY_X_Appmesh_Agent_Precheck) == "1";

		const auto decision = RequestHardening::instance().evaluate(input);
		if (decision.audit)
		{
			LOG_WAR << fname << "tolerated request hardening violation from <" << request->m_remote_address << ">: "
					<< decision.reason;
		}
		if (decision.action == RequestHardening::Decision::Action::Reject)
		{
			LOG_WAR << fname << "rejected request from <" << request->m_remote_address << "> path <"
					<< request->m_relative_uri << ">: " << decision.reason;
			request->reply(static_cast<web::http::status_code>(decision.status),
						   Utility::text2json(decision.reason));
			return false;
		}
		return true;
	}

	// Bearer authentication for the frame and gateway paths: returns the
	// principal id via `principalId` and true on success; false after the
	// failure reply went out (503 for an unavailable authentication backend,
	// 401 + challenge for a bad bearer).
	bool authenticateBearerOrReply(const std::shared_ptr<HttpRequest> &request, std::string &principalId)
	{
		try
		{
			principalId = Security::authenticateBearerAuthorization(request->m_headers.get(HTTP_HEADER_JWT_Authorization)).id();
			return true;
		}
		catch (const AuthenticationUnavailableException &e)
		{
			request->reply(web::http::status_codes::ServiceUnavailable, Utility::text2json(e.what()));
		}
		catch (const std::exception &e)
		{
			request->reply(web::http::status_codes::Unauthorized, Utility::text2json(e.what()),
				{{"WWW-Authenticate", HTTP_HEADER_VALUE_BEARER_CHALLENGE ", error=\"invalid_token\""}});
		}
		return false;
	}

	// Extract the request uuid without decoding the full message, so an
	// undecodable request can still be answered with a correlated error.
	std::string recoverRequestUuid(const ByteBuffer &data)
	{
		try
		{
			msgpack::unpacked result;
			msgpack::unpack(result, reinterpret_cast<const char *>(data.data()), data.size());
			const auto obj = result.get();
			if (obj.type != msgpack::type::MAP)
				return {};
			for (std::uint32_t i = 0; i < obj.via.map.size; ++i)
			{
				const auto &entry = obj.via.map.ptr[i];
				if (entry.key.type == msgpack::type::STR && entry.key.as<std::string>() == "uuid" &&
					entry.val.type == msgpack::type::STR)
					return entry.val.as<std::string>();
			}
		}
		catch (...)
		{
		}
		return {};
	}

	std::unique_ptr<Response> errorResponse(const std::string &uuid, web::http::status_code status, const std::string &message)
	{
		auto response = std::make_unique<Response>();
		response->uuid = uuid;
		response->http_status = status;
		response->body_msg_type = web::http::mime_types::application_json;
		const auto text = Utility::text2json(message).dump();
		response->body.assign(text.begin(), text.end());
		return response;
	}
}

struct HttpRequestContext
{
	ByteBuffer m_data;
	int m_tcpClientId = -1;
	LwsSessionRef m_lwsRef{};
	// Explicit shutdown marker (an empty m_data must never mean shutdown: a zero-length
	// frame would then let any client kill a worker).
	bool m_isShutdownSentinel = false;
};

bool Worker::enqueueRequest(const std::shared_ptr<HttpRequestContext> &ctx)
{
	static const char fname[] = "Worker::enqueueRequest() ";
	if (m_pendingCount.fetch_add(1, std::memory_order_relaxed) + 1 > MAX_PENDING_REQUESTS)
	{
		m_pendingCount.fetch_sub(1, std::memory_order_relaxed);
		LOG_WAR << fname << "Inbound queue saturated (" << MAX_PENDING_REQUESTS << "), rejecting request";
		return false;
	}
	// enqueue only fails/throws on allocation failure; roll back the reserved slot so
	// the counter can't ratchet up and permanently wedge the cap.
	bool enqueued = false;
	try
	{
		enqueued = m_messages.enqueue(ctx);
	}
	catch (...)
	{
		enqueued = false;
	}
	if (!enqueued)
	{
		m_pendingCount.fetch_sub(1, std::memory_order_relaxed);
		LOG_ERR << fname << "Failed to enqueue request (allocation failure)";
		return false;
	}
	return true;
}

bool Worker::replyErrorLws(const LwsSessionRef &lwsRef, const ByteBuffer &data,
						   web::http::status_code status, const std::string &message)
{
	const auto uuid = recoverRequestUuid(data);
	if (uuid.empty() || !lwsRef)
		return false;

	auto resp = std::make_unique<WSResponse>();
	resp->m_session_ref = const_cast<void *>(lwsRef.wsi);
	resp->m_req_id = lwsRef.reqId;
	resp->m_session_id = lwsRef.sessionId;
	resp->m_payload = errorResponse(uuid, status, message)->serialize();
	resp->m_is_http = lwsRef.httpFrame;
	WebSocketService::instance()->enqueueOutgoingResponse(std::move(resp));
	return true;
}

void Worker::queueTcpRequest(ByteBuffer &&data, int tcpClientId)
{
	auto ctx = std::make_shared<HttpRequestContext>();
	ctx->m_data = std::move(data);
	ctx->m_tcpClientId = tcpClientId;
	if (!enqueueRequest(ctx))
	{
		// Shed with an immediate error instead of letting the client wait for its own timeout.
		const auto uuid = recoverRequestUuid(ctx->m_data);
		if (uuid.empty())
			SocketServer::closeClient(tcpClientId);
		else
		{
			auto resp = errorResponse(uuid, web::http::status_codes::ServiceUnavailable, "Request queue is saturated");
			SocketServer::replyTcp(tcpClientId, std::move(resp));
		}
	}
}

void Worker::queueLwsRequest(ByteBuffer &&data, LwsSessionRef lwsRef)
{
	auto ctx = std::make_shared<HttpRequestContext>();
	ctx->m_data = std::move(data);
	ctx->m_lwsRef = lwsRef;
	if (!enqueueRequest(ctx))
		replyErrorLws(lwsRef, ctx->m_data, web::http::status_codes::ServiceUnavailable, "Request queue is saturated");
}

int Worker::svc()
{
	static const char fname[] = "Worker::svc() ";
	Utility::setThreadName("appmesh-worker");
	LOG_INF << fname << "Worker thread started";

	while (!QuitHandler::instance()->shouldExit())
	{
		std::shared_ptr<HttpRequestContext> requestContext;
		m_messages.wait_dequeue(requestContext);

		// Sentinel check — explicit flag only (never data-derived), see HttpRequestContext.
		if (!requestContext || requestContext->m_isShutdownSentinel)
		{
			LOG_INF << fname << "Received shutdown sentinel";
			break;
		}
		m_pendingCount.fetch_sub(1, std::memory_order_relaxed); // matched to enqueueRequest reservation

		auto request = HttpRequest::deserialize(requestContext->m_data, requestContext->m_tcpClientId, requestContext->m_lwsRef);

		if (!request || !process(request))
		{
			LOG_WAR << fname << "Failed to parse or process request, closing connection | ClientID=" << requestContext->m_tcpClientId;

			// Answer with a correlated 400 so the client fails at once instead of
			// waiting for its own timeout; without a uuid there is nothing to
			// correlate, so fall back to closing (TCP) or dropping (WS).
			if (requestContext->m_tcpClientId > 0)
			{
				const auto uuid = recoverRequestUuid(requestContext->m_data);
				if (!uuid.empty())
					SocketServer::replyTcp(requestContext->m_tcpClientId,
										   errorResponse(uuid, web::http::status_codes::BadRequest, "Unable to decode the request"));
				else
					SocketServer::closeClient(requestContext->m_tcpClientId);
			}
			else if (requestContext->m_lwsRef)
			{
				replyErrorLws(requestContext->m_lwsRef, requestContext->m_data,
							  web::http::status_codes::BadRequest, "Unable to decode the request");
			}
		}
	}

	LOG_INF << fname << "Worker thread exiting";
	return 0;
}

void Worker::shutdown()
{
	const size_t threadNum = this->thr_count();
	for (size_t i = 0; i < threadNum; ++i)
	{
		auto sentinel = std::make_shared<HttpRequestContext>();
		sentinel->m_isShutdownSentinel = true;
		m_messages.enqueue(std::move(sentinel)); // bypass the cap: shutdown must always enqueue
	}
}

// CSRF: reject cross-origin, cookie-authenticated, state-changing requests. Only cookie auth is
// CSRF-relevant (Bearer/SDK exempt); a missing Origin passes; allowed = same-origin (via
// X-Forwarded-Host/Host) plus the configured CsrfAllowedOrigins.
static bool isCsrfViolation(const std::shared_ptr<HttpRequest> &request)
{
	const auto &headers = request->m_headers;
	if (!headers.contains("cookie"))
		return false;

	const auto &m = request->m_method;
	if (!(m == web::http::methods::POST || m == web::http::methods::PUT || m == web::http::methods::DEL))
		return false;

	const auto origin = Utility::stdStringTrim(headers.get("origin"));
	if (origin.empty())
		return false; // same-origin / non-browser
	if (Configuration::instance()->getCsrfAllowedOrigins().count(origin) > 0)
		return false; // explicitly allow-listed

	// Same-origin: match Origin host[:port] against the browser-facing host. Prefer
	// X-Forwarded-Host (set by the proxy) since behind nginx/agent the daemon's Host is upstream.
	// Safe on the direct path only because x-forwarded-host is non-safelisted — never add it to
	// the CORS Access-Control-Allow-Headers list, or a cross-site request could forge same-origin.
	auto host = Utility::stdStringTrim(headers.get("x-forwarded-host"));
	if (host.empty())
		host = Utility::stdStringTrim(headers.get("host"));
	if (!host.empty())
	{
		auto originHostPort = origin;
		const auto schemeEnd = originHostPort.find("://");
		if (schemeEnd != std::string::npos)
			originHostPort = originHostPort.substr(schemeEnd + 3);
		originHostPort = originHostPort.substr(0, originHostPort.find('/'));
		if (originHostPort == host)
			return false;
	}
	return true;
}

bool Worker::process(const std::shared_ptr<HttpRequest> &request)
{
	static const char fname[] = "Worker::process() ";
	if (request->m_relative_uri.find("?process_key=") != std::string::npos ||
		request->m_relative_uri.find("&process_key=") != std::string::npos)
	{
		LOG_WAR << fname << "Rejected legacy process-key URI authentication";
		request->reply(web::http::status_codes::BadRequest,
			Utility::text2json("process_key URI authentication is not supported"));
		return true;
	}

	LOG_DBG << fname << request->m_method << " from <"
				<< request->m_remote_address << "> path <"
				<< request->m_relative_uri << "> id <"
				<< request->m_uuid << ">";
	RESTHANDLER::instance()->observeHttpRequest(request);

	if (!request->transportPrincipalId().empty() &&
		request->m_headers.contains(HTTP_HEADER_JWT_Authorization))
	{
		std::string framePrincipalId;
		if (!authenticateBearerOrReply(request, framePrincipalId))
			return true;
		if (framePrincipalId != request->transportPrincipalId())
		{
			request->reply(web::http::status_codes::Forbidden,
				Utility::text2json("WebSocket frame cannot change the session principal"));
			return true;
		}
	}

	if (isCsrfViolation(request))
	{
		LOG_WAR << fname << "CSRF: rejected cross-origin cookie request, path <" << request->m_relative_uri
				<< "> origin <" << request->m_headers.get("origin") << ">";
		request->reply(web::http::status_codes::Forbidden, Utility::text2json("CSRF validation failed: origin not allowed"));
		return true;
	}

	// Replay protection and request signature run after CSRF and before
	// forwarding: the entry node decides, and the four signature headers stay
	// on the forwarded request so the target node can re-verify.
	if (!enforceRequestHardening(request))
		return true;

	if (request->m_headers.contains(HTTP_HEADER_KEY_Forwarding_Host))
	{
		if (request->isManagedWorkerTransport() ||
			request->m_headers.contains(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY) ||
			request->m_headers.contains(HMAC_HTTP_HEADER))
		{
			request->reply(web::http::status_codes::Forbidden,
				Utility::text2json("managed process proof cannot be forwarded"));
			return true;
		}

		// Forwarding is a capability regardless of the target path: an unauthenticated
		// caller must never get an outbound connection (port-scan oracle).
		if (!request->m_headers.contains(HTTP_HEADER_JWT_Authorization))
		{
			request->reply(web::http::status_codes::Unauthorized,
				Utility::text2json("Forwarded requests require bearer authentication"),
				{{"WWW-Authenticate", HTTP_HEADER_VALUE_BEARER_CHALLENGE}});
			return true;
		}
		// A WebSocket frame with a bearer was already checked against the pinned
		// session principal above. HTTP and TCP have no pinned principal, so validate
		// their bearer before the gateway opens an outbound connection. The target
		// validates the unchanged bearer again and makes the authorization decision.
		std::string gatewayPrincipalId = request->transportPrincipalId();
		if (gatewayPrincipalId.empty())
		{
			if (!authenticateBearerOrReply(request, gatewayPrincipalId))
				return true;
		}
		// The outbound connection itself is a capability: without this gate any
		// authenticated principal could probe the network through open/closed/
		// timeout answers (blind port-scan oracle).
		try
		{
			Security::requirePermission(gatewayPrincipalId, PERMISSION_KEY_host_forward);
		}
		catch (const std::exception &e)
		{
			// AuthorizationException, or the principal vanished after the
			// bearer check above; either way fail closed.
			LOG_WAR << fname << "Rejected forward, principal <" << gatewayPrincipalId << ">: " << e.what();
			request->reply(web::http::status_codes::Forbidden, Utility::text2json(e.what()));
			return true;
		}

		if (isSubscriptionRequest(request) && !request->isPersistentClientTransport())
		{
			request->reply(web::http::status_codes::MethodNotAllowed,
				Utility::text2json("Forwarded subscriptions require TCP or WebSocket"));
			return true;
		}
		std::string host = request->m_headers.get(HTTP_HEADER_KEY_Forwarding_Host);
		request->m_headers.erase(HTTP_HEADER_KEY_Forwarding_Host); // prevent loop forwarding
		request->m_headers.erase(HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE);
		// The target uses this marker only to deny operations that require a
		// direct client. A caller can forge the marker only to deny its own request.
		request->m_headers[HTTP_HEADER_KEY_APPMESH_FORWARDED] = "1";
		// Subscription events can race their create response. Carry an internal
		// correlation key so the gateway can route those early events safely.
		request->m_headers[HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE] = request->m_uuid;
		return forward(std::move(host), request);
	}

	if (request->m_method == web::http::methods::GET)
	{
		RESTHANDLER::instance()->handle_get(request);
	}
	else if (request->m_method == web::http::methods::PUT)
	{
		RESTHANDLER::instance()->handle_put(request);
	}
	else if (request->m_method == web::http::methods::DEL)
	{
		RESTHANDLER::instance()->handle_delete(request);
	}
	else if (request->m_method == web::http::methods::POST)
	{
		RESTHANDLER::instance()->handle_post(request);
	}
	else if (request->m_method == web::http::methods::OPTIONS)
	{
		RESTHANDLER::instance()->handle_options(request);
	}
	else if (request->m_method == web::http::methods::HEAD)
	{
		RESTHANDLER::instance()->handle_head(request);
	}
	else
	{
		request->reply(web::http::status_codes::MethodNotAllowed);
	}

	return true;
}

bool Worker::forward(std::string forwardTo, const std::shared_ptr<HttpRequest> &request)
{
	static const char fname[] = "Worker::forward() ";
	LOG_DBG << fname << "Forwarding Host: " << forwardTo;

	Uri parser;
	auto uri = parser.parse(forwardTo);
	const std::string host = uri.host;
	uri.port = (uri.port <= 1024) ? Configuration::instance()->getTcpApiPort() : uri.port;

	return ForwardingManager::instance().forward(host, uri.port, request);
}
