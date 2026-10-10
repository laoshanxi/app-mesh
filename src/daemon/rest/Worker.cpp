// src/daemon/rest/Worker.cpp

#include "Worker.h"

#include "../../common/QuitHandler.h"
#include "../../common/UriParser.hpp"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../security/HMACVerifier.h"
#include "../security/Security.h"
#include "Data.h"
#include "ForwardingManager.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#if defined(HAVE_DROGON)
#include "ReplyContext.h"
#endif

#include <memory>
#include <set>
#include <utility>

// Global backpressure cap on the shared inbound queue. Bounds a
// request-flood DoS: a client sending faster than workers drain is shed, not buffered.
static constexpr size_t MAX_PENDING_REQUESTS = 10000;

namespace
{
	bool isPublicForwardRequest(const std::shared_ptr<HttpRequest> &request)
	{
		return request->m_method == web::http::methods::GET &&
			(request->m_relative_uri == "/appmesh/auth/config" ||
			 request->m_relative_uri == "/.well-known/oauth-protected-resource");
	}

	bool isSubscriptionRequest(const std::shared_ptr<HttpRequest> &request)
	{
		const auto &path = request->m_relative_uri;
		return path == "/appmesh/subscribe" ||
			(path.size() > 10 && path.compare(path.size() - 10, 10, "/subscribe") == 0) ||
			request->m_query.count("subscribe_events") != 0;
	}

#if defined(HAVE_DROGON)
	// An undecodable payload keeps its envelope: the correlation uuid is read
	// straight from the map so the frame can still be answered.
	std::string recoverRequestUuid(const std::string &data)
	{
		try
		{
			msgpack::unpacked result;
			msgpack::unpack(result, data.data(), data.size());
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

	// Answer an undecodable request so the client fails at once instead of
	// waiting for its own timeout. False when there is no uuid to reply with.
	bool replyUndecodableRequest(const std::shared_ptr<WSS::ReplyContext> &ctx, const std::string &data)
	{
		const auto uuid = recoverRequestUuid(data);
		if (uuid.empty())
			return false;

		Response response;
		response.uuid = uuid;
		response.http_status = web::http::status_codes::BadRequest;
		response.body_msg_type = web::http::mime_types::application_json;
		const auto text = Utility::text2json("Unable to decode the request").dump();
		response.body.assign(text.begin(), text.end());
		ctx->replyWebSocket(response.serialize(), true, true);
		return true;
	}
#endif
}

struct HttpRequestContext
{
	std::string m_data;
	LwsSessionRef m_lwsRef{};
#if defined(HAVE_DROGON)
	std::shared_ptr<WSS::ReplyContext> m_wsReplyContext;
#endif
	// Explicit shutdown marker (an empty m_data must never mean shutdown: a zero-length
	// frame would then let any client kill a worker).
	bool m_isShutdownSentinel = false;
};

bool Worker::enqueueRequest(std::shared_ptr<HttpRequestContext> ctx)
{
	static const char fname[] = "Worker::enqueueRequest() ";
	if (m_pendingCount.fetch_add(1, std::memory_order_relaxed) + 1 > MAX_PENDING_REQUESTS)
	{
		m_pendingCount.fetch_sub(1, std::memory_order_relaxed);
		LOG_WAR << fname << "Inbound queue saturated (" << MAX_PENDING_REQUESTS << "), dropping request";
		return false;
	}
	// enqueue only fails/throws on allocation failure; roll back the reserved slot so
	// the counter can't ratchet up and permanently wedge the cap.
	bool enqueued = false;
	try
	{
		enqueued = m_messages.enqueue(std::move(ctx));
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

void Worker::queueLwsRequest(std::string &&data, LwsSessionRef lwsRef)
{
	auto ctx = std::make_shared<HttpRequestContext>();
	ctx->m_data = std::move(data);
	ctx->m_lwsRef = lwsRef;
	enqueueRequest(std::move(ctx));
}

#if defined(HAVE_DROGON)
void Worker::queueWsRequest(std::string &&data, std::shared_ptr<WSS::ReplyContext> wsContext)
{
	auto ctx = std::make_shared<HttpRequestContext>();
	ctx->m_data = std::move(data);
	ctx->m_wsReplyContext = std::move(wsContext);
	enqueueRequest(std::move(ctx));
}
#endif

int Worker::svc()
{
	static const char fname[] = "Worker::svc() ";
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

#if defined(HAVE_DROGON)
		auto request = HttpRequest::deserialize(requestContext->m_data, requestContext->m_lwsRef, requestContext->m_wsReplyContext);
#else
		auto request = HttpRequest::deserialize(requestContext->m_data, requestContext->m_lwsRef, nullptr);
#endif

		if (!request || !process(request))
		{
			LOG_WAR << fname << "Failed to parse or process request";

#if defined(HAVE_DROGON)
			if (requestContext->m_wsReplyContext)
			{
				auto &wsCtx = requestContext->m_wsReplyContext;
				if (wsCtx->getProtocolType() == WSS::ReplyContext::ProtocolType::Http)
					wsCtx->replyHTTP("500 Internal Server Error", "Internal Server Error", {}, "text/plain");
				else if (!replyUndecodableRequest(wsCtx, requestContext->m_data))
					// Nothing to correlate a framed error with: drop the message (the
					// TCP transport closes the connection through its abort hook).
					wsCtx->markAborted();
			}
#else
			if (requestContext->m_lwsRef)
			{
				// TODO: handle libwebsockets close to avoid leak
			}
#endif
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
	if (!headers.contains(web::http::header_names::cookie))
		return false;

	const auto &m = request->m_method;
	if (!(m == web::http::methods::POST || m == web::http::methods::PUT || m == web::http::methods::DEL))
		return false;

	const auto origin = Utility::stdStringTrim(headers.get(web::http::header_names::origin));
	if (origin.empty())
		return false; // same-origin / non-browser
	if (Configuration::instance()->getCsrfAllowedOrigins().count(origin) > 0)
		return false; // explicitly allow-listed

	// Same-origin: match Origin host[:port] against the browser-facing host. Prefer
	// X-Forwarded-Host (set by the proxy) since behind nginx/agent the daemon's Host is upstream.
	// Safe on the direct path only because x-forwarded-host is non-safelisted — never add it to
	// the CORS Access-Control-Allow-Headers list, or a cross-site request could forge same-origin.
	auto host = Utility::stdStringTrim(headers.get(HTTP_HEADER_KEY_X_Forwarded_Host));
	if (host.empty())
		host = Utility::stdStringTrim(headers.get(web::http::header_names::host));
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
		try
		{
			const auto framePrincipal = Security::authenticateBearerAuthorization(
				request->m_headers.get(HTTP_HEADER_JWT_Authorization));
			if (framePrincipal.id() != request->transportPrincipalId())
			{
				request->reply(web::http::status_codes::Forbidden,
					Utility::text2json("WebSocket frame cannot change the session principal"));
				return true;
			}
		}
		catch (const AuthenticationUnavailableException &e)
		{
			request->reply(web::http::status_codes::ServiceUnavailable, Utility::text2json(e.what()));
			return true;
		}
		catch (const std::exception &e)
		{
			request->reply(web::http::status_codes::Unauthorized, Utility::text2json(e.what()),
				{{"WWW-Authenticate", "Bearer realm=\"appmesh\", error=\"invalid_token\""}});
			return true;
		}
	}

	if (isCsrfViolation(request))
	{
		LOG_WAR << fname << "CSRF: rejected cross-origin cookie request, path <" << request->m_relative_uri
				<< "> origin <" << request->m_headers.get(web::http::header_names::origin) << ">";
		request->reply(web::http::status_codes::Forbidden, Utility::text2json("CSRF validation failed: origin not allowed"));
		return true;
	}

	if (request->m_headers.contains(HTTP_HEADER_KEY_Forwarding_Host))
	{
		if (request->m_headers.contains(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY) ||
			request->m_headers.contains(HMAC_HTTP_HEADER))
		{
			request->reply(web::http::status_codes::Forbidden,
				Utility::text2json("managed process proof cannot be forwarded"));
			return true;
		}

		// Socket file transfer is per-connection: forwarding it would use this node.
		if (request->m_headers.contains(HTTP_HEADER_KEY_X_Send_File_Socket) ||
			request->m_headers.contains(HTTP_HEADER_KEY_X_Recv_File_Socket))
		{
			request->reply(web::http::status_codes::BadRequest,
				Utility::text2json("File transfer is not supported through forwarding"));
			return true;
		}

		const bool publicRequest = isPublicForwardRequest(request);
		if (!publicRequest && !request->m_headers.contains(HTTP_HEADER_JWT_Authorization))
		{
			request->reply(web::http::status_codes::Unauthorized,
				Utility::text2json("Forwarded requests require bearer authentication"),
				{{"WWW-Authenticate", "Bearer realm=\"appmesh\""}});
			return true;
		}
		// A WebSocket frame with a bearer was already checked against the pinned
		// session principal above. HTTP and TCP have no pinned principal, so validate
		// their bearer before the gateway opens an outbound connection. The target
		// validates the unchanged bearer again and makes the authorization decision.
		if (!publicRequest && request->transportPrincipalId().empty())
		{
			try
			{
				Security::authenticateBearerAuthorization(
					request->m_headers.get(HTTP_HEADER_JWT_Authorization));
			}
			catch (const AuthenticationUnavailableException &e)
			{
				request->reply(web::http::status_codes::ServiceUnavailable, Utility::text2json(e.what()));
				return true;
			}
			catch (const std::exception &e)
			{
				request->reply(web::http::status_codes::Unauthorized, Utility::text2json(e.what()),
					{{"WWW-Authenticate", "Bearer realm=\"appmesh\", error=\"invalid_token\""}});
				return true;
			}
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
	const auto uri = parser.parse(forwardTo);

	// Which API port a bare host means depends on the transport; see ForwardingManager.
	return ForwardingManager::instance().forward(uri.host, uri.port, request);
}
