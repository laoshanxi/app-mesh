// src/daemon/rest/Worker.cpp

#include "Worker.h"

#include "../../common/QuitHandler.h"
#include "../../common/UriParser.hpp"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Data.h"
#include "ForwardingManager.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "SocketServer.h"
#if defined(HAVE_UWEBSOCKETS)
#include "uwebsockets/ReplyContext.h"
#endif

#include <memory>
#include <set>
#include <utility>

struct HttpRequestContext
{
	ByteBuffer m_data;
	int m_tcpClientId = -1;
	LwsSessionRef m_lwsRef{};
#if defined(HAVE_UWEBSOCKETS)
	std::shared_ptr<WSS::ReplyContext> m_uwsReplyContext;
#endif
};

void Worker::queueTcpRequest(ByteBuffer &&data, int tcpClientId)
{
	auto ctx = std::make_shared<HttpRequestContext>();
	ctx->m_data = std::move(data);
	ctx->m_tcpClientId = tcpClientId;
	m_messages.enqueue(std::move(ctx));
}

void Worker::queueLwsRequest(ByteBuffer &&data, LwsSessionRef lwsRef)
{
	auto ctx = std::make_shared<HttpRequestContext>();
	ctx->m_data = std::move(data);
	ctx->m_lwsRef = lwsRef;
	m_messages.enqueue(std::move(ctx));
}

#if defined(HAVE_UWEBSOCKETS)
void Worker::queueUwsRequest(ByteBuffer &&data, std::shared_ptr<WSS::ReplyContext> uwsContext)
{
	auto ctx = std::make_shared<HttpRequestContext>();
	ctx->m_data = std::move(data);
	ctx->m_uwsReplyContext = std::move(uwsContext);
	m_messages.enqueue(std::move(ctx));
}
#endif

int Worker::svc()
{
	static const char fname[] = "Worker::svc() ";
	LOG_INF << fname;

	while (!QuitHandler::instance()->shouldExit())
	{
		std::shared_ptr<HttpRequestContext> requestContext;
		m_messages.wait_dequeue(requestContext);

		// Sentinel check
		const bool isSentinel = !requestContext || requestContext->m_data.empty();
		if (isSentinel)
		{
			LOG_INF << fname << "Got sentinel";
			break;
		}

#if defined(HAVE_UWEBSOCKETS)
		auto request = HttpRequest::deserialize(requestContext->m_data, requestContext->m_tcpClientId, requestContext->m_lwsRef, requestContext->m_uwsReplyContext);
#else
		auto request = HttpRequest::deserialize(requestContext->m_data, requestContext->m_tcpClientId, requestContext->m_lwsRef, nullptr);
#endif

		if (!request || !process(request))
		{
			LOG_WAR << fname << "Failed to parse request, closing connection";

			if (requestContext->m_tcpClientId > 0)
			{
				SocketServer::closeClient(requestContext->m_tcpClientId);
			}
#if defined(HAVE_UWEBSOCKETS)
			else if (requestContext->m_uwsReplyContext)
			{
				requestContext->m_uwsReplyContext->replyWebSocket("500 Internal Server Error", true, false);
			}
#else
			else if (requestContext->m_lwsRef)
			{
				// TODO: handle libwebsockets close to avoid leak
			}
#endif
		}
	}

	LOG_WAR << fname << "Exit";
	return 0;
}

void Worker::shutdown()
{
	const size_t threadNum = this->thr_count();
	for (size_t i = 0; i < threadNum; ++i)
	{
		ByteBuffer sentinel;
		queueTcpRequest(std::move(sentinel), 0);
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

	LOG_DBG << fname << request->m_method << " from <"
			<< request->m_remote_address << "> path <"
			<< request->m_relative_uri << "> id <"
			<< request->m_uuid << ">";

	if (isCsrfViolation(request))
	{
		LOG_WAR << fname << "CSRF: rejected cross-origin cookie request, path <" << request->m_relative_uri
				<< "> origin <" << request->m_headers.get("origin") << ">";
		request->reply(web::http::status_codes::Forbidden, Utility::text2json("CSRF validation failed: origin not allowed"));
		return true;
	}

	if (request->m_headers.contains(HTTP_HEADER_KEY_Forwarding_Host))
	{
		std::string host = request->m_headers.get(HTTP_HEADER_KEY_Forwarding_Host);
		request->m_headers.erase(HTTP_HEADER_KEY_Forwarding_Host); // prevent loop forwarding
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
		return false;
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
	uri.port = (uri.port <= 1024) ? Configuration::instance()->getRestTcpPort() : uri.port;

	return ForwardingManager::instance().forward(host, uri.port, request);
}
