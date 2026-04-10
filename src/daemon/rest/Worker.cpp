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
#include "uwebsockets/ReplyContext.h"

#include <memory>
#include <utility>

struct HttpRequestContext
{
	HttpRequestContext(ByteBuffer data, int tcpClientId, LwsSessionRef lwsRef, std::shared_ptr<WSS::ReplyContext> uwsReplyCtx)
		: m_data(std::move(data)), m_tcpClientId(tcpClientId), m_lwsRef(lwsRef),
		  m_uwsReplyContext(std::move(uwsReplyCtx))
	{
	}

	ByteBuffer m_data;

	const int m_tcpClientId;							  // TCP socket
	const LwsSessionRef m_lwsRef;						  // libwebsockets (wsi + ABA IDs)
	std::shared_ptr<WSS::ReplyContext> m_uwsReplyContext; // uWebsockets
};

void Worker::queueTcpRequest(ByteBuffer &&data, int tcpClientId)
{
	m_messages.enqueue(std::make_shared<HttpRequestContext>(std::move(data), tcpClientId, LwsSessionRef{}, nullptr));
}

void Worker::queueLwsRequest(ByteBuffer &&data, LwsSessionRef lwsRef)
{
	m_messages.enqueue(std::make_shared<HttpRequestContext>(std::move(data), -1, lwsRef, nullptr));
}

void Worker::queueUwsRequest(ByteBuffer &&data, std::shared_ptr<WSS::ReplyContext> uwsContext)
{
	m_messages.enqueue(std::make_shared<HttpRequestContext>(std::move(data), -1, LwsSessionRef{}, std::move(uwsContext)));
}

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

		auto request = HttpRequest::deserialize(requestContext->m_data, requestContext->m_tcpClientId, requestContext->m_lwsRef, requestContext->m_uwsReplyContext);

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

bool Worker::process(const std::shared_ptr<HttpRequest> &request)
{
	static const char fname[] = "Worker::process() ";

	LOG_DBG << fname << request->m_method << " from <"
			<< request->m_remote_address << "> path <"
			<< request->m_relative_uri << "> id <"
			<< request->m_uuid << ">";

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
