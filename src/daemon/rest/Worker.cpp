// src/daemon/rest/Worker.cpp

#include "Worker.h"

#include "../../common/QuitHandler.h"
#include "../../common/UriParser.hpp"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Data.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "SocketServer.h"
#include "SocketStream.h"
#include "uwebsockets/ReplyContext.h"

#include <ace/Handle_Set.h>
#include <ace/OS_NS_sys_select.h>
#include <ace/os_include/netinet/os_tcp.h>

#include <cerrno>
#include <fstream>
#include <limits>
#include <memory>
#include <thread>
#include <utility>

struct HttpRequestContext
{
	HttpRequestContext(ByteBuffer data, int tcpClientId, void *lwsSession, std::shared_ptr<WSS::ReplyContext> uwsReplyCtx)
		: m_data(std::move(data)), m_tcpClientId(tcpClientId), m_lwsSession(lwsSession), m_uwsReplyContext(std::move(uwsReplyCtx))
	{
	}

	ByteBuffer m_data;

	const int m_tcpClientId;							  // TCP socket
	void *const m_lwsSession;							  // libwebsockets
	std::shared_ptr<WSS::ReplyContext> m_uwsReplyContext; // uWebsockets
};

void Worker::queueTcpRequest(ByteBuffer &&data, int tcpClientId)
{
	m_messages.enqueue(std::make_shared<HttpRequestContext>(std::move(data), tcpClientId, nullptr, nullptr));
}

void Worker::queueLwsRequest(ByteBuffer &&data, void *lwsSession)
{
	m_messages.enqueue(std::make_shared<HttpRequestContext>(std::move(data), -1, lwsSession, nullptr));
}

void Worker::queueUwsRequest(ByteBuffer &&data, std::shared_ptr<WSS::ReplyContext> uwsContext)
{
	m_messages.enqueue(std::make_shared<HttpRequestContext>(std::move(data), -1, nullptr, std::move(uwsContext)));
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

		auto request = HttpRequest::deserialize(requestContext->m_data, requestContext->m_tcpClientId, requestContext->m_lwsSession, requestContext->m_uwsReplyContext);

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
			else if (requestContext->m_lwsSession)
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

	static ACE_Map_Manager<std::string, std::shared_ptr<SocketStreamPtr>, ACE_Thread_Mutex> connectedClients;

	Uri parser;
	auto uri = parser.parse(forwardTo);
	const std::string host = uri.host;
	uri.port = (uri.port <= 1024) ? Configuration::instance()->getRestTcpPort() : uri.port;

	std::shared_ptr<SocketStreamPtr> client;
	if (connectedClients.find(host, client) != 0)
	{
		ACE_GUARD_RETURN(ACE_Thread_Mutex, guard, connectedClients.mutex(), false);

		// Double-checked locking
		if (connectedClients.find(host, client) != 0)
		{
			client = std::make_shared<SocketStreamPtr>(new SocketStream(Global::getClientSSL()));

			if (!client->stream()->connect(ACE_INET_Addr(uri.port, host.c_str())))
			{
				LOG_ERR << fname << "Failed to connect to forwarding host: " << host;
				request->reply(web::http::status_codes::BadGateway, "Failed to connect to forwarding host");
				return true;
			}

			connectedClients.bind(host, client);
		}
	}

	if (!client || !client->stream())
	{
		LOG_CRT << fname << "Failed to create connection to: " << forwardTo;
		return false;
	}

	// Ensure callback does not trigger before send to maintain sequence
	std::lock_guard<std::mutex> lock(client->stream()->get_state_mutex());

	client->stream()->onData(
		[request](std::vector<std::uint8_t> &&data)
		{
			Response r;
			if (r.deserialize(data.data(), data.size()))
			{
				request->reply(r.request_uri, r.uuid, r.body, r.headers, r.http_status, r.body_msg_type);
			}
			else
			{
				request->reply(web::http::status_codes::InternalError, "Failed to parse forwarded response");
			}
		});

	client->stream()->onClose(
		[host, request]()
		{
			LOG_WAR << "Forwarding client to " << host << " closed";
			connectedClients.unbind(host);
			request->reply(web::http::status_codes::BadGateway, "Forwarding host connection closed");
		});

	auto data = request->serialize();
	client->stream()->send(std::move(data));

	return true;
}
