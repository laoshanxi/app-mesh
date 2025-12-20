// src/daemon/rest/Worker.cpp
#include <cerrno>
#include <fstream>
#include <limits>
#include <memory>
#include <thread>

#include <ace/Handle_Set.h>
#include <ace/OS_NS_sys_select.h>
#include <ace/os_include/netinet/os_tcp.h>

#include "../../common/QuitHandler.h"
#include "../../common/RestClient.h"
#include "../../common/TimerHandler.h"
#include "../../common/UriParser.hpp"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Data.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "SocketServer.h"
#include "SocketStream.h"
#include "Worker.h"
#include "uwebsockets/ReplyContext.h"

struct HttpRequestMsg
{
	explicit HttpRequestMsg(const ByteBuffer &data, int tcpClientId, void *lwsSessionID = NULL, std::shared_ptr<WSS::ReplyContext> uwsReplyCtx = nullptr)
		: m_data(data), m_tcpClientId(tcpClientId), m_wsSessionId(lwsSessionID), m_replyContext(std::move(uwsReplyCtx))
	{
	}
	const ByteBuffer m_data; // TODO: use more efficiency definition
	// Three different protocols:
	const int m_tcpClientId;
	const void *m_wsSessionId;
	std::shared_ptr<WSS::ReplyContext> m_replyContext;
};

void Worker::queueInputRequest(ByteBuffer &data, int tcpClientId, void *lwsSessionID, std::shared_ptr<WSS::ReplyContext> uwsContext)
{
	m_messages.enqueue(std::make_shared<HttpRequestMsg>(std::move(data), tcpClientId, lwsSessionID, std::move(uwsContext)));
}

int Worker::svc()
{
	const static char fname[] = "Worker::svc() ";
	LOG_INF << fname;

	while (!QuitHandler::instance()->shouldExit())
	{
		std::shared_ptr<HttpRequestMsg> entity;
		m_messages.wait_dequeue(entity);

		// Sentinel check
		if (!entity || (entity->m_tcpClientId == 0 && entity->m_wsSessionId == nullptr && !entity->m_replyContext))
		{
			LOG_INF << fname << "Got sentinel";
			break;
		}

		auto request = HttpRequest::deserialize(entity->m_data, entity->m_tcpClientId, entity->m_wsSessionId, entity->m_replyContext);
		if (!request || !processRequest(request))
		{
			LOG_WAR << fname << "Failed to parse request, closing connection";
			if (entity->m_tcpClientId > 0)
			{
				SocketServer::closeClient(entity->m_tcpClientId);
			}
#if defined(HAVE_UWEBSOCKETS)
			else if (entity->m_replyContext)
			{
				entity->m_replyContext->replyData("500 Internal Server Error", true, false);
			}
#else
			else if (entity->m_wsSessionId)
			{
				// TODO: handle libwensockets close to avoid leak
			}
#endif
		}
	}

	LOG_WAR << fname << "Exit";
	return 0;
}

void Worker::shutdown()
{
	ByteBuffer sentinel{nullptr};
	size_t threadNum = this->thr_count();
	for (size_t i = 0; i < threadNum; ++i)
	{
		queueInputRequest(sentinel, 0, nullptr);
	}
}

bool Worker::processRequest(std::shared_ptr<HttpRequest> &request)
{
	const static char fname[] = "Worker::processRequest() ";

	LOG_DBG << fname << request->m_method << " from <"
			<< request->m_remote_address << "> path <"
			<< request->m_relative_uri << "> id <"
			<< request->m_uuid << ">";

	if (request->m_headers.contains(HTTP_HEADER_KEY_Forwarding_Host))
	{
		auto host = request->m_headers.get(HTTP_HEADER_KEY_Forwarding_Host);
		request->m_headers.erase(HTTP_HEADER_KEY_Forwarding_Host); // prevent loop forwarding
		return processForward(std::move(host), request);
	}

	if (request->m_method == web::http::methods::GET)
		RESTHANDLER::instance()->handle_get(request);
	else if (request->m_method == web::http::methods::PUT)
		RESTHANDLER::instance()->handle_put(request);
	else if (request->m_method == web::http::methods::DEL)
		RESTHANDLER::instance()->handle_delete(request);
	else if (request->m_method == web::http::methods::POST)
		RESTHANDLER::instance()->handle_post(request);
	else if (request->m_method == web::http::methods::OPTIONS)
		RESTHANDLER::instance()->handle_options(request);
	else if (request->m_method == web::http::methods::HEAD)
		RESTHANDLER::instance()->handle_head(request);
	else
	{
		return false;
	}
	return true;
}

bool Worker::processForward(const std::string forwardTo, std::shared_ptr<HttpRequest> &request)
{
	const static char fname[] = "Worker::processForward() ";
	LOG_DBG << fname << "Forwarding Host: " << forwardTo;

	static ACE_Map_Manager<std::string, std::shared_ptr<SocketStreamPtr>, ACE_Thread_Mutex> connectedClients;

	Uri parser;
	auto uri = parser.parse(forwardTo);
	auto host = uri.host;
	uri.port = (uri.port <= 1024) ? Configuration::instance()->getRestTcpPort() : uri.port;

	std::shared_ptr<SocketStreamPtr> client;
	if (connectedClients.find(host, client) != 0)
	{
		ACE_GUARD_RETURN(ACE_Thread_Mutex, guard, connectedClients.mutex(), false);
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
		LOG_CRT << fname << "Failed create connection to: " << forwardTo;
		return false;
	}

	// Ensure call back not trigger before send to keep sequence.
	std::lock_guard<std::mutex> lock(client->stream()->get_state_mutex());
	client->stream()->onData([request](std::vector<std::uint8_t> &&data)
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

	client->stream()->onClose([host, request]()
	{
		LOG_WAR << "Forwarding client to " << host << " closed";
		connectedClients.unbind(host);
		request->reply(web::http::status_codes::BadGateway, "Forwarding host connection closed");
	});

	auto data = request->serialize();
	client->stream()->send(std::move(data));
	return true;
}
