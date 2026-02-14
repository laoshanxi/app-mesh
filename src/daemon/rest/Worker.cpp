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

#include <atomic>
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

struct ForwardingConnection
{
	SocketStreamPtr stream;
	using PendingRequestMap = ACE_Map_Manager<std::string, std::shared_ptr<HttpRequest>, ACE_Thread_Mutex>;
	PendingRequestMap pending_requests;
	std::atomic<bool> closed{false};

	bool addRequest(const std::string &uuid, std::shared_ptr<HttpRequest> request)
	{
		if (closed.load(std::memory_order_relaxed))
			return false;
		return pending_requests.bind(uuid, std::move(request)) == 0;
	}

	std::shared_ptr<HttpRequest> takeRequest(const std::string &uuid)
	{
		std::shared_ptr<HttpRequest> req;
		pending_requests.unbind(uuid, req);
		return req;
	}

	void failAll(const std::string &msg)
	{
		std::vector<std::string> keys;
		{
			ACE_GUARD(ACE_Thread_Mutex, guard, pending_requests.mutex());
			closed.store(true, std::memory_order_relaxed);
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

	using ForwardingClientMap = ACE_Map_Manager<std::string, std::shared_ptr<ForwardingConnection>, ACE_Recursive_Thread_Mutex>;
	static ForwardingClientMap connectedClients;

	Uri parser;
	auto uri = parser.parse(forwardTo);
	const std::string host = uri.host;
	uri.port = (uri.port <= 1024) ? Configuration::instance()->getRestTcpPort() : uri.port;

	std::shared_ptr<ForwardingConnection> conn;
	if (connectedClients.find(host, conn) != 0 || conn->closed.load(std::memory_order_relaxed))
	{
		ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, guard, connectedClients.mutex(), false);

		// Remove stale closed connection
		if (connectedClients.find(host, conn) == 0 && conn->closed.load(std::memory_order_relaxed))
		{
			connectedClients.unbind(host);
			conn.reset();
		}

		// Double-checked locking
		if (connectedClients.find(host, conn) != 0)
		{
			conn = std::make_shared<ForwardingConnection>();
			conn->stream = SocketStreamPtr(new SocketStream(Global::getClientSSL()));

			// Set up callbacks once before connecting (safe: callbacks are stored, not invoked yet)
			std::weak_ptr<ForwardingConnection> weakConn = conn;

			conn->stream->onData(
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
							LOG_WAR << "Worker::forward() Received response for unknown UUID: " << r.uuid;
						}
					}
					else
					{
						LOG_ERR << "Worker::forward() Failed to deserialize forwarded response";
						c->failAll("Corrupted response from forwarding host");
					}
				});

			conn->stream->onClose(
				[weakConn, host]()
				{
					LOG_WAR << "Worker::forward() Forwarding connection to " << host << " closed";
					if (auto c = weakConn.lock())
					{
						c->failAll("Forwarding host connection closed");
					}
					connectedClients.unbind(host);
				});

			if (!conn->stream->connect(ACE_INET_Addr(uri.port, host.c_str())))
			{
				LOG_ERR << fname << "Failed to connect to forwarding host: " << host;
				request->reply(web::http::status_codes::BadGateway, "Failed to connect to forwarding host");
				return true;
			}

			connectedClients.bind(host, conn);
		}
	}

	if (!conn || !conn->stream.stream())
	{
		LOG_CRT << fname << "Failed to create connection to: " << forwardTo;
		return false;
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
