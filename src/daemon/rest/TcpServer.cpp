#include <memory>

#include "../../common/Utility.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "TcpServer.h"
#include "protoc/ProtobufHelper.h"

// Default constructor.
TcpHandler::TcpHandler(void)
{
}

TcpHandler::~TcpHandler()
{
	const static char fname[] = "TcpHandler::~TcpHandler() ";
	LOG_DBG << fname << "from this =" << this;
}

// Perform the tcp record receive.
// handle_input() will be triggered before handle_close()
int TcpHandler::handle_input(ACE_HANDLE)
{
	const static char fname[] = "TcpHandler::handle_input() ";
	LOG_DBG << fname << "from this =" << this;

	auto data = ProtobufHelper::readMessageBlock(this->peer());
	if (data != nullptr)
	{
		auto httpRequest = HttpRequest::deserialize(data.get());
		if (httpRequest != nullptr)
		{
			handleTcpRest(*httpRequest);
			if (httpRequest->m_response != nullptr)
			{
				return replyResponse(*(httpRequest->m_response.get())) ? 0 : -1;
			}
		}
	}
	LOG_ERR << fname << "Connection from " << m_clientHostName << " closing down";
	return -1;
}

int TcpHandler::open(void *)
{
	const static char fname[] = "TcpHandler::open() ";
	LOG_DBG << fname << "from this =" << this;

	ACE_INET_Addr addr;
	if (this->peer().get_remote_addr(addr) == -1)
	{
		return -1;
	}
	else
	{
		this->m_clientHostName = addr.get_host_name();
		if (ACE_Reactor::instance()->register_handler(this, READ_MASK) == -1)
		{
			LOG_ERR << fname << "can't register with reactor";
			return -1;
		}
		else
		{
			LOG_INF << fname << "Connected with " << m_clientHostName;
		}
		return 0;
	}
}

void TcpHandler::handleTcpRest(const HttpRequest &message)
{
	const static char fname[] = "TcpHandler::handleTcpRest() ";
	LOG_DBG << fname << message.m_method << " from <" << message.m_remote_address << "> path <" << message.m_relative_uri << "> id <" << message.m_uuid << ">";

	if (message.m_method == web::http::methods::GET)
		RESTHANDLER::instance()->handle_get(message);
	else if (message.m_method == web::http::methods::PUT)
		RESTHANDLER::instance()->handle_put(message);
	else if (message.m_method == web::http::methods::DEL)
		RESTHANDLER::instance()->handle_delete(message);
	else if (message.m_method == web::http::methods::POST)
		RESTHANDLER::instance()->handle_post(message);
	else if (message.m_method == web::http::methods::OPTIONS)
		RESTHANDLER::instance()->handle_options(message);
	else if (message.m_method == web::http::methods::HEAD)
		RESTHANDLER::instance()->handle_head(message);
	else
	{
		LOG_ERR << fname << "no such method " << message.m_method << " from " << message.m_remote_address << " with path " << message.m_relative_uri;
	}
}

bool TcpHandler::replyResponse(const appmesh::Response &resp)
{
	const static char fname[] = "TcpHandler::replyResponse() ";

	const auto data = ProtobufHelper::serialize(resp);
	const auto buffer = std::get<0>(data);
	const auto length = std::get<1>(data);

	std::lock_guard<std::recursive_mutex> guard(m_socketSendLock);
	if (this->peer().get_handle() != ACE_INVALID_HANDLE)
	{
		const auto sendSize = (size_t)this->peer().send_n((void *)buffer.get(), length);
		LOG_DBG << fname << m_clientHostName << " response: " << resp.uuid() << " with length: " << length << " sent len:" << sendSize;
		if (sendSize != length)
		{
			LOG_ERR << fname << "send response failed with error: " << std::strerror(errno);
			return false;
		}
	}
	else
	{
		LOG_WAR << fname << "Socket not available, ignore message: " << resp.uuid();
		return false;
	}
	return true;
}
