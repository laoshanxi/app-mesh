#include <cerrno>
#include <memory>

#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "TcpServer.h"
#include "protoc/ProtobufHelper.h"

ACE_Map_Manager<TcpHandler *, bool, ACE_Recursive_Thread_Mutex> TcpHandler::m_handlers;
ACE_Message_Queue<ACE_MT_SYNCH> TcpHandler::messageQueue;

struct HttpRequestMsg
{
	explicit HttpRequestMsg(std::shared_ptr<char> data, size_t len,
							TcpHandler *client)
		: m_data(data), m_dataSize(len), m_client(client) {}
	const std::shared_ptr<char> m_data;
	const size_t m_dataSize;
	TcpHandler *m_client;
};

// Default constructor.
TcpHandler::TcpHandler(void)
{
	const static char fname[] = "TcpHandler::TcpHandler() ";
	m_handlers.bind(this, true);
	LOG_DBG << fname << "TcpHandler client size: " << m_handlers.current_size();
}

TcpHandler::~TcpHandler()
{
	const static char fname[] = "TcpHandler::~TcpHandler() ";
	LOG_DBG << fname << "from this =" << this;
	m_handlers.unbind(this);
	ACE_Reactor::instance()->remove_handler(this, READ_MASK);
}

// Perform the tcp record receive.
// handle_input() will be triggered before handle_close()
int TcpHandler::handle_input(ACE_HANDLE)
{
	const static char fname[] = "TcpHandler::handle_input() ";
	LOG_DBG << fname << "from this =" << this;

	std::lock_guard<std::mutex> guard(m_socketLock); // hold this lock to avoid recv TCP file stream data
	auto result = ProtobufHelper::readProtobufBlock(this->peer());
	auto data = std::get<0>(result);
	auto readCount = std::get<1>(result);

	// https://github.com/DOCGroup/ACE_TAO/blob/master/ACE/examples/Reactor/WFMO_Reactor/Network_Events.cpp#L66
	if (readCount > 0)
	{
		assert(data != nullptr);
		messageQueue.enqueue(new ACE_Message_Block((const char *)(new HttpRequestMsg(data, readCount, this))));
		return 0;
	}
	else if (readCount == 0)
	{
		LOG_ERR << fname << "Connection from " << m_clientHostName << " closing down";
		return -1;
	}
	else if (errno == EWOULDBLOCK)
	{
		LOG_ERR << fname << "socket buffer full: " << std::strerror(errno);
		// return 0; // here does not support continue recieve to existing buffer
		return -1;
	}
	else
	{
		LOG_ERR << fname << "Problems in receiving data from " << m_clientHostName << ": " << std::strerror(errno);
		return -1;
	}
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
		// TODO: one TCP connection can not leverage parallel ACE_TP_Reactor thread pool
		if (ACE_Reactor::instance()->register_handler(this, READ_MASK) == -1)
		{
			LOG_ERR << fname << "can't register with reactor";
			return -1;
		}
		else
		{
			if (this->peer().disable(ACE_NONBLOCK) == -1)
			{
				LOG_ERR << fname << "Can't disable nonblocking";
			}
			LOG_INF << fname << "client <" << m_clientHostName << ":" << addr.get_port_number() << "> connected";
		}
		return 0;
	}
}

void TcpHandler::handleTcpRest()
{
	const static char fname[] = "TcpHandler::handleTcpRest() ";

	ACE_Message_Block *msg = nullptr;
	while (0 == messageQueue.deactivated() && QUIT_HANDLER::instance()->is_set() == 0)
	{
		if (messageQueue.dequeue(msg) >= -1 && msg)
		{
			std::unique_ptr<HttpRequestMsg> entity(static_cast<HttpRequestMsg *>((void *)msg->rd_ptr()));
			auto request = HttpRequest::deserialize(entity->m_data.get(), entity->m_dataSize, entity->m_client);
			msg->release();
			msg = nullptr;
			if (request != nullptr)
			{
				const HttpRequest &message = *request;
				LOG_DBG << fname << message.m_method << " from <"
						<< message.m_remote_address << "> path <"
						<< message.m_relative_uri << "> id <"
						<< message.m_uuid << ">";

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
					LOG_ERR << fname << "no such method " << message.m_method
							<< " from " << message.m_remote_address
							<< " with path " << message.m_relative_uri;
				}
				// TODO: check request without reply
			}
		}
	}
}

void TcpHandler::closeMsgQueue()
{
	// TODO: release memory before clear
	messageQueue.close();
}

bool TcpHandler::reply(const appmesh::Response &resp)
{
	const static char fname[] = "TcpHandler::reply() ";

	const auto data = ProtobufHelper::serialize(resp);
	const auto buffer = std::get<0>(data);
	const auto length = std::get<1>(data);

	std::lock_guard<std::mutex> guard(m_socketLock);
	if (this->peer().get_handle() != ACE_INVALID_HANDLE)
	{
		if (!sendBytes(buffer.get(), length))
		{
			LOG_ERR << fname << "send response failed with error: " << std::strerror(errno);
			return false;
		}

		if (resp.http_status() == web::http::status_codes::OK &&
			resp.http_body_msg_type() == web::http::mime_types::application_octetstream &&
			resp.request_uri() == "/appmesh/file/download" &&
			nlohmann::json::parse(resp.http_body()).contains(TCP_JSON_MSG_FILE))
		{
			auto path = nlohmann::json::parse(resp.http_body())[TCP_JSON_MSG_FILE].get<std::string>();
			// send file via TCP with chunks
			auto pBuffer = make_shared_array<char>(BLOCK_CHUNK_SIZE + PROTOBUF_HEADER_LENGTH);
			std::ifstream file(path, std::ios::binary | std::ios::in);
			if (file)
			{
				// get length of file:
				file.seekg(0, file.end);
				auto fileEnd = file.tellg();
				file.seekg(0, file.beg);
				auto currentPos = file.tellg();
				while (currentPos < fileEnd && file.good())
				{
					// continue read data chunk
					file.readsome(pBuffer.get() + PROTOBUF_HEADER_LENGTH, BLOCK_CHUNK_SIZE);
					auto readChunkSize = file.tellg() - currentPos;
					currentPos = file.tellg();

					// write data size to header
					*((uint32_t *)pBuffer.get()) = htonl(readChunkSize); // host to network byte order

					// send chunk size to client
					if (!sendBytes(pBuffer.get(), PROTOBUF_HEADER_LENGTH + readChunkSize))
					{
						LOG_ERR << fname << "send response failed with error: " << std::strerror(errno);
						return false;
					}
				}
			}
			// send last 0 for delimiter
			*((uint32_t *)pBuffer.get()) = htonl(0); // host to network byte order
			sendBytes(pBuffer.get(), PROTOBUF_HEADER_LENGTH);
		}

		if (resp.http_status() == web::http::status_codes::OK &&
			resp.http_body_msg_type() == web::http::mime_types::application_octetstream &&
			resp.request_uri() == "/appmesh/file/upload" &&
			nlohmann::json::parse(resp.http_body()).contains(TCP_JSON_MSG_FILE))
		{
			auto path = nlohmann::json::parse(resp.http_body())[TCP_JSON_MSG_FILE].get<std::string>();
			std::ofstream file(path, std::ios::binary | std::ios::out | std::ios::trunc);
			ssize_t recvReturn = 0;
			auto bodySize = ProtobufHelper::readMsgHeader(this->peer(), recvReturn);
			while (bodySize > 0)
			{
				auto result = ProtobufHelper::readBytes(this->peer(), bodySize, recvReturn);
				auto pBuffer = std::get<0>(result);
				auto readCount = std::get<1>(result);
				if (readCount > 0)
				{
					file.write(pBuffer.get(), readCount);
					bodySize = ProtobufHelper::readMsgHeader(this->peer(), recvReturn);
				}
				else
				{
					return false;
				}
			}
		}
	}
	else
	{
		LOG_WAR << fname << "Socket not available, ignore message: " << resp.uuid();
		return false;
	}
	LOG_DBG << fname << "successfully";
	return true;
}

bool TcpHandler::sendBytes(const char *data, size_t length)
{
	const static char fname[] = "TcpHandler::sendBytes() ";

	size_t totalSent = 0;
	while (totalSent < length)
	{
		size_t sendSize = 0;
		errno = 0;
		const auto sendReturn = (size_t)this->peer().send_n((void *)(data + totalSent), (length - totalSent), 0, &sendSize);
		LOG_DBG << fname << m_clientHostName << " total length: " << (length - totalSent) << " sent length:" << sendSize;
		if (sendReturn <= 0 && EINTR != errno)
		{
			LOG_ERR << fname << m_clientHostName << " send response failed with error: " << std::strerror(errno);
			return false;
		}
		totalSent += sendSize;
	}
	LOG_INF << fname << m_clientHostName << " success";
	return true;
}

bool TcpHandler::replyTcp(TcpHandler *tcpHandler, const appmesh::Response &resp)
{
	const static char fname[] = "TcpHandler::replyTcp() ";

	ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, locker, m_handlers.mutex(), false);
	if (m_handlers.find(tcpHandler) == 0)
	{
		return tcpHandler->reply(resp);
	}
	LOG_WAR << fname << "Client not exist: " << resp.uuid();
	return false;
}
