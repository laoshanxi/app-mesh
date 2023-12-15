#include <cerrno>
#include <fstream>
#include <memory>

#include <ace/INet/HTTPS_Context.h>

#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "TcpServer.h"
#include "protoc/ProtobufHelper.h"

ACE_Map_Manager<int, TcpHandler *, ACE_Recursive_Thread_Mutex> TcpHandler::m_handlers;
ACE_Message_Queue<ACE_MT_SYNCH> TcpHandler::m_messageQueue;
std::atomic_int TcpHandler::m_idGenerator = ATOMIC_FLAG_INIT;

struct HttpRequestMsg
{
	explicit HttpRequestMsg(std::shared_ptr<char> data, size_t len, int client)
		: m_data(data), m_dataSize(len), m_tcpHanlerId(client)
	{
	}
	const std::shared_ptr<char> m_data;
	const size_t m_dataSize;
	const int m_tcpHanlerId;
};

// Default constructor.
TcpHandler::TcpHandler(void)
	: m_id(++m_idGenerator)
{
	const static char fname[] = "TcpHandler::TcpHandler() ";
	m_handlers.bind(m_id, this);
	LOG_DBG << fname << "client=" << m_id << ", total client number: " << m_handlers.current_size();
}

TcpHandler::~TcpHandler()
{
	const static char fname[] = "TcpHandler::~TcpHandler() ";
	LOG_DBG << fname << "client=" << m_id;
	m_handlers.unbind(m_id);
	ACE_Reactor::instance()->remove_handler(this, READ_MASK);
}

// Perform the tcp record receive.
// handle_input() will be triggered before handle_close()
int TcpHandler::handle_input(ACE_HANDLE)
{
	const static char fname[] = "TcpHandler::handle_input() ";
	LOG_DBG << fname << "from client=" << m_id;

	std::lock_guard<std::mutex> guard(m_socketLock); // hold this lock to avoid recv TCP file stream data
	auto result = ProtobufHelper::readMessageBlock(this->peer());
	auto data = std::get<0>(result);
	auto readCount = std::get<1>(result);

	// https://github.com/DOCGroup/ACE_TAO/blob/master/ACE/examples/Reactor/WFMO_Reactor/Network_Events.cpp#L66
	if (readCount > 0)
	{
		assert(data != nullptr);
		m_messageQueue.enqueue(new ACE_Message_Block((const char *)(new HttpRequestMsg(data, readCount, m_id))));
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
	LOG_DBG << fname << "from client=" << m_id;

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
	while (0 == m_messageQueue.deactivated() && QUIT_HANDLER::instance()->is_set() == 0)
	{
		if (m_messageQueue.dequeue(msg) >= -1 && msg)
		{
			std::unique_ptr<HttpRequestMsg> entity(static_cast<HttpRequestMsg *>((void *)msg->rd_ptr()));
			auto request = HttpRequest::deserialize(entity->m_data.get(), entity->m_dataSize, entity->m_tcpHanlerId);
			msg->release();
			msg = nullptr;
			if (request != nullptr)
			{
				const HttpRequest &message = *request;
				LOG_DBG << fname << message.m_method << " from <"
						<< message.m_remote_address << "> path <"
						<< message.m_relative_uri << "> id <"
						<< message.m_uuid << "> TcpHandler <"
						<< entity->m_tcpHanlerId << ">";

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
			// TODO: check request without reply
		}
	}
}

void TcpHandler::closeMsgQueue()
{
	// TODO: release memory before clear
	m_messageQueue.close();
}

const int &TcpHandler::id()
{
	return m_id;
}

bool TcpHandler::reply(const Response &resp)
{
	const static char fname[] = "TcpHandler::reply() ";

	const auto data = resp.serialize();
	const auto buffer = data->data();
	const auto length = data->size();

	LOG_DBG << fname << "send response length: " << length;
	std::lock_guard<std::mutex> guard(m_socketLock);
	if (this->peer().get_handle() != ACE_INVALID_HANDLE)
	{
		if (length == 0)
		{
			this->peer().close();
			return false;
		}
		if (!sendBytes(length) || !sendBytes(buffer, length))
		{
			LOG_ERR << fname << "send response failed with error: " << std::strerror(errno);
			return false;
		}

		if (resp.http_status == web::http::status_codes::OK &&
			resp.body_msg_type == web::http::mime_types::application_octetstream &&
			resp.request_uri == "/appmesh/file/download" && resp.body.size() &&
			nlohmann::json::parse(resp.body).contains(TCP_JSON_MSG_FILE))
		{
			auto path = nlohmann::json::parse(resp.body)[TCP_JSON_MSG_FILE].get<std::string>();
			// send file via TCP with chunks
			auto pBuffer = make_shared_array<char>(BLOCK_CHUNK_SIZE);
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
					file.readsome(pBuffer.get(), BLOCK_CHUNK_SIZE);
					auto readChunkSize = file.tellg() - currentPos;
					currentPos = file.tellg();

					// send chunk size to client
					if (!sendBytes(readChunkSize) || !sendBytes(pBuffer.get(), readChunkSize))
					{
						LOG_ERR << fname << "send response failed with error: " << std::strerror(errno);
						return false;
					}
				}
			}
			// send last 0 for delimiter
			sendBytes(0);
		}

		if (resp.http_status == web::http::status_codes::OK &&
			resp.body_msg_type == web::http::mime_types::application_octetstream &&
			resp.request_uri == "/appmesh/file/upload" && resp.body.size() &&
			nlohmann::json::parse(resp.body).contains(TCP_JSON_MSG_FILE))
		{
			auto path = nlohmann::json::parse(resp.body)[TCP_JSON_MSG_FILE].get<std::string>();
			std::ofstream file(path, std::ios::binary | std::ios::out | std::ios::trunc);
			auto msg = ProtobufHelper::readMessageBlock(this->peer());
			while (std::get<0>(msg) != nullptr)
			{
				auto msgData = std::get<0>(msg);
				auto msgSize = std::get<1>(msg);
				file.write(msgData.get(), msgSize);
				msg = ProtobufHelper::readMessageBlock(this->peer());
			}
		}
	}
	else
	{
		LOG_WAR << fname << "Socket not available, ignore message: " << resp.uuid;
		return false;
	}
	LOG_DBG << fname << "successfully";
	return true;
}

void TcpHandler::initTcpSSL()
{
	const static char fname[] = "TcpHandler::initTcpSSL() ";


	ACE::HTTPS::Context::set_default_ssl_mode(ACE_SSL_Context::SSLv23_server);
	ACE::HTTPS::Context::set_default_verify_mode(Configuration::instance()->getSslVerifyPeer());
	if (Configuration::instance()->getSslVerifyPeer())
		ACE::HTTPS::Context::set_default_verify_settings(Configuration::instance()->getSslVerifyPeer());
	ACE::HTTPS::Context::instance().set_key_files(
		Configuration::instance()->getSSLCertificateFile().c_str(),
		Configuration::instance()->getSSLCertificateKeyFile().c_str(),
		SSL_FILETYPE_PEM);
	ACE::HTTPS::Context::instance().ssl_context().filter_versions(TCP_SSL_VERSION_LIST);

	// Enable ECDH cipher
	if (!SSL_CTX_set_ecdh_auto(ACE::HTTPS::Context::instance().ssl_context().context(), 1))
	{
		LOG_WAR << fname << "SSL_CTX_set_ecdh_auto  failed: " << std::strerror(errno);
	}
	auto ciphers = "ALL:!RC4:!SSLv2:+HIGH:!MEDIUM:!LOW";
	// auto ciphers = "HIGH:!aNULL:!eNULL:!kECDH:!aDH:!RC4:!3DES:!CAMELLIA:!MD5:!PSK:!SRP:!KRB5:@STRENGTH";
	if (!SSL_CTX_set_cipher_list(ACE::HTTPS::Context::instance().ssl_context().context(), ciphers))
	{
		LOG_WAR << fname << "SSL_CTX_set_cipher_list failed: " << std::strerror(errno);
	}
	SSL_CTX_clear_options(ACE::HTTPS::Context::instance().ssl_context().context(), SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

	if (Configuration::instance()->getSSLCaPath().length())
	{
		auto result = ACE::HTTPS::Context::instance().load_trusted_ca(Configuration::instance()->getSSLCaPath().c_str());
		LOG_INF << fname << "load_trusted_ca " << Configuration::instance()->getSSLCaPath() << " with result: " << result;
	}
}

bool TcpHandler::sendBytes(const char *data, size_t length)
{
	const static char fname[] = "TcpHandler::sendBytes() ";

	size_t totalSent = 0;
	while (totalSent < length)
	{
		size_t sendSize = 0;
		size_t sendReturn = 0;
		errno = 0;
		sendReturn = (size_t)this->peer().send_n((void *)(data + totalSent), (length - totalSent), 0, &sendSize);
		LOG_DBG << fname << m_clientHostName << " total length: " << (length - totalSent) << " sent length:" << sendSize << " with result: " << std::strerror(errno);
		if (sendReturn == 0)
		{
			if (EINTR == errno)
			{
				LOG_WAR << fname << m_clientHostName << " send response failed with warning: " << std::strerror(errno);
			}
			else
			{
				LOG_ERR << fname << m_clientHostName << " send response failed with error: " << std::strerror(errno);
				return false;
			}
		}
		totalSent += sendSize;
	}
	LOG_INF << fname << m_clientHostName << " success";
	return true;
}

bool TcpHandler::sendBytes(size_t intValue)
{
	char headerBuff[PROTOBUF_HEADER_LENGTH];
	// write data size to header
	*((uint32_t *)headerBuff) = htonl(intValue); // host to network byte order
	return sendBytes(headerBuff, PROTOBUF_HEADER_LENGTH);
}

bool TcpHandler::replyTcp(int tcpHandlerId, const Response &resp)
{
	const static char fname[] = "TcpHandler::replyTcp() ";

	ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, locker, m_handlers.mutex(), false);
	TcpHandler *client = NULL;
	if (m_handlers.find(tcpHandlerId, client) == 0 && client)
	{
		return client->reply(resp);
	}
	LOG_WAR << fname << "Client " << tcpHandlerId << " not exist, can not reply response: " << resp.uuid;
	return false;
}
