#include <cerrno>
#include <fstream>
#include <limits>
#include <memory>
#include <thread>

#include <ace/Handle_Set.h>
#include <ace/OS_NS_sys_select.h>
#include <ace/os_include/netinet/os_tcp.h>

#include "../../common/RestClient.h"
#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "HttpRequest.h"
#include "RestHandler.h"
#include "TcpServer.h"
#include "protoc/ProtobufHelper.h"

ACE_Map_Manager<int, TcpHandler *, ACE_Recursive_Thread_Mutex> TcpHandler::m_handlers;
MessageQueue TcpHandler::m_messageQueue;
std::atomic_int TcpHandler::m_idGenerator = ATOMIC_FLAG_INIT;

struct HttpRequestMsg
{
	explicit HttpRequestMsg(const std::shared_ptr<char> &data, size_t len, int client)
		: m_data(data), m_dataSize(len), m_tcpHanlerId(client)
	{
	}
	const std::shared_ptr<char> m_data;
	const size_t m_dataSize;
	const int m_tcpHanlerId;
};

// Default constructor.
TcpHandler::TcpHandler(void)
	: m_id(++m_idGenerator), m_pendingUploadFile(1)
{
	const static char fname[] = "TcpHandler::TcpHandler() ";
	m_handlers.bind(m_id, this);
	LOG_DBG << fname << "client=" << m_id << ", total client number: " << m_handlers.current_size();
}

TcpHandler::FileUploadInfo::FileUploadInfo(const std::string &uploadFilePath, const std::map<std::string, std::string> &requestHeaders)
	: m_filePath(uploadFilePath), m_requestHeaders(requestHeaders)
{
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

	// hold this lock to avoid recv TCP file stream data
	std::lock_guard<std::mutex> guard(m_socketLock);

	// Handle file upload if necessary
	if (recvUploadFile())
	{
		int streamStatus = testStream();
		LOG_DBG << fname << "stream test status=" << streamStatus;
		if (streamStatus <= 0)
		{
			LOG_WAR << fname << "Stream test failed, closing connection with <" << m_clientHostName << ">";
			return streamStatus;
		}
	}

	// Read incoming message
	auto result = ProtobufHelper::readMessageBlock(this->peer());
	auto data = std::get<0>(result);
	auto readCount = std::get<1>(result);

	// Early return on null data
	if (!data)
	{
		LOG_WAR << fname << "Failed to receive data from <" << m_clientHostName << ">, closing connection";
		return -1;
	}

	// Handle successful read
	// https://github.com/DOCGroup/ACE_TAO/blob/master/ACE/examples/Reactor/WFMO_Reactor/Network_Events.cpp#L66
	if (readCount > 0)
	{
		m_messageQueue.enqueue(new ACE_Message_Block((const char *)(new HttpRequestMsg(data, readCount, m_id))));
		return 0;
	}

	// Handle connection closure
	if (readCount == 0)
	{
		LOG_WAR << fname << "Connection closed by <" << m_clientHostName << ">";
		return -1;
	}

	// Handle errors
	if (errno == EWOULDBLOCK)
	{
		LOG_WAR << fname << "Socket buffer full: " << last_error_msg() << ", closing connection with <" << m_clientHostName << ">";
		return -1; // No partial reads supported
	}

	LOG_WAR << fname << "Receive error from <" << m_clientHostName << ">: " << last_error_msg() << ", closing connection";
	return -1;
}

int TcpHandler::testStream()
{
	// Create a handle set for the current socket
	ACE_Handle_Set handleSet;
	handleSet.set_bit(this->peer().get_handle());

	// Zero timeout for immediate return
	ACE_Time_Value timeout(ACE_Time_Value::zero);

	// Use select to check if data is available for reading
	int ret = ACE_OS::select(int(this->peer().get_handle()) + 1,
							 handleSet, // read set
							 nullptr,	// write set (not used)
							 nullptr,	// exception set (not used)
							 &timeout);

	if (ret == -1)
	{
		int lastErr = ACE_OS::last_error();

#if defined(_WIN32)
		// Windows: retry if interrupted
		if (lastErr == WSAEINTR)
			return 0; // retry select
#else
		// Linux/Unix: retry if interrupted
		if (lastErr == EINTR)
			return 0; // retry select
#endif
		// Hard error
		LOG_WAR << "testStream(): select() failed with error(" << lastErr << "): " << ACE_OS::strerror(lastErr);
		return -1;
	}
	else if (ret == 0)
	{
		// No data available, immediate return
		return 0;
	}

	// Data is available
	return ret;
}

bool TcpHandler::recvUploadFile()
{
	const static char fname[] = "TcpHandler::recvUploadFile() ";

	std::shared_ptr<FileUploadInfo> fileInfo;
	if (m_pendingUploadFile.pop(fileInfo))
	{
		std::ofstream file(fileInfo->m_filePath, std::ios::binary | std::ios::out | std::ios::trunc);
		auto msg = ProtobufHelper::readMessageBlock(this->peer());
		while (std::get<0>(msg) != nullptr)
		{
			auto msgData = std::get<0>(msg);
			auto msgSize = std::get<1>(msg);
			file.write(msgData.get(), msgSize);
			msg = ProtobufHelper::readMessageBlock(this->peer());
		}
		LOG_INF << fname << "upload finished";
		// set permission
		Utility::applyFilePermission(fileInfo->m_filePath, fileInfo->m_requestHeaders);
		return true;
	}
	return false;
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
		this->m_clientHostName = Utility::stringFormat("%s:%hu", addr.get_host_name(), addr.get_port_number());
		// TODO: one TCP connection can not leverage parallel ACE_TP_Reactor thread pool
		if (ACE_Reactor::instance()->register_handler(this, READ_MASK) == -1)
		{
			LOG_ERR << fname << "can't register with reactor";
			return -1;
		}
		else
		{
			// Disable Nagle's algorithm on both sides if you're sending small, frequent messages.
			int flag = 1;
			if (this->peer().set_option(ACE_IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) == -1)
			{
				LOG_ERR << fname << "Can't disable Nagle's algorithm with error: " << last_error_msg();
			}

			// if (this->peer().disable(ACE_NONBLOCK) == -1) // Disable non-blocking mode already controled by ACE_NONBLOCK_FLAG

			LOG_INF << fname << "client <" << m_clientHostName << "> connected";
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
			if (request)
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
	LOG_WAR << fname << "Exit";
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

	// Early validation
	{
		std::lock_guard<std::mutex> guard(m_socketLock);
		if (this->peer().get_handle() == ACE_INVALID_HANDLE)
		{
			LOG_WAR << fname << "Socket not available, ignoring message: " << resp.uuid;
			return false;
		}
	}

	// Serialize response data once
	const auto data = resp.serialize();
	if (!data || data->size() == 0)
	{
		this->peer().close();
		return false;
	}

	const auto buffer = data->data();
	const auto length = data->size();
	LOG_DBG << fname << "send response length: " << length;

	// Handle file upload preparation
	if (resp.http_status == web::http::status_codes::OK &&
		resp.request_uri == REST_PATH_UPLOAD && !resp.body.empty() &&
		resp.headers.count(HTTP_HEADER_KEY_X_Send_File_Socket))
	{
		const auto fileName = Utility::decode64(resp.headers.find(HTTP_HEADER_KEY_X_Send_File_Socket)->second);
		m_pendingUploadFile.push(std::make_shared<FileUploadInfo>(fileName, resp.file_upload_request_headers));
		LOG_INF << fname << "upload from socket to : " << fileName;
	}

	// Send response data
	{
		std::lock_guard<std::mutex> guard(m_socketLock);
		if (!sendHeader(length) || !sendBytes(buffer, length))
		{
			LOG_ERR << fname << "send response failed with error: " << last_error_msg();
			return false;
		}
	}

	// Handle file download
	if (resp.http_status == web::http::status_codes::OK &&
		resp.request_uri == REST_PATH_DOWNLOAD && !resp.body.empty() &&
		resp.headers.count(HTTP_HEADER_KEY_X_Recv_File_Socket))
	{
		const auto fileName = Utility::decode64(resp.headers.find(HTTP_HEADER_KEY_X_Recv_File_Socket)->second);
		LOG_INF << fname << "download socket file : " << fileName;

		std::ifstream file(fileName, std::ios::binary | std::ios::ate);
		if (file)
		{
			const auto fileSize = file.tellg();
			std::streampos sentSize = 0;
			file.seekg(0, std::ios::beg);
			auto buffer = make_shared_array<char>(TCP_CHUNK_BLOCK_SIZE);
			std::lock_guard<std::mutex> guard(m_socketLock);

			while (file.good() && sentSize < fileSize)
			{
				file.read(buffer.get(), TCP_CHUNK_BLOCK_SIZE);
				const auto readSize = file.gcount();
				if (readSize <= 0)
				{
					break;
				}
				sentSize += readSize;
				if (!sendHeader(readSize) || !sendBytes(buffer.get(), readSize))
				{
					LOG_ERR << fname << "send chunk failed with error: " << last_error_msg();
					return false;
				}
			}
		}
		else
		{
			LOG_ERR << fname << "Failed to open file: " << fileName;
		}

		// Send final delimiter
		return sendHeader(0);
	}

	LOG_DBG << fname << "successfully";
	return true;
}

ACE_SSL_Context *TcpHandler::initTcpSSL(ACE_SSL_Context *context)
{
	const static char fname[] = "TcpHandler::initTcpSSL() ";

	// Retrieve SSL configuration
	const static std::string homeDir = Utility::getHomeDir();
	bool verifyClient = Configuration::instance()->getSslVerifyClient();
	auto cert = ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCertificateFile());	 // Server certificate (PEM, include intermediates)
	auto key = ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCertificateKeyFile()); // Private key
	auto ca = ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCaPath());				 // CA file or directory

	LOG_INF << fname << "Init SSL with CA <" << ca << "> server cert <" << cert << "> server private key <" << key << ">";

	// Set server mode, allow TLSv1.2 and TLSv1.3 only
	context->set_mode(ACE_SSL_Context::SSLv23_server); // SSLv23_server enables TLS negotiation
	context->filter_versions(TCP_SSL_VERSION_LIST);	   // "tlsv1.2,tlsv1.3"

	// Load server certificate and private key
#if defined(COMPILER_LOWER_EQUAL_485)
	if (context->certificate(cert.c_str(), SSL_FILETYPE_PEM) != 0)
#else
	if (context->certificate_chain(cert.c_str(), SSL_FILETYPE_PEM) != 0)
#endif
	{
		LOG_ERR << fname << "Failed to load certificate: " << last_error_msg();
		return nullptr;
	}
	if (context->private_key(key.c_str(), SSL_FILETYPE_PEM) != 0 || context->verify_private_key() != 0)
	{
		LOG_ERR << fname << "Failed to load private key: " << last_error_msg();
		return nullptr;
	}

	// Enable forward secrecy for TLS1.2 (ECDH automatic selection)
	if (!SSL_CTX_set_ecdh_auto(context->context(), 1))
	{
		LOG_WAR << fname << "SSL_CTX_set_ecdh_auto failed: " << last_error_msg();
	}

	// Configure cipher suites to prioritize security, explicitly excluding weak ciphers
	const char *tls12Ciphers = "HIGH:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5";
	if (!SSL_CTX_set_cipher_list(context->context(), tls12Ciphers))
	{
		LOG_WAR << fname << "SSL_CTX_set_cipher_list failed: " << last_error_msg();
	}

	// Set TLS1.3 ciphers separately
#if OPENSSL_VERSION_NUMBER >= 0x10101000L
	const char *tls13Ciphers = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256";
	if (!SSL_CTX_set_ciphersuites(context->context(), tls13Ciphers))
	{
		LOG_WAR << fname << "SSL_CTX_set_ciphersuites failed: " << last_error_msg();
	}
#endif

	// Disable unsafe legacy renegotiation
	SSL_CTX_clear_options(context->context(), SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION);

	// Set client certificate verification if required
	if (verifyClient)
	{
		context->set_verify_peer(true, 1 /* verify once */, 0 /* verification depth */);

		// Load trusted CA certificates if the CA path is accessible
		if (ACE_OS::access(ca.c_str(), R_OK) == 0)
		{
			bool isDir = Utility::isDirExist(ca);
			if (context->load_trusted_ca(isDir ? 0 : ca.c_str(), isDir ? ca.c_str() : 0, false) != 0)
			{
				LOG_WAR << fname << "Failed to load trusted CA from: " << ca;
			}

			// Set verify mode and callback explicitly for the SSL context
			SSL_CTX_set_verify(context->context(), context->default_verify_mode(), context->default_verify_callback());
		}
		else
		{
			LOG_WAR << fname << "CA path inaccessible or invalid: " << ca;
		}
	}

	// Configure session caching and lifetime to improve TLS session resumption performance
	SSL_CTX_set_session_cache_mode(context->context(), SSL_SESS_CACHE_SERVER);
	SSL_CTX_set_timeout(context->context(), 300); // 5-minute session timeout

	return context;
}

bool TcpHandler::sendBytes(const char *data, size_t length, int timeoutSeconds)
{
	const static char fname[] = "TcpHandler::sendBytes() ";

	size_t totalSent = 0;					// Track total bytes sent
	ACE_Time_Value timeout(timeoutSeconds); // Timeout for the send operation

	while (totalSent < length)
	{
		size_t sendSize = 0;	// Bytes sent in the current iteration
		ssize_t sendReturn = 0; // Result of send_n call
		errno = 0;				// Reset errno before the call

		// Attempt to send the remaining bytes
		sendReturn = this->peer().send_n(
			(void *)(data + totalSent),				   // Pointer to unsent data
			length - totalSent,						   // Remaining length to send
			(timeoutSeconds > 0) ? &timeout : nullptr, // Optional timeout
			&sendSize								   // Capture bytes sent in this call
		);

		// LOG_DBG << fname << m_clientHostName
		//		<< " Total length remaining: " << (length - totalSent)
		//		<< ", Sent length: " << sendSize
		//		<< ", Send result: " << sendReturn
		//		<< ", Error: " << (errno ? last_error_msg() : "None");

		// Handle send_n result
		if (sendReturn <= 0) // `0` or negative indicates failure
		{
			if (errno == EINTR) // Interrupted by a signal
			{
				LOG_WAR << fname << m_clientHostName << " Send interrupted, retrying. Error: " << last_error_msg();
				continue; // Retry sending
			}
			else if (errno == EWOULDBLOCK || errno == ETIMEDOUT) // Timeout occurred
			{
				LOG_ERR << fname << m_clientHostName << " Send operation timed out. Error: " << last_error_msg();
				return false; // Timeout is a failure condition
			}
			else // Other errors
			{
				LOG_ERR << fname << m_clientHostName << " Send failed. Error: " << last_error_msg();
				return false;
			}
		}

		// Accumulate the bytes successfully sent
		totalSent += sendSize;
	}

	return true;
}

bool TcpHandler::sendHeader(size_t intValue)
{
	const static char fname[] = "TcpHandler::sendHeader() ";
	LOG_DBG << fname << "sending <" << intValue << "> data to " << m_clientHostName;

	const static int headerSendTimeout = 10;

	// Write the TCP header (8 bytes) to the buffer in network byte order (big-endian):
	// - First 4 bytes: Magic number (for message validation)
	// - Next 4 bytes: Body size (data length)
	char headerBuff[TCP_MESSAGE_HEADER_LENGTH];
	uint32_t magic = htonl(TCP_MESSAGE_MAGIC);
	std::memcpy(headerBuff, &magic, sizeof(magic));
	uint32_t dataSize = htonl(intValue);
	std::memcpy(headerBuff + 4, &dataSize, sizeof(dataSize));

	return sendBytes(headerBuff, TCP_MESSAGE_HEADER_LENGTH, headerSendTimeout);
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
