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
#include "uwebsockets/ReplyContext.h"

ACE_Map_Manager<int, TcpHandler *, ACE_Recursive_Thread_Mutex> TcpHandler::g_handlers;
RequestQueue TcpHandler::g_messageQueue;
std::atomic_int TcpHandler::g_idGenerator{0};

struct HttpRequestMsg
{
	explicit HttpRequestMsg(const ByteBuffer &data, int tcpHandlerID, void *lwsSessionID = NULL, std::shared_ptr<WSS::ReplyContext> uwsReplyCtx = nullptr)
		: m_data(data), m_tcpHanlerId(tcpHandlerID), m_wsSessionId(lwsSessionID), m_replyContext(uwsReplyCtx)
	{
	}
	const ByteBuffer m_data; // TODO: use more efficiency definition
	// Three different protocols:
	const int m_tcpHanlerId;
	const void *m_wsSessionId;
	std::shared_ptr<WSS::ReplyContext> m_replyContext;
};

// Default constructor.
TcpHandler::TcpHandler(void)
	: m_id(++g_idGenerator), m_pendingUploadFile(1)
{
	const static char fname[] = "TcpHandler::TcpHandler() ";
	g_handlers.bind(m_id, this);
	LOG_DBG << fname << "client=" << m_id << ", total client number: " << g_handlers.current_size();
}

TcpHandler::FileUploadInfo::FileUploadInfo(const std::string &uploadFilePath, const HttpHeaderMap &requestHeaders)
	: m_filePath(uploadFilePath), m_requestHeaders(requestHeaders)
{
}

TcpHandler::~TcpHandler()
{
	const static char fname[] = "TcpHandler::~TcpHandler() ";
	LOG_DBG << fname << "client=" << m_id;
	g_handlers.unbind(m_id);
	ACE_Reactor::instance()->remove_handler(this, READ_MASK);
	ACE_Reactor::instance()->remove_handler(this, WRITE_MASK);
}

void TcpHandler::queueInputRequest(ByteBuffer &data, int tcpHandlerID, void *lwsSessionID, std::shared_ptr<WSS::ReplyContext> uwsContext)
{
	auto req = std::make_shared<HttpRequestMsg>(data, tcpHandlerID, lwsSessionID, uwsContext);
	g_messageQueue.enqueue(req);
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
	auto data = ProtobufHelper::readMessageBlock(this->peer());

	// Early return on empty data
	if (!data || data->size() == 0)
	{
		LOG_WAR << fname << "Receive error from <" << m_clientHostName << ">: " << last_error_msg() << ", closing connection";
		return -1;
	}

	// Handle successful read
	// https://github.com/DOCGroup/ACE_TAO/blob/master/ACE/examples/Reactor/WFMO_Reactor/Network_Events.cpp#L66
	queueInputRequest(data, m_id);
	return 0;
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
		while (msg)
		{
			file.write(reinterpret_cast<const char *>(msg->data()), msg->size());
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
		if (ACE_Reactor::instance()->register_handler(this, READ_MASK) == -1 ||
			ACE_Reactor::instance()->register_handler(this, WRITE_MASK) == -1)
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

			// if (this->peer().disable(ACE_NONBLOCK) == -1) // Disable non-blocking mode already controled by FLAG_ACE_NONBLOCK

			LOG_INF << fname << "client <" << m_clientHostName << "> connected";
		}
		return 0;
	}
}

void TcpHandler::handleTcpRestLoop()
{
	const static char fname[] = "TcpHandler::handleTcpRestLoop() ";

	while (QUIT_HANDLER::instance()->is_set() == 0)
	{
		std::shared_ptr<HttpRequestMsg> entity;
		g_messageQueue.wait_dequeue(entity);
		if (entity)
		{
			auto request = HttpRequest::deserialize(entity->m_data, entity->m_tcpHanlerId, entity->m_wsSessionId, entity->m_replyContext);
			if (!request || !processRequest(request))
			{
				LOG_WAR << fname << "Failed to parse request, closing connection";
				if (entity->m_tcpHanlerId > 0)
				{
					closeTcpHandler(entity->m_tcpHanlerId);
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
	}
	LOG_WAR << fname << "Exit";
}

bool TcpHandler::processRequest(std::shared_ptr<HttpRequest> &request)
{
	const static char fname[] = "TcpHandler::processRequest() ";

	LOG_DBG << fname << request->m_method << " from <"
			<< request->m_remote_address << "> path <"
			<< request->m_relative_uri << "> id <"
			<< request->m_uuid << ">";

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

void TcpHandler::closeTcpHandler(int tcpHandlerId)
{
	const static char fname[] = "TcpHandler::closeTcpHandler() ";

	ACE_GUARD(ACE_Recursive_Thread_Mutex, locker, g_handlers.mutex());
	TcpHandler *client = NULL;
	if (g_handlers.find(tcpHandlerId, client) == 0 && client)
	{
		LOG_INF << fname << "Closing TcpHandler id=" << tcpHandlerId;
		client->peer().close();
	}
	else
	{
		LOG_WAR << fname << "No such TcpHandler id=" << tcpHandlerId;
	}
}

const int &TcpHandler::id()
{
	return m_id;
}

bool TcpHandler::reply(std::unique_ptr<Response> &&resp)
{
	m_respQueue.enqueue(std::move(resp));
	return reactor()->notify(this, ACE_Event_Handler::WRITE_MASK) == 0;
}

int TcpHandler::handle_output(ACE_HANDLE)
{
	const static char fname[] = "TcpHandler::handle_output() ";

	std::unique_ptr<Response> r;
	while (m_respQueue.try_dequeue(r))
	{
		auto resp = *r;

		// Serialize response data once
		const auto data = resp.serialize();
		if (!data || data->size() == 0)
		{
			this->peer().close();
			return -1;
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
			if (!sendData(buffer, length))
			{
				LOG_ERR << fname << "send response failed with error: " << last_error_msg();
				return -1;
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
					if (!sendData(buffer.get(), readSize))
					{
						LOG_ERR << fname << "send chunk failed with error: " << last_error_msg();
						return -1;
					}
				}
			}
			else
			{
				LOG_ERR << fname << "Failed to open file: " << fileName;
			}

			// Send final delimiter
			sendData(0, 0);
		}
	}

	LOG_DBG << fname << "successfully";
	bool empty = m_respQueue.size_approx() == 0;
	if (empty)
		this->reactor()->cancel_wakeup(this, ACE_Event_Handler::WRITE_MASK);

	return 0;
}

ACE_SSL_Context *TcpHandler::initTcpSSL(ACE_SSL_Context *context, const std::string &cert, const std::string &key, const std::string &ca)
{
	const static char fname[] = "TcpHandler::initTcpSSL() ";

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
	if (!ca.empty())
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

bool TcpHandler::sendBytes(const iovec *iov, size_t count)
{
	const static char fname[] = "TcpHandler::sendBytes() ";

	size_t idx = 0;	   // Current index in the iovec array
	size_t offset = 0; // Offset inside the current iovec buffer

	while (idx < count)
	{
		// Create a temporary iovec pointing to the remaining data in the current buffer
		iovec cur;

		// Cast to (char*) ensures pointer arithmetic works correctly on both void* (Linux) and char* (Windows)
		cur.iov_base = (char *)iov[idx].iov_base + offset;
		cur.iov_len = iov[idx].iov_len - offset;

		// Reset errno/last_error before the call for clean state
		ACE_OS::last_error(0);

		// Send 1 iovec buffer at a time to ensure SSL state consistency during partial writes
		ssize_t sendReturn = this->peer().sendv(&cur, 1);

		// LOG_DBG << fname << m_clientHostName
		//         << " iov_idx: " << idx
		//         << " len: " << cur.iov_len
		//         << " sent: " << sendReturn;

		if (sendReturn <= 0)
		{
			int err = ACE_OS::last_error(); // Get platform-agnostic error code (Critical for Windows support)
			if (sendReturn < 0 && err == EINTR)
			{
				// Interrupted by signal - Log warning and retry immediately
				LOG_WAR << fname << m_clientHostName << " Send interrupted (EINTR), retrying.";
				continue;
			}

			// Handle fatal errors or blocking conditions (since timeout is not requested)
			// Note: EWOULDBLOCK means the socket buffer is full. Without a timeout/select loop,
			// we treat this as a failure to send.
			if (err == EWOULDBLOCK || err == EAGAIN)
			{
				LOG_ERR << fname << m_clientHostName << " Socket would block (buffer full). Error: " << last_error_msg();
				return false;
			}

			// Connection closed (0) or other fatal error
			LOG_ERR << fname << m_clientHostName << " Send failed. Res: " << sendReturn << ", Error: " << last_error_msg();
			return false;
		}

		// Update offset with bytes actually sent
		offset += sendReturn;

		// If we have sent the full content of the current iovec, move to the next one
		// Note: use >= to be safe, though == is mathematically expected
		if (offset >= iov[idx].iov_len)
		{
			idx++;
			offset = 0; // Reset offset for the next buffer
		}
	}

	return true;
}

bool TcpHandler::sendData(const char *data, size_t length)
{
	const static char fname[] = "TcpHandler::sendData() ";
	LOG_DBG << fname << "sending <" << length << "> data to " << m_clientHostName;

	// Write the TCP header (8 bytes) to the buffer in network byte order (big-endian):
	// - First 4 bytes: Magic number (for message validation)
	// - Next 4 bytes: Body size (data length)
	char headerBuff[TCP_MESSAGE_HEADER_LENGTH];
	uint32_t magic = htonl(TCP_MESSAGE_MAGIC);
	std::memcpy(headerBuff, &magic, sizeof(magic));
	uint32_t dataSize = htonl(length);
	std::memcpy(headerBuff + 4, &dataSize, sizeof(dataSize));

	iovec iov[2];
	iov[0].iov_base = headerBuff;
	iov[0].iov_len = TCP_MESSAGE_HEADER_LENGTH;

	size_t count = 1;

	if (length > 0)
	{
		iov[1].iov_base = (char *)data;
		iov[1].iov_len = length;
		count = 2;
	}

	return sendBytes(iov, count);
}

bool TcpHandler::replyTcp(int tcpHandlerId, std::unique_ptr<Response> &&resp)
{
	const static char fname[] = "TcpHandler::replyTcp() ";

	ACE_GUARD_RETURN(ACE_Recursive_Thread_Mutex, locker, g_handlers.mutex(), false);
	TcpHandler *client = NULL;
	if (g_handlers.find(tcpHandlerId, client) == 0 && client)
	{
		return client->reply(std::move(resp));
	}
	LOG_WAR << fname << "Client " << tcpHandlerId << " not exist, can not reply response.";
	return false;
}
