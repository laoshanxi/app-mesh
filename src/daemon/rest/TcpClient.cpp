#include <cerrno>
#include <memory>
#include <thread>

#include <ace/SSL/SSL_SOCK_Connector.h>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "TcpClient.h"

// Default constructor.
TcpClient::TcpClient(void) : m_sslStream(nullptr)
{
	m_buffer = make_shared_array<char>(PROTOBUF_HEADER_LENGTH);
	// make sure init ACE_SSL_Context before set to ACE_SSL_SOCK_Stream
	m_sslStream = std::make_shared<ACE_SSL_SOCK_Stream>(initTcpSSL(&m_sslContext));
}

TcpClient::~TcpClient()
{
}

bool TcpClient::connect(const ACE_INET_Addr &addr)
{
	const static char fname[] = "TcpClient::connect() ";

	if (m_connector.connect(*m_sslStream, addr) == 0)
	{
		LOG_INF << fname << "Connect test stream to TCP server success";
		return true;
	}
	else
	{
		LOG_ERR << fname << "Connect to TCP server failed with error: " << std::strerror(errno);
		return false;
	}
}

bool TcpClient::testConnection(int timeoutSeconds)
{
	const static char fname[] = "TcpClient::testConnection() ";

	m_timeout.sec(timeoutSeconds);
	auto recvReturn = m_sslStream->recv(m_buffer.get(), PROTOBUF_HEADER_LENGTH, &m_timeout);
	if (recvReturn == -1 && errno == ETIME)
	{
		// LOG_DBG << fname << "Read from TCP server: " << std::strerror(errno);
		return true;
	}
	m_sslStream->close();
	LOG_ERR << fname << "Read from TCP server failed with error: " << std::strerror(errno);
	return false;
}

ACE_SSL_Context *TcpClient::initTcpSSL(ACE_SSL_Context *context)
{
	// Initialize SSL
	context->set_mode(ACE_SSL_Context::SSLv23_client);
	bool verifyClient = Configuration::instance()->getSslVerifyClient();
	if (verifyClient)
	{
		auto cert = Configuration::instance()->getSSLCertificateFile();
		auto key = Configuration::instance()->getSSLCertificateKeyFile();

		context->certificate(cert.c_str(), SSL_FILETYPE_PEM);
		context->private_key(key.c_str(), SSL_FILETYPE_PEM);
	}
	return context;
}
