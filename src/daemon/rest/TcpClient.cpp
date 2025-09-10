#include <cerrno>
#include <memory>
#include <thread>

#ifdef __has_include
#if __has_include(<ace/SSL/SSL_SOCK_Connector.h>)
#include <ace/SSL/SSL_SOCK_Connector.h>
#else
#include <ace/SSL_SOCK_Connector.h>
#endif
#else
#include <ace/SSL/SSL_SOCK_Connector.h>
#endif

#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "TcpClient.h"

// Default constructor.
TcpClient::TcpClient(void) : m_sslStream(nullptr)
{
	m_buffer = make_shared_array<char>(TCP_MESSAGE_HEADER_LENGTH);
}

TcpClient::~TcpClient()
{
}

bool TcpClient::connect(const ACE_INET_Addr &addr)
{
	const static char fname[] = "TcpClient::connect() ";
	// make sure init ACE_SSL_Context before set to ACE_SSL_SOCK_Stream
	m_sslStream = std::make_shared<ACE_SSL_SOCK_Stream>(initTcpSSL(&m_sslContext));
	if (m_connector.connect(*m_sslStream, addr) == 0)
	{
		LOG_INF << fname << "Connect test stream to TCP server success";
		return true;
	}
	else
	{
		LOG_ERR << fname << "Connect to TCP server failed with error: " << ACE_OS::strerror(ACE_OS::last_error());
		m_sslStream.reset(); // Reset stream on connection failure
		return false;
	}
}

bool TcpClient::testConnection(int timeoutSeconds)
{
	const static char fname[] = "TcpClient::testConnection() ";

	if (m_sslStream == nullptr)
	{
		LOG_ERR << fname << "not connected";
		return false;
	}

	m_timeout.sec(timeoutSeconds);
	// Retry loop for EINTR
	ssize_t recvReturn;
	do
	{
		// Retry loop for EINTR
		errno = 0;
		recvReturn = m_sslStream->recv_n(m_buffer.get(), TCP_MESSAGE_HEADER_LENGTH, &m_timeout);
	} while (recvReturn == -1 && errno == EINTR);

	if (recvReturn == -1 && errno == ETIME)
	{
		return true; // Connection is still considered alive
	}

	m_sslStream->close();
	m_sslStream.reset();
	LOG_ERR << fname << "Test read failed with return " << recvReturn << " error: " << ACE_OS::strerror(ACE_OS::last_error());
	return false;
}

ACE_SSL_Context *TcpClient::initTcpSSL(ACE_SSL_Context *context)
{
	// Initialize SSL
	context->set_mode(ACE_SSL_Context::SSLv23_client);
	const bool verifyClient = Configuration::instance()->getSslVerifyClient();
	const static auto &homeDir = Utility::getHomeDir();
	if (verifyClient)
	{
		auto cert = ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCertificateFile());
		auto key = ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCertificateKeyFile());

		context->certificate(cert.c_str(), SSL_FILETYPE_PEM);
		context->private_key(key.c_str(), SSL_FILETYPE_PEM);
	}
	return context;
}
