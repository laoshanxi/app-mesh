#pragma once
#include <memory>

#include <ace/SSL/SSL_SOCK_Connector.h>

class TcpClient
{
public:
	TcpClient(void);
	virtual ~TcpClient(void);

	bool connect(const ACE_INET_Addr &addr);

	bool testConnection(int timeoutSeconds);

private:
	ACE_SSL_Context *initTcpSSL(ACE_SSL_Context *context);

private:
	std::shared_ptr<ACE_SSL_SOCK_Stream> m_sslStream;
	ACE_SSL_Context m_sslContext;
	ACE_SSL_SOCK_Connector m_connector;

	ACE_Time_Value m_timeout;
	std::shared_ptr<char> m_buffer;
};
