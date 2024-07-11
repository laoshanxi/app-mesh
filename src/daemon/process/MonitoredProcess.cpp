#include <fstream>
#include <thread>

#include <ace/Process.h>

#include "../../common/Utility.h"
#include "../rest/HttpRequest.h"
#include "../rest/TcpServer.h"
#include "MonitoredProcess.h"

MonitoredProcess::MonitoredProcess() : m_httpRequestReplyFlag(ATOMIC_FLAG_INIT)
{
}

MonitoredProcess::~MonitoredProcess()
{
	const static char fname[] = "MonitoredProcess::~MonitoredProcess() ";
	LOG_DBG << fname << "Process <" << AppProcess::getpid() << "> released";
}

void MonitoredProcess::returnValue(int value)
{
	AppProcess::returnValue(value);
	replyAsyncRequest();
}

void MonitoredProcess::setAsyncHttpRequest(void *httpRequest)
{
	m_httpRequestReplyFlag.clear();
	m_httpRequest.reset(static_cast<HttpRequestWithAppRef *>(httpRequest));
}

void MonitoredProcess::replyAsyncRequest()
{
	const static char fname[] = "MonitoredProcess::replyAsyncRequest() ";
	if (!m_httpRequestReplyFlag.test_and_set())
	{
		try
		{
			if (m_httpRequest)
			{
				long position = 0;
				auto body = this->getOutputMsg(&position);
				std::map<std::string, std::string> headers;
				headers[HTTP_HEADER_KEY_exit_code] = std::to_string(AppProcess::returnValue());
				headers[HTTP_HEADER_KEY_output_pos] = std::to_string(position);
				m_httpRequest->reply(web::http::status_codes::OK, body, headers);
				// explicit release memory here
				m_httpRequest = nullptr;
			}
		}
		catch (...)
		{
			LOG_ERR << fname << "message reply failed, maybe the http connection broken with error: " << std::strerror(errno);
		}
	}
}
