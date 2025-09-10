#include <ace/Process.h>

#include "../../common/Utility.h"
#include "../rest/HttpRequest.h"
#include "../rest/TcpServer.h"
#include "MonitoredProcess.h"

MonitoredProcess::MonitoredProcess(void *owner)
	: AppProcess(owner)
{
}

MonitoredProcess::~MonitoredProcess()
{
	const static char fname[] = "MonitoredProcess::~MonitoredProcess() ";
	LOG_DBG << fname << "Process <" << AppProcess::getpid() << "> released";
}

void MonitoredProcess::onExit(int exitCode)
{
	AppProcess::onExit(exitCode);
	replyAsyncRequest();
}

void MonitoredProcess::setAsyncHttpRequest(std::shared_ptr<void> httpRequest)
{
	auto locked = m_httpRequest.synchronize();
	*locked = std::static_pointer_cast<HttpRequest>(httpRequest);
}

void MonitoredProcess::replyAsyncRequest()
{
	const static char fname[] = "MonitoredProcess::replyAsyncRequest() ";
	try
	{
		std::shared_ptr<HttpRequest> request;
		m_httpRequest.swap(request);
		if (request)
		{
			long position = 0;
			auto body = this->getOutputMsg(&position);
			std::map<std::string, std::string> headers;
			headers[HTTP_HEADER_KEY_exit_code] = std::to_string(AppProcess::returnValue());
			headers[HTTP_HEADER_KEY_output_pos] = std::to_string(position);
			request->reply(web::http::status_codes::OK, body, headers);
		}
	}
	catch (...)
	{
		LOG_ERR << fname << "message reply failed, maybe the http connection broken with error: " << ACE_OS::strerror(ACE_OS::last_error());
	}
}
