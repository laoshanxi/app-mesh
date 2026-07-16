// src/daemon/process/MonitoredProcess.cpp
#include "../../common/Utility.h"
#include "../rest/HttpRequest.h"
#include "MonitoredProcess.h"

MonitoredProcess::MonitoredProcess(std::weak_ptr<Application> owner)
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
	// Call parent class exit handler first
	AppProcess::onExit(exitCode);

	// Flush pipe to disk before reading — fast-exit processes may still have
	// buffered stdout when the async timer hasn't fired yet (idempotent).
	cleanResource();

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
			const auto body = getOutputMsg(&position);

			// Set response headers with exit code and output position
			std::map<std::string, std::string> headers;
			headers[HTTP_HEADER_KEY_exit_code] = std::to_string(AppProcess::returnValue());
			headers[HTTP_HEADER_KEY_output_pos] = std::to_string(position);

			request->reply(web::http::status_codes::OK, body, headers);
		}
	}
	catch (...)
	{
		LOG_ERR << fname << "Failed to reply async HTTP request, connection may be broken: " << last_error_msg();
	}
}
