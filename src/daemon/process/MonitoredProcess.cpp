#include <fstream>
#include <thread>

#include <ace/Process.h>

#include "../../common/Utility.h"
#include "../rest/HttpRequest.h"
#include "../rest/TcpServer.h"
#include "MonitoredProcess.h"

MonitoredProcess::MonitoredProcess() : m_httpRequest(nullptr)
{
}

MonitoredProcess::~MonitoredProcess()
{
	const static char fname[] = "MonitoredProcess::~MonitoredProcess() ";

	if (m_httpRequest)
		m_httpRequest = nullptr;
	if (m_thread != nullptr)
		m_thread->join();

	LOG_DBG << fname << "Process <" << this->getpid() << "> released";
}

pid_t MonitoredProcess::spawn(ACE_Process_Options &option)
{
	auto rt = AppProcess::spawn(option);

	// Start thread to read stdout/stderr stream
	m_thread = std::make_unique<std::thread>(std::bind(&MonitoredProcess::runPipeReaderThread, this));

	return rt;
}

void MonitoredProcess::waitThread()
{
	if (nullptr != m_thread)
	{
		// crash will happen if thread join itself
		m_thread->join();
		m_thread = nullptr;
	}
}

void MonitoredProcess::runPipeReaderThread()
{
	const static char fname[] = "MonitoredProcess::runPipeReaderThread() ";
	LOG_DBG << fname << "Entered";

	// hold self point to avoid release
	auto self = this->shared_from_this();

	/// @brief if no wait, there will be no exit_code
	this->wait();

	replyAsyncRequest();
	LOG_DBG << fname << "Exited";
	this->registerTimer(0, 0, std::bind(&MonitoredProcess::waitThread, this), fname);
}

void MonitoredProcess::replyAsyncRequest()
{
	const static char fname[] = "MonitoredProcess::replyAsyncRequest() ";
	std::lock_guard<std::recursive_mutex> guard(m_httpRequestMutex);
	if (m_httpRequest)
	{
		try
		{
			std::unique_ptr<HttpRequest> request(static_cast<HttpRequest *>(m_httpRequest));
			m_httpRequest = nullptr;
			if (nullptr != request)
			{
				long position = 0;
				auto body = this->getOutputMsg(&position);
				std::map<std::string, std::string> headers;
				headers[HTTP_HEADER_KEY_exit_code] = std::to_string(this->returnValue());
				headers[HTTP_HEADER_KEY_output_pos] = std::to_string(position);
				request->reply(web::http::status_codes::OK, body, headers);
			}
		}
		catch (...)
		{
			LOG_ERR << fname << "message reply failed, maybe the http connection broken with error: " << std::strerror(errno);
		}
	}
}

void MonitoredProcess::killgroup()
{
	AppProcess::killgroup();
	replyAsyncRequest();
	// TODO: sometimes, terminated process can not get stdout from file.
}
