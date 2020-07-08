#include <thread>
#include <fstream>
#include <ace/Process.h>
#include "MonitoredProcess.h"
#include "../../common/Utility.h"
#include "../../common/HttpRequest.h"

MonitoredProcess::MonitoredProcess(bool enableBuildinThread)
	:m_httpRequest(nullptr), m_buildinThreadFinished(false), m_enableBuildinThread(enableBuildinThread)
{
}

MonitoredProcess::~MonitoredProcess()
{
	const static char fname[] = "MonitoredProcess::~MonitoredProcess() ";

	if (m_httpRequest)
	{
		std::unique_ptr<HttpRequest> response(static_cast<HttpRequest*>(m_httpRequest));
		m_httpRequest = nullptr;
	}
	if (m_thread != nullptr) m_thread->join();

	LOG_DBG << fname << "Process <" << this->getpid() << "> released";
}

pid_t MonitoredProcess::spawn(ACE_Process_Options & option)
{
	auto rt = AppProcess::spawn(option);

	// Start thread to read stdout/stderr stream
	if (m_enableBuildinThread) m_thread = std::make_unique<std::thread>(std::bind(&MonitoredProcess::runPipeReaderThread, this));

	return rt;
}

void MonitoredProcess::waitThread(int timerId)
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
	m_buildinThreadFinished = false;
	LOG_DBG << fname << "Entered";

	// hold self point to avoid release
	auto self = this->shared_from_this();

	/// @brief if no wait, there will be no exit_code
	this->wait();

	///////////////////////////////////////////////////////////////////////
	if (m_httpRequest)
	{
		try
		{
			web::http::http_response resp(web::http::status_codes::OK);
			resp.set_body(this->fetchOutputMsg());
			resp.headers().add(HTTP_HEADER_KEY_exit_code, this->return_value());
			std::unique_ptr<HttpRequest> response(static_cast<HttpRequest*>(m_httpRequest));
			m_httpRequest = nullptr;
			if (nullptr != response)
			{
				response->reply(resp).get();
			}
		}
		catch (...)
		{
			LOG_ERR << fname << "message reply failed, maybe the http connection broken with error: " << std::strerror(errno);
		}
	}
	///////////////////////////////////////////////////////////////////////
	LOG_DBG << fname << "Exited";
	m_buildinThreadFinished = true;
	this->registerTimer(0, 0, std::bind(&MonitoredProcess::waitThread, this, std::placeholders::_1), fname);
}
