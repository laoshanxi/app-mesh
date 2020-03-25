#include <thread>
#include <ace/Pipe.h>
#include <ace/Process.h>
#include "MonitoredProcess.h"
#include "../common/Utility.h"
#include "../common/HttpRequest.h"

MonitoredProcess::MonitoredProcess(int cacheOutputLines, bool enableBuildinThread)
	:AppProcess(cacheOutputLines), m_readPipeFile(0), m_httpRequest(nullptr), m_buildinThreadFinished(false), m_enableBuildinThread(enableBuildinThread)
{
}

MonitoredProcess::~MonitoredProcess()
{
	const static char fname[] = "MonitoredProcess::~MonitoredProcess() ";

	// clean pipe handlers and file
	if (m_pipe != nullptr) m_pipe->close();
	if (m_readPipeFile != nullptr) ACE_OS::fclose(m_readPipeFile);

	if (m_httpRequest)
	{
		delete (HttpRequest*)m_httpRequest;
		m_httpRequest = nullptr;
	}

	std::lock_guard<std::recursive_mutex> guard(m_queueMutex);
	if (m_thread != nullptr) m_thread->join();

	LOG_DBG << fname << "Process <" << this->getpid() << "> released";
}

pid_t MonitoredProcess::spawn(ACE_Process_Options & options)
{
	const static char fname[] = "MonitoredProcess::spawn() ";

	m_pipe = std::make_unique<ACE_Pipe>();
	if (m_pipe->open(m_pipeHandler) < 0)
	{
		LOG_ERR << fname << "Create pipe failed with error : " << std::strerror(errno);
		return ACE_INVALID_PID;
	}
	m_readPipeFile = ACE_OS::fdopen(m_pipe->read_handle(), "r");
	if (m_readPipeFile == nullptr)
	{
		LOG_ERR << fname << "Get file stream failed with error : " << std::strerror(errno);
		return ACE_INVALID_PID;
	}
	else
	{
		// release the handles if already set in process options
		options.release_handles();
		options.set_handles(ACE_STDIN, m_pipe->write_handle(), m_pipe->write_handle());
	}
	auto rt = AppProcess::spawn(options);

	// Start thread to read stdout/stderr stream
	if (m_enableBuildinThread) m_thread = std::make_unique<std::thread>(std::bind(&MonitoredProcess::runPipeReaderThread, this));

	// close write in parent side (write handler is used for child process in our case)
	m_pipe->close_write();
	return rt;
}

void MonitoredProcess::safeWait(int timerId)
{
	ACE_Process::wait();
	std::lock_guard<std::recursive_mutex> guard(m_queueMutex);
	if (nullptr != m_thread)
	{
		// crash will happen if thread join itself
		m_thread->join();
		m_thread = nullptr;
	}
}

std::string MonitoredProcess::fetchOutputMsg()
{
	const static char fname[] = "MonitoredProcess::fecthPipeMessages() ";

	std::stringstream stdoutMsg;
	{
		std::lock_guard<std::recursive_mutex> guard(m_queueMutex);
		while (m_msgQueue.size())
		{
			stdoutMsg << m_msgQueue.front();
			m_msgQueue.pop();
		}
		LOG_DBG << fname;
	}
	return std::move(stdoutMsg.str());
}

std::string MonitoredProcess::getOutputMsg()
{
	const static char fname[] = "MonitoredProcess::getPipeMessages() ";

	std::stringstream stdoutMsg;
	std::queue<std::string> msgQueue;
	{
		std::lock_guard<std::recursive_mutex> guard(m_queueMutex);
		msgQueue = m_msgQueue;
	}
	while (msgQueue.size())
	{
		stdoutMsg << msgQueue.front();
		msgQueue.pop();
	}
	std::string msgStr = stdoutMsg.str();
	LOG_DBG << fname;// << msgStr;
	return std::move(msgStr);
}

void MonitoredProcess::runPipeReaderThread()
{
	const static char fname[] = "MonitoredProcess::runPipeReaderThread() ";
	m_buildinThreadFinished = false;
	LOG_DBG << fname << "Entered";

	// hold self point to avoid release
	auto self = this->shared_from_this();

	const int stdoutQueueMaxLineCount = m_cacheOutputLines;
	char buffer[1024] = { 0 };
	while (true)
	{
		char* result = fgets(buffer, sizeof(buffer), m_readPipeFile);
		if (result == nullptr)
		{
			LOG_DBG << fname << "Get message from pipe finished";
			break;
		}
		// LOG_DBG << fname << "Read line : " << buffer;

		std::lock_guard<std::recursive_mutex> guard(m_queueMutex);
		m_msgQueue.push(buffer);
		// Do not store too much in memory
		if ((int)m_msgQueue.size() > stdoutQueueMaxLineCount) m_msgQueue.pop();
	}

	///////////////////////////////////////////////////////////////////////
	if (m_httpRequest)
	{
		try
		{
			web::http::http_response resp(web::http::status_codes::OK);
			resp.set_body(this->fetchOutputMsg());
			resp.headers().add(HTTP_HEADER_KEY_exit_code, this->return_value());
			if (m_httpRequest)
			{
				((HttpRequest*)m_httpRequest)->reply(resp).get();
				delete (HttpRequest*)m_httpRequest;
				m_httpRequest = nullptr;
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
	this->registerTimer(0, 0, std::bind(&MonitoredProcess::safeWait, this, std::placeholders::_1), fname);
}
