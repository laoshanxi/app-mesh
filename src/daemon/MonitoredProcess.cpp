#include <thread>
#include "MonitoredProcess.h"
#include "../common/Utility.h"
#include "../common/HttpRequest.h"

MonitoredProcess::MonitoredProcess(int cacheOutputLines, bool enableBuildinThread)
	:AppProcess(cacheOutputLines), m_readPipeFile(0), m_httpRequest(NULL), m_buildinThreadFinished(false), m_enableBuildinThread(enableBuildinThread)
{
}

MonitoredProcess::~MonitoredProcess()
{
	const static char fname[] = "MonitoredProcess::~MonitoredProcess() ";

	// clean pipe handlers and file
	if (m_pipe != nullptr) m_pipe->close();
	if (m_readPipeFile != nullptr) ACE_OS::fclose(m_readPipeFile);

	if (m_thread != nullptr) m_thread->join();

	if (m_httpRequest)
	{
		delete (HttpRequest*)m_httpRequest;
		m_httpRequest = NULL;
	}

	LOG_DBG << fname << "Process <" << this->getpid() << "> released";
}

pid_t MonitoredProcess::spawn(ACE_Process_Options & options)
{
	const static char fname[] = "MonitoredProcess::spawn() ";

	m_pipe = std::make_shared<ACE_Pipe>();
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
	if (m_enableBuildinThread) m_thread = std::make_shared<std::thread>(std::bind(&MonitoredProcess::runPipeReaderThread, this));

	// close write in parent side (write handler is used for child process in our case)
	m_pipe->close_write();
	return rt;
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
		LOG_NST << fname;
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
	LOG_NST << fname;// << msgStr;
	return std::move(msgStr);
}

pid_t MonitoredProcess::wait(const ACE_Time_Value& tv, ACE_exitcode* status)
{
	auto rt = ACE_Process::wait(tv, status);
	if (rt > 0)
	{
		// Only need wait thread when process already exit.
		m_thread->join();
		m_thread = nullptr;
	}
	return rt;
}

bool MonitoredProcess::complete() const
{
	return m_buildinThreadFinished;
}

void MonitoredProcess::runPipeReaderThread()
{
	const static char fname[] = "MonitoredProcess::monitorThread() ";
	m_buildinThreadFinished = false;
	LOG_NST << fname << "Entered";

	const int stdoutQueueMaxLineCount = m_cacheOutputLines;
	char buffer[768] = { 0 };
	while (true)
	{
		char* result = fgets(buffer, sizeof(buffer), m_readPipeFile);
		if (result == nullptr)
		{
			LOG_DBG << fname << "Get message from pipe finished";
			break;
		}
		LOG_NST << fname << "Read line : " << buffer;

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
				m_httpRequest = NULL;
			}
		}
		catch (...)
		{
			LOG_ERR << fname << "message reply failed, maybe the http connection broken with error: " << std::strerror(errno);
		}
	}
	///////////////////////////////////////////////////////////////////////
	ACE_Process::wait();	// release defunct process here
	LOG_NST << fname << "Exited";
	m_buildinThreadFinished = true;
}
