#include <thread>
#include <cpprest/http_client.h>
#include "MonitoredProcess.h"
#include "../common/Utility.h"

MonitoredProcess::MonitoredProcess(int cacheOutputLines)
	:m_readPipeFile(0), m_monitorComplete(false), m_httpRequest(NULL), m_cacheOutputLines(cacheOutputLines)
{
}

MonitoredProcess::~MonitoredProcess()
{
	const static char fname[] = "MonitoredProcess::~MonitoredProcess() ";

	// clean pipe handlers and file
	if (m_pipe != nullptr) m_pipe->close();
	if (m_readPipeFile != nullptr) ACE_OS::fclose(m_readPipeFile);

	if (m_thread != nullptr) m_thread->join();

	LOG_DBG << fname << "Process <" << this->getpid() << "> released";
}

pid_t MonitoredProcess::spawn(ACE_Process_Options & options)
{
	const static char fname[] = "MonitoredProcess::spawn() ";

	m_pipe = std::make_shared<ACE_Pipe>();
	if (m_pipe->open(m_pipeHandler) < 0)
	{
		LOG_ERR << fname << "Create pipe failed with error : " << std::strerror(errno);
		return -1;
	}
	m_readPipeFile = ACE_OS::fdopen(m_pipe->read_handle(), "r");
	if (m_readPipeFile == nullptr)
	{
		LOG_ERR << fname << "Get file stream failed with error : " << std::strerror(errno);
		return -1;
	}
	else
	{
		// release the handles if already set in process options
		options.release_handles();
		options.set_handles(ACE_STDIN, m_pipe->write_handle(), m_pipe->write_handle());
	}
	auto rt = Process::spawn(options);

	// Start thread to read stdout/stderr stream
	m_thread = std::make_shared<std::thread>(std::bind(&MonitoredProcess::monitorThread, this));

	// close write in parent side (write handler is used for child process in our case)
	m_pipe->close_write();
	return rt;
}

std::string MonitoredProcess::fecthPipeMessages()
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

std::string MonitoredProcess::getPipeMessages()
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

pid_t MonitoredProcess::wait(const ACE_Time_Value& tv, ACE_exitcode* status)
{
	auto rt = ACE_Process::wait(tv, status);
	// Only need wait when process already exit.
	if (m_thread != nullptr && !this->running())
	{
		auto thread = m_thread;
		m_thread = nullptr;
		thread->join();
	}
	return rt;
}

bool MonitoredProcess::monitorComplete() const
{
	return m_monitorComplete;
}

void MonitoredProcess::monitorThread()
{
	const static char fname[] = "MonitoredProcess::monitorThread() ";
	m_monitorComplete = false;
	while (true)
	{
		char buffer[1024] = { 0 };
		char* result = fgets(buffer, sizeof(buffer), m_readPipeFile);
		if (result == nullptr)
		{
			LOG_ERR << fname << "Get line from pipe failed with error : " << std::strerror(errno);
			break;
		}
		LOG_DBG << fname << "Read line : " << buffer;

		const int stdoutQueueMaxLineCount = m_cacheOutputLines;
		std::lock_guard<std::recursive_mutex> guard(m_queueMutex);
		m_msgQueue.push(buffer);
		// Do not store too much in memory
		if (m_msgQueue.size() > stdoutQueueMaxLineCount) m_msgQueue.pop();
	}

	ACE_Process::wait();
	///////////////////////////////////////////////////////////////////////
	if (m_httpRequest)
	{
		web::http::http_request* message = (web::http::http_request*)m_httpRequest;
		try
		{
			web::http::http_response resp(web::http::status_codes::OK);
			resp.set_body(this->fecthPipeMessages());
			resp.headers().add("exit_code", this->return_value());
			message->reply(resp).get();
			delete message;
			m_httpRequest = NULL;
		}
		catch (...)
		{
			LOG_ERR << fname << "message reply failed, maybe the http connection broken with error: " << std::strerror(errno);
		}
	}
	///////////////////////////////////////////////////////////////////////


	LOG_DBG << fname << "monitor thread exit";
	m_monitorComplete = true;
}
