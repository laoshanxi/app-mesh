#include <thread>
#include "MonitoredProcess.h"
#include "../common/Utility.h"

MonitoredProcess::MonitoredProcess()
	:m_readPipeFile(0), m_monitorComplete(false)
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
	std::stringstream stdoutMsg;
	{
		std::lock_guard<std::recursive_mutex> guard(m_queueMutex);
		while (m_msgQueue.size())
		{
			stdoutMsg << m_msgQueue.front();
			m_msgQueue.pop();
		}
	}
	return std::move(stdoutMsg.str());
}

pid_t MonitoredProcess::wait(const ACE_Time_Value& tv, ACE_exitcode* status)
{
	// Only need wait when process already exit.
	if (m_thread != nullptr && !this->running())
	{
		auto thread = m_thread;
		m_thread = nullptr;
		thread->join();
	}
	return ACE_Process::wait(tv, status);
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

		const int stdoutQueueMaxLineCount = 1024;
		std::lock_guard<std::recursive_mutex> guard(m_queueMutex);
		m_msgQueue.push(buffer);
		// Do not store too much in memory
		if (m_msgQueue.size() > stdoutQueueMaxLineCount) m_msgQueue.pop();
	}
	m_monitorComplete = true;
}
