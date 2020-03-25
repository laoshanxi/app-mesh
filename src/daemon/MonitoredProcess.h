#pragma once

#include <thread>
#include <memory>
#include <queue>
#include <mutex>
#include "AppProcess.h"

class ACE_Pipe;
class ACE_Process_Options;
//////////////////////////////////////////////////////////////////////////
/// Monitored Process Object
//////////////////////////////////////////////////////////////////////////
class MonitoredProcess :public AppProcess
{
public:
	explicit MonitoredProcess(int cacheOutputLines, bool enableBuildinThread = true);
	virtual ~MonitoredProcess();

	// overwrite ACE_Process spawn method
	virtual pid_t spawn(ACE_Process_Options& options);

	virtual void safeWait(int timerId = 0);
	void setAsyncHttpRequest(void* httpRequest) { m_httpRequest = httpRequest; }

	// pipe message
	virtual std::string getOutputMsg() override;
	virtual std::string fetchOutputMsg() override;
	void runPipeReaderThread();
	virtual bool complete() override { return m_buildinThreadFinished; }
private:
	ACE_HANDLE m_pipeHandler[2]; // 0 for read, 1 for write
	std::unique_ptr<ACE_Pipe> m_pipe;
	FILE* m_readPipeFile;

	std::queue<std::string> m_msgQueue;
	std::recursive_mutex m_queueMutex;
	void* m_httpRequest;

	std::unique_ptr<std::thread> m_thread;
	bool m_buildinThreadFinished;
	bool m_enableBuildinThread;
};
