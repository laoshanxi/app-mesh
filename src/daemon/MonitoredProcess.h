#pragma once

#include <thread>
#include <memory>
#include <queue>
#include <string>
#include <mutex>
#include "AppProcess.h"

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

	virtual void waitThread(int timerId = 0);
	void setAsyncHttpRequest(void* httpRequest) { m_httpRequest = httpRequest; }

	// pipe message
	virtual std::string getOutputMsg() override;
	virtual std::string fetchOutputMsg() override;
	std::string fetchLine();
	void runPipeReaderThread();
	virtual bool complete() override { return m_buildinThreadFinished; }

private:
	const int m_cacheOutputLines;
	/// @brief 0 for parent read, 1 for child write
	ACE_HANDLE m_pipeHandler[2];
	FILE* m_readPipeFile;

	std::queue<std::string> m_msgQueue;
	std::recursive_mutex m_queueMutex;
	void* m_httpRequest;

	std::unique_ptr<std::thread> m_thread;
	bool m_buildinThreadFinished;
	bool m_enableBuildinThread;
};
