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
class MonitoredProcess : public AppProcess
{
public:
	explicit MonitoredProcess(bool enableBuildinThread = true);
	virtual ~MonitoredProcess();

	// overwrite ACE_Process spawn method
	virtual pid_t spawn(ACE_Process_Options &options);

	virtual void waitThread(int timerId = 0);
	void setAsyncHttpRequest(void *httpRequest) { m_httpRequest = httpRequest; }

	void runPipeReaderThread();
	virtual bool complete() override { return m_buildinThreadFinished; }

private:
	void *m_httpRequest;

	std::unique_ptr<std::thread> m_thread;
	bool m_buildinThreadFinished;
	bool m_enableBuildinThread;
};
