#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "AppProcess.h"

class ACE_Process_Options;
/// <summary>
/// Monitor process and reply http request when finished
/// <summary>
class MonitoredProcess : public AppProcess
{
public:
	explicit MonitoredProcess();
	virtual ~MonitoredProcess();

	// overwrite ACE_Process spawn method
	virtual pid_t spawn(ACE_Process_Options &options);
	void setAsyncHttpRequest(void *httpRequest) { m_httpRequest = httpRequest; }

protected:
	virtual void waitThread(int timerId = INVALID_TIMER_ID);
	void runPipeReaderThread();

private:
	void *m_httpRequest;
	std::unique_ptr<std::thread> m_thread;
};
