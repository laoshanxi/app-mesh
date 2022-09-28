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
	virtual pid_t spawn(ACE_Process_Options &options) override;
	void setAsyncHttpRequest(void *httpRequest) { m_httpRequest = httpRequest; }
	void replyAsyncRequest();

	/// <summary>
	/// kill the process group
	/// </summary>
	/// <param name="timerId"></param>
	virtual void killgroup(int timerId = INVALID_TIMER_ID) override;

protected:
	virtual void waitThread(int timerId = INVALID_TIMER_ID);
	void runPipeReaderThread();

private:
	void *m_httpRequest;
	mutable std::recursive_mutex m_httpRequestMutex;
	std::unique_ptr<std::thread> m_thread;
};
