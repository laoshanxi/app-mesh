#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include "AppProcess.h"

class ACE_Process_Options;
class HttpRequestWithAppRef;
/// <summary>
/// Monitor process and reply http request when finished
/// <summary>
class MonitoredProcess : public AppProcess, public ACE_Process
{
public:
	explicit MonitoredProcess(const std::string &appName);
	virtual ~MonitoredProcess();

	/// <summary>
	/// Set process exit code
	/// </summary>
	virtual void onExit(int exitCode) override;

	void setAsyncHttpRequest(void *httpRequest);
	void replyAsyncRequest();

private:
	std::unique_ptr<HttpRequestWithAppRef> m_httpRequest;
	std::atomic_flag m_httpRequestReplyFlag;
};
