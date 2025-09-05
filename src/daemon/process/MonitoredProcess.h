#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include <boost/thread/synchronized_value.hpp>

#include "AppProcess.h"

class HttpRequest;
/// <summary>
/// Monitor process and reply http request when finished
/// <summary>
class MonitoredProcess : public AppProcess, public ACE_Process
{
public:
	explicit MonitoredProcess(void *owner);
	virtual ~MonitoredProcess();

	/// <summary>
	/// Set process exit code
	/// </summary>
	virtual void onExit(int exitCode) override;

	void setAsyncHttpRequest(void *httpRequest);
	void replyAsyncRequest();

private:
	boost::synchronized_value<std::shared_ptr<HttpRequest>> m_httpRequest;
};
