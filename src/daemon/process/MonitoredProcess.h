// src/daemon/process/MonitoredProcess.h
#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <thread>

#include <boost/thread/synchronized_value.hpp>

#include "AppProcess.h"

class HttpRequest;

// Monitor process and reply HTTP request when finished
class MonitoredProcess : public AppProcess, public ACE_Process
{
public:
	explicit MonitoredProcess(std::weak_ptr<Application> owner);
	~MonitoredProcess();

	// Called when process exits
	void onExit(int exitCode) override;

	// Set async HTTP request to reply when process completes
	void setAsyncHttpRequest(std::shared_ptr<void> httpRequest);

	// Reply to async HTTP request with process output and exit code
	void replyAsyncRequest();

private:
	boost::synchronized_value<std::shared_ptr<HttpRequest>> m_httpRequest;
};
