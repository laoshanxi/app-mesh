// src/daemon/process/MonitoredProcess.h
#pragma once

#include <memory>

#include <boost/thread/synchronized_value.hpp>

#include "AppProcess.h"

class HttpRequest;

// Monitor process and reply HTTP request when finished
class MonitoredProcess : public AppProcess
{
public:
	explicit MonitoredProcess(std::weak_ptr<Application> owner);
	~MonitoredProcess();

	// Set async HTTP request to reply when process completes
	void setAsyncHttpRequest(std::shared_ptr<void> httpRequest);

protected:
	void finishExit(int exitCode) override;

private:
	std::shared_ptr<HttpRequest> replyAsyncRequest();
	boost::synchronized_value<std::shared_ptr<HttpRequest>> m_httpRequest;
};
