// src/daemon/process/StdoutStrategy.h
#pragma once

#include <memory>
#include <mutex>
#include <string>

#include <ace/OS_NS_unistd.h>

class Application;
class TimerHandler;

// Abstract base for stdout dispatch strategies.
class StdoutStrategy
{
public:
	virtual ~StdoutStrategy() = default;

	// Start dispatch only after the PROCESS_START event has been published.
	virtual void activate(TimerHandler &owner, const std::string &runId) = 0;
	virtual long dispatchedBytes() const = 0;
	virtual bool isActive() const = 0;
	virtual void teardown() = 0;

	static std::unique_ptr<StdoutStrategy> create(
		std::string appName, ACE_HANDLE pipeRead, ACE_HANDLE diskWrite,
		std::shared_ptr<std::mutex> diskMutex,
		std::weak_ptr<Application> owner);

protected:
	StdoutStrategy() = default;

private:
	StdoutStrategy(const StdoutStrategy &) = delete;
	StdoutStrategy &operator=(const StdoutStrategy &) = delete;
};
