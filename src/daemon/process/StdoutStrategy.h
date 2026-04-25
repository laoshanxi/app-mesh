// src/daemon/process/StdoutStrategy.h
#pragma once

#include <memory>
#include <mutex>
#include <string>

#include <ace/OS_NS_unistd.h>

class Application;

// Abstract base for stdout dispatch strategies.
class StdoutStrategy
{
public:
	virtual ~StdoutStrategy() = default;

	virtual long dispatchedBytes() const = 0;
	virtual bool isActive() const = 0;
	virtual void teardown() = 0;

	static std::unique_ptr<StdoutStrategy> create(
		std::string appName, ACE_HANDLE pipeRead, ACE_HANDLE diskWrite,
		std::shared_ptr<std::recursive_mutex> diskMutex,
		std::weak_ptr<Application> owner);

protected:
	StdoutStrategy() = default;

private:
	StdoutStrategy(const StdoutStrategy &) = delete;
	StdoutStrategy &operator=(const StdoutStrategy &) = delete;
};
