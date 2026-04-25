// src/daemon/process/StdoutStrategy.cpp
#include "StdoutStrategy.h"
#include "PipeStdoutStrategy.h"
#include "TimerStdoutStrategy.h"
#include "../../common/Utility.h"

// No-op strategy for processes without stdout capture.
class NullStdoutStrategy : public StdoutStrategy
{
public:
	long dispatchedBytes() const override { return 0; }
	bool isActive() const override { return false; }
	void teardown() override {}
};

std::unique_ptr<StdoutStrategy> StdoutStrategy::create(
	std::string appName, ACE_HANDLE pipeRead, ACE_HANDLE diskWrite,
	std::shared_ptr<std::recursive_mutex> diskMutex,
	std::weak_ptr<Application> owner)
{
#if !defined(_WIN32)
	if (pipeRead != ACE_INVALID_HANDLE && diskWrite != ACE_INVALID_HANDLE)
		return std::make_unique<PipeStdoutStrategy>(std::move(appName), pipeRead, diskWrite, std::move(diskMutex));
#else
	if (diskWrite != ACE_INVALID_HANDLE)
		return std::make_unique<TimerStdoutStrategy>(std::move(appName), std::move(owner));
#endif
	return std::make_unique<NullStdoutStrategy>();
}
