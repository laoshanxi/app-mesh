// src/daemon/process/StdoutStrategy.cpp
#include "StdoutStrategy.h"
#include "PipeStdoutStrategy.h"
#include "../../common/Utility.h"

// No-op strategy for processes without stdout capture.
class NullStdoutStrategy : public StdoutStrategy
{
public:
	void activate(TimerHandler &, const std::string &) override {}
	long dispatchedBytes() const override { return 0; }
	bool isActive() const override { return false; }
	void teardown() override {}
};

std::unique_ptr<StdoutStrategy> StdoutStrategy::create(
	std::string appName, ACE_HANDLE pipeRead, ACE_HANDLE diskWrite,
	std::shared_ptr<std::mutex> diskMutex,
	std::weak_ptr<Application> owner)
{
	if (pipeRead != ACE_INVALID_HANDLE && diskWrite != ACE_INVALID_HANDLE)
		return std::make_unique<PipeStdoutStrategy>(std::move(appName), pipeRead, diskWrite, std::move(diskMutex));
	return std::make_unique<NullStdoutStrategy>();
}
