// src/daemon/process/PipeStdoutStrategy.h
#pragma once

#include <atomic>
#include <memory>

#include "StdoutStrategy.h"

class StdoutPump;

// POSIX pipe pump strategy: owns an asio StdoutPump running on the
// ProcessService io thread.
class PipeStdoutStrategy : public StdoutStrategy
{
public:
	// construction creates the pump (fd ownership transfers to the pump)
	PipeStdoutStrategy(std::string appName, int pipeReadFd, int diskWriteFd, std::shared_ptr<std::mutex> diskMutex);
	~PipeStdoutStrategy() override;

	void activate(TimerHandler &owner, const std::string &runId) override;
	long dispatchedBytes() const override;
	bool isActive() const override { return !m_tornDown.load(std::memory_order_acquire) && m_pump != nullptr; }
	void teardown() override;

private:
	std::shared_ptr<StdoutPump> m_pump;
	std::atomic<long> m_snapshotBytes{0};
	std::atomic<bool> m_tornDown{false};
};
