// src/daemon/process/PipeStdoutStrategy.h
#pragma once

#include <atomic>

#include "StdoutStrategy.h"

class StdoutPump;

// POSIX reactor-driven pipe pump strategy (wraps StdoutPump).
class PipeStdoutStrategy : public StdoutStrategy
{
public:
	PipeStdoutStrategy(std::string appName, ACE_HANDLE pipeRead,
					   ACE_HANDLE diskWrite, std::shared_ptr<std::recursive_mutex> diskMutex);
	~PipeStdoutStrategy() override;

	long dispatchedBytes() const override;
	bool isActive() const override { return !m_tornDown; }
	void teardown() override;

private:
	StdoutPump *m_pump{nullptr};
	std::atomic<long> m_snapshotBytes{0};
	std::atomic<bool> m_tornDown{false};
};
