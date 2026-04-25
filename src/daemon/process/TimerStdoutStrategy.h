// src/daemon/process/TimerStdoutStrategy.h
#pragma once

#include <atomic>

#include "StdoutStrategy.h"
#include "../../common/TimerHandler.h"

class Application;

// Windows timer-based 1Hz polling fallback for stdout dispatch.
// Timer is registered via an external TimerHandler (AppProcess) so the
// TimerEvent holds shared_from_this() on the owner — preventing UAF if
// the strategy is destroyed while a callback is in-flight.
class TimerStdoutStrategy : public StdoutStrategy
{
public:
	TimerStdoutStrategy(std::string appName, std::weak_ptr<Application> owner);
	~TimerStdoutStrategy() override;

	// Must be called after construction with the owning TimerHandler (AppProcess).
	void startTimer(TimerHandler &owner);

	long dispatchedBytes() const override { return m_dispatchedBytes.load(std::memory_order_acquire); }
	bool isActive() const override { return false; }
	void teardown() override;

private:
	bool onTimerDispatch();

	const std::string m_appName;
	std::weak_ptr<Application> m_owner;
	std::atomic<long> m_dispatchedBytes{0};
	std::atomic_long m_timerId{INVALID_TIMER_ID};
};
