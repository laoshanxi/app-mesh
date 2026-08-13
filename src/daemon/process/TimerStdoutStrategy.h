// src/daemon/process/TimerStdoutStrategy.h
#pragma once

#include <atomic>
#include <mutex>

#include "StdoutStrategy.h"
#include "../../common/TimerHandler.h"

class Application;

// Windows timer-based 1Hz polling fallback for stdout dispatch.
// Timer is registered via the owning AppProcess.
class TimerStdoutStrategy : public StdoutStrategy
{
public:
	TimerStdoutStrategy(std::string appName, std::weak_ptr<Application> owner);
	~TimerStdoutStrategy() override;

	// Must be called after construction with the owning TimerHandler (AppProcess).
	void startTimer(TimerHandler &owner, std::string processUuid);

	long dispatchedBytes() const override;
	bool isActive() const override { return false; }
	void teardown() override;

private:
	struct State
	{
		State(std::string name, std::weak_ptr<Application> app)
			: appName(std::move(name)), owner(std::move(app)) {}

		const std::string appName;
		std::weak_ptr<Application> owner;
		std::string processUuid;
		std::atomic<long> dispatchedBytes{0};
		std::atomic_long timerId{INVALID_TIMER_ID};
		std::atomic_bool stopped{true};
		std::mutex registrationMutex;
		std::mutex dispatchMutex;
	};

	static bool onTimerDispatch(const std::shared_ptr<State> &state);
	std::shared_ptr<State> m_state;
};
