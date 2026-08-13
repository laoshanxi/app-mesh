// src/daemon/process/TimerStdoutStrategy.cpp
#include "TimerStdoutStrategy.h"

#include <nlohmann/json.hpp>

#include "../../common/StreamLogger.h"
#include "../application/Application.h"
#include "../rest/EventDispatcher.h"

TimerStdoutStrategy::TimerStdoutStrategy(std::string appName, std::weak_ptr<Application> owner)
	: m_state(std::make_shared<State>(std::move(appName), std::move(owner)))
{
}

TimerStdoutStrategy::~TimerStdoutStrategy()
{
	teardown();
}

void TimerStdoutStrategy::activate(TimerHandler &owner, const std::string &processUuid)
{
	const static char fname[] = "TimerStdoutStrategy::activate() ";
	auto state = m_state;
	std::lock_guard<std::mutex> registrationGuard(state->registrationMutex);
	state->processUuid = processUuid;
	state->stopped.store(false, std::memory_order_release);
	state->timerId = owner.registerTimer(0, 1000, fname, [state]()
										 { return onTimerDispatch(state); });
	if (!isValidTimerId(state->timerId))
		state->stopped.store(true, std::memory_order_release);
}

long TimerStdoutStrategy::dispatchedBytes() const
{
	return m_state->dispatchedBytes.load(std::memory_order_acquire);
}

void TimerStdoutStrategy::teardown()
{
	auto state = m_state;
	long timerId = INVALID_TIMER_ID;
	{
		std::lock_guard<std::mutex> registrationGuard(state->registrationMutex);
		state->stopped.store(true, std::memory_order_release);
		timerId = state->timerId.exchange(INVALID_TIMER_ID, std::memory_order_acq_rel);
	}
	TIMER_MANAGER::instance()->cancelTimer(timerId);
	std::lock_guard<std::mutex> guard(state->dispatchMutex);
}

bool TimerStdoutStrategy::onTimerDispatch(const std::shared_ptr<State> &state)
{
	const static char fname[] = "TimerStdoutStrategy::onTimerDispatch() ";

	{
		std::lock_guard<std::mutex> registrationGuard(state->registrationMutex);
		if (state->stopped.load(std::memory_order_acquire))
			return false;
	}
	auto owner = state->owner.lock();
	if (!owner)
	{
		state->timerId.store(INVALID_TIMER_ID, std::memory_order_release);
		return false;
	}
	if (!EventDispatcher::instance()->hasStdoutSubscriber(state->appName))
		return !state->stopped.load(std::memory_order_acquire);
	try
	{
		long pos = state->dispatchedBytes.load(std::memory_order_acquire);
		const long startPos = pos;
		auto result = owner->getOutput(pos, 64 * 1024, state->processUuid, 0, 0);
		auto &output = std::get<0>(result);
		std::lock_guard<std::mutex> guard(state->dispatchMutex);
		if (state->stopped.load(std::memory_order_acquire))
			return false;
		if (!output.empty())
		{
			nlohmann::json data;
			data["output"] = output;
			data["position"] = startPos;
			data["finished"] = std::get<1>(result);
			EventDispatcher::instance()->dispatch(state->appName, AppEventType::STDOUT_OUTPUT, data);
			state->dispatchedBytes.store(pos, std::memory_order_release);
		}
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "failed for app=" << state->appName << ": " << e.what();
	}
	return !state->stopped.load(std::memory_order_acquire);
}
