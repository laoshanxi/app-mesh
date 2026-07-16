// src/daemon/process/TimerStdoutStrategy.cpp
#include "TimerStdoutStrategy.h"

#include <nlohmann/json.hpp>

#include "../../common/StreamLogger.h"
#include "../application/Application.h"
#include "../rest/EventDispatcher.h"

TimerStdoutStrategy::TimerStdoutStrategy(std::string appName, std::weak_ptr<Application> owner)
	: m_appName(std::move(appName)),
	  m_owner(std::move(owner))
{
}

TimerStdoutStrategy::~TimerStdoutStrategy()
{
	teardown();
}

void TimerStdoutStrategy::startTimer(TimerHandler &owner)
{
	const static char fname[] = "TimerStdoutStrategy::startTimer() ";
	m_timerId = owner.registerTimer(0, 1000, fname, std::bind(&TimerStdoutStrategy::onTimerDispatch, this));
}

void TimerStdoutStrategy::teardown()
{
	cancelTimer(m_timerId);
}

bool TimerStdoutStrategy::onTimerDispatch()
{
	const static char fname[] = "TimerStdoutStrategy::onTimerDispatch() ";

	auto owner = m_owner.lock();
	if (!owner)
		return IS_VALID_TIMER_ID(m_timerId);
	if (!EventDispatcher::instance()->hasStdoutSubscriber(m_appName))
		return IS_VALID_TIMER_ID(m_timerId);
	try
	{
		long pos = m_dispatchedBytes.load(std::memory_order_acquire);
		const long startPos = pos;
		auto result = owner->getOutput(pos, 64 * 1024, "", 0, 0);
		auto &output = std::get<0>(result);
		if (!output.empty())
		{
			nlohmann::json data;
			data["output"] = output;
			data["position"] = startPos;
			data["finished"] = std::get<1>(result);
			EventDispatcher::instance()->dispatch(m_appName, AppEventType::STDOUT_OUTPUT, data);
			m_dispatchedBytes.store(pos, std::memory_order_release);
		}
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "failed for app=" << m_appName << ": " << e.what();
	}
	return IS_VALID_TIMER_ID(m_timerId);
}
