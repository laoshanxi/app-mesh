#include "TimerHandler.h"
#include <ace/Time_Value.h>
#include <ace/OS.h>
#include <assert.h>
#include "TimerHandler.h"
#include "../common/Utility.h"

TimerHandler::TimerHandler()
{
}

TimerHandler::~TimerHandler()
{
}

int TimerHandler::handle_timeout(const ACE_Time_Value& current_time, const void* act)
{
	const static char fname[] = "TimerHandler::handle_timeout() ";

	const int* timerIdPtr = static_cast<const int*>(act);
	std::map<const int*, std::shared_ptr<TimerDefinition>> timers;
	{
		// Should not hold this lock too long
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		timers = m_timers;
	}

	if (timers.find(timerIdPtr) == timers.end())
	{
		LOG_WAR << fname << "unrecognized Timer Id <" << *timerIdPtr << ">.";
		// Remove this wrong timer
		return -1;
	}
	else
	{
		auto timerDef = timers.find(timerIdPtr)->second;
		timerDef->m_handler(*timerIdPtr);
		if (timerDef->m_callOnce)
		{
			LOG_DBG << fname << "one-time timer removed <" << *timerIdPtr << ">.";
			std::lock_guard<std::recursive_mutex> guard(m_mutex);
			m_timers.erase(timerIdPtr);
		}
	}
	return 0;
}

int TimerHandler::registerTimer(size_t delaySeconds, size_t intervalSeconds, const std::function<void(int)>& handler, const std::string from)
{
	const static char fname[] = "TimerHandler::registerTimer() ";

	bool callOnce = false;
	ACE_Time_Value delay(delaySeconds);
	ACE_Time_Value interval(intervalSeconds);
	if (intervalSeconds == 0)
	{
		interval = ACE_Time_Value::zero;
		callOnce = true;
	}

	int* timerIdPtr = new int(0);
	(*timerIdPtr) = ACE_Reactor::instance()->schedule_timer(this, (void*)timerIdPtr, delay, interval);
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	assert(m_timers.find(timerIdPtr) == m_timers.end());
	m_timers[timerIdPtr] = std::make_shared<TimerDefinition>(timerIdPtr, handler, this->shared_from_this(), callOnce);
	LOG_DBG << fname << from << " register timer <" << *timerIdPtr << "> delaySeconds <" << delaySeconds << "> intervalSeconds <" << intervalSeconds << ">.";
	return *timerIdPtr;
}

bool TimerHandler::cancleTimer(int timerId)
{
	const static char fname[] = "TimerHandler::cancleTimer() ";

	auto cancled = ACE_Reactor::instance()->cancel_timer(timerId);
	LOG_DBG << fname << "Timer <" << timerId << "> cancled <" << cancled << ">.";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	for (auto& v : m_timers)
	{
		if (timerId == *(v.first))
		{
			m_timers.erase(v.first);
			LOG_DBG << fname << "Timer removed <" << timerId << ">.";
			break;
		}
	}

	return cancled;
}

void TimerHandler::runTimerThread()
{
	const static char fname[] = "TimerHandler::runEventLoop() ";
	LOG_DBG << fname << "Entered";

	while (!ACE_Reactor::instance()->reactor_event_loop_done())
	{
		// set the owner of the reactor to the identity of the thread that runs the event loop
		ACE_Reactor::instance()->owner(ACE_OS::thr_self());
		ACE_Reactor::instance()->run_reactor_event_loop();
	}
	LOG_WAR << fname << "Exit";
}

int TimerHandler::endEventLoop()
{
	return ACE_Reactor::instance()->end_reactor_event_loop();
}

TimerHandler::TimerDefinition::TimerDefinition(const int* timerId, std::function<void(int)> handler, const std::shared_ptr<TimerHandler> object, bool callOnce)
	:m_timerId(timerId), m_handler(handler), m_timerObject(object), m_callOnce(callOnce)
{
}

TimerHandler::TimerDefinition::~TimerDefinition()
{
	delete m_timerId;
}
