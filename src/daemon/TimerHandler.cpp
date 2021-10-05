
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/Time_Value.h>
#include <assert.h>

#include "../common/Utility.h"
#include "TimerHandler.h"

TimerHandler::TimerHandler()
	: m_reactor(ACE_Reactor::instance())
{
}

TimerHandler::~TimerHandler()
{
}

int TimerHandler::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
	const static char fname[] = "TimerHandler::handle_timeout() ";

	const int *timerIdPtr = static_cast<const int *>(act);
	std::map<const int *, std::shared_ptr<TimerEvent>> timers;
	{
		// Should not hold this lock too long
		std::lock_guard<std::recursive_mutex> guard(m_timerMutex);
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
		if (timerDef->m_callOnce)
		{
			// remove one-time handler from map before run callback
			LOG_DBG << fname << "one-time timer removed <" << *timerIdPtr << ">.";
			std::lock_guard<std::recursive_mutex> guard(m_timerMutex);
			m_timers.erase(timerIdPtr);
		}
		timerDef->m_handler(*timerIdPtr);
	}
	return 0;
}

int TimerHandler::registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::function<void(int)> &handler, const std::string &from)
{
	const static char fname[] = "TimerHandler::registerTimer() ";

	bool callOnce = false;
	ACE_Time_Value delay;
	delay.msec(delayMillisecond);
	ACE_Time_Value interval(intervalSeconds);
	if (intervalSeconds == 0)
	{
		interval = ACE_Time_Value::zero;
		callOnce = true;
	}

	int *timerIdPtr = new int(0);
	std::lock_guard<std::recursive_mutex> guard(m_timerMutex);
	(*timerIdPtr) = m_reactor->schedule_timer(this, (void *)timerIdPtr, delay, interval);
	assert(m_timers.find(timerIdPtr) == m_timers.end());
	m_timers[timerIdPtr] = std::make_shared<TimerEvent>(timerIdPtr, handler, this->shared_from_this(), callOnce);
	LOG_DBG << fname << from << " register timer <" << *timerIdPtr << "> delay seconds <" << (delayMillisecond / 1000) << "> interval seconds <" << intervalSeconds << ">.";
	return *timerIdPtr;
}

bool TimerHandler::cancelTimer(int &timerId)
{
	const static char fname[] = "TimerHandler::cancelTimer() ";

	if (0 == timerId)
		return false;
	auto cancled = m_reactor->cancel_timer(timerId);
	LOG_DBG << fname << "Timer <" << timerId << "> cancled <" << cancled << ">.";

	std::lock_guard<std::recursive_mutex> guard(m_timerMutex);
	auto it = std::find_if(m_timers.begin(), m_timers.end(),
						   [timerId](std::map<const int *, std::shared_ptr<TimerEvent>>::value_type const &pair)
						   {
							   return timerId == *(pair.first);
						   });
	if (it != m_timers.end())
	{
		m_timers.erase(it);
		LOG_DBG << fname << "Timer removed <" << timerId << ">.";
	}
	timerId = 0;
	return cancled;
}

void TimerHandler::runReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "TimerHandler::runReactorEvent() ";
	LOG_DBG << fname << "Entered";

	while (!reactor->reactor_event_loop_done())
	{
		// set the owner of the reactor to the identity of the thread that runs the event loop
		reactor->owner(ACE_OS::thr_self());
		reactor->run_reactor_event_loop();
		LOG_ERR << fname << "run_reactor_event_loop exited";
	}
	LOG_WAR << fname << "Exit";
}

int TimerHandler::endReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "TimerHandler::endReactorEvent() ";
	LOG_DBG << fname << "Entered";

	return reactor->end_reactor_event_loop();
}

TimerHandler::TimerEvent::TimerEvent(int *timerId, std::function<void(int)> handler, const std::shared_ptr<TimerHandler> object, bool callOnce)
	: m_timerId(timerId), m_handler(handler), m_timerObject(object), m_callOnce(callOnce)
{
}
