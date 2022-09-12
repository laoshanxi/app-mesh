
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/TP_Reactor.h>
#include <ace/Time_Value.h>
#include <assert.h>

#include "../common/Utility.h"
#include "TimerHandler.h"

ACE_Reactor TimerManager::m_reactor(new ACE_TP_Reactor(), true);
TimerManager::TimerManager()
{
}

TimerManager::~TimerManager()
{
}

int TimerManager::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
	const static char fname[] = "TimerManager::handle_timeout() ";

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

int TimerManager::registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::function<void(int)> &handler, const std::string &from, const std::shared_ptr<TimerHandler> fromObj)
{
	const static char fname[] = "TimerManager::registerTimer() ";

	bool callOnce = false;
	ACE_Time_Value delay;
	delay.msec(delayMillisecond);
	ACE_Time_Value interval(intervalSeconds);
	if (intervalSeconds == 0)
	{
		interval = ACE_Time_Value::zero;
		callOnce = true;
	}

	int *timerIdPtr = new int(INVALID_TIMER_ID);
	std::lock_guard<std::recursive_mutex> guard(m_timerMutex);
	(*timerIdPtr) = m_reactor.schedule_timer(this, (void *)timerIdPtr, delay, interval);
	// once schedule_timer failed(return -1), do not hold shared_ptr, the handler will never be triggered
	if ((*timerIdPtr) >= 0)
	{
		assert(m_timers.find(timerIdPtr) == m_timers.end());
		m_timers[timerIdPtr] = std::make_shared<TimerEvent>(timerIdPtr, handler, fromObj, callOnce);
		LOG_DBG << fname << from << " register timer <" << *timerIdPtr << "> delay seconds <" << (delayMillisecond / 1000) << "> interval seconds <" << intervalSeconds << ">.";
		return *timerIdPtr;
	}
	else
	{
		std::unique_ptr<int> autoRelease(timerIdPtr);
		LOG_ERR << fname << from << " failed with error: " << std::strerror(errno);
		return -1;
	}
}

bool TimerManager::cancelTimer(int &timerId)
{
	const static char fname[] = "TimerManager::cancelTimer() ";

	if (timerId <= INVALID_TIMER_ID)
	{
		return false;
	}

	auto cancled = m_reactor.cancel_timer(timerId);
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
	timerId = INVALID_TIMER_ID;
	return cancled;
}

void TimerManager::runReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "TimerManager::runReactorEvent() ";
	LOG_DBG << fname << "Entered";

	if (QUIT_HANDLER::instance()->is_set() == 0)
	{
		reactor->owner(ACE_OS::thr_self());
		reactor->run_reactor_event_loop();
	}
	LOG_WAR << fname << "Exit";
}

int TimerManager::endReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "TimerManager::endReactorEvent() ";
	LOG_DBG << fname << "Entered";

	return reactor->end_reactor_event_loop();
}

ACE_Reactor *TimerManager::timerReactor()
{
	return &m_reactor;
}

TimerManager::TimerEvent::TimerEvent(int *timerId, std::function<void(int)> handler, const std::shared_ptr<TimerHandler> object, bool callOnce)
	: m_timerId(timerId), m_handler(handler), m_timerObject(object), m_callOnce(callOnce)
{
}

int TimerHandler::registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::function<void(int)> &handler, const std::string &from)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMillisecond, intervalSeconds, handler, from, this->shared_from_this());
}

bool TimerHandler::cancelTimer(int &timerId)
{
	return TIMER_MANAGER::instance()->cancelTimer(timerId);
}
