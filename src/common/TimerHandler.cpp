
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/Time_Value.h>
#include <assert.h>

#include "../common/Utility.h"
#include "TimerHandler.h"

TimerManager::TimerManager()
{
	const static char fname[] = "TimerManager::TimerManager() ";
	LOG_DBG << fname;
	this->reactor(&m_reactor);
}

TimerManager::~TimerManager()
{
	const static char fname[] = "TimerManager::~TimerManager() ";
	LOG_DBG << fname;
}

int TimerManager::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
	const static char fname[] = "TimerManager::handle_timeout() ";

	const int *timerIdPtr = static_cast<const int *>(act);
	std::shared_ptr<TimerEvent> timerDef;
	if (m_timers.find(timerIdPtr, timerDef) != 0)
	{
		LOG_WAR << fname << "unrecognized Timer Id <" << *timerIdPtr << ">.";
		// remove this wrong timer
		return -1;
	}
	else
	{
		if (timerDef->m_callOnce)
		{
			// remove one-time handler from map before run callback
			auto removed = m_timers.unbind(timerIdPtr, timerDef);
			LOG_DBG << fname << "one-time timer <" << *timerIdPtr << "> removed:" << (removed == 0);
		}
		// call timer function
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
	(*timerIdPtr) = this->reactor()->schedule_timer(this, (void *)timerIdPtr, delay, interval);
	// once schedule_timer failed(return -1), do not hold shared_ptr, the handler will never be triggered
	if ((*timerIdPtr) >= 0)
	{
		assert(m_timers.find(timerIdPtr) != 0);
		m_timers.bind(timerIdPtr, std::make_shared<TimerEvent>(timerIdPtr, handler, fromObj, callOnce));
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

	auto cancled = this->reactor()->cancel_timer(timerId);
	LOG_DBG << fname << "timer <" << timerId << "> cancled <" << cancled << ">.";

	ACE_Guard<ACE_Recursive_Thread_Mutex> locker(m_timers.mutex());
	for (const auto &timer : m_timers)
	{
		if (timerId == *(timer.ext_id_))
		{
			m_timers.unbind(timer.ext_id_);
			LOG_DBG << fname << "timer <" << timerId << "> removed.";
			break;
		}
	}
	timerId = INVALID_TIMER_ID;
	return cancled;
}

void TimerManager::runReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "TimerManager::runReactorEvent() ";
	LOG_DBG << fname << "Entered";

	reactor->owner(ACE_OS::thr_self());
	while (QUIT_HANDLER::instance()->is_set() == 0 && !reactor->reactor_event_loop_done())
	{

		reactor->run_reactor_event_loop();
		LOG_WAR << fname << "reactor_event_loop";
	}
	LOG_WAR << fname << "Exit";
}

int TimerManager::endReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "TimerManager::endReactorEvent() ";
	LOG_DBG << fname << "Entered";

	return reactor->end_reactor_event_loop();
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
