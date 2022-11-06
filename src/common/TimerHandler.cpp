
#include <ace/OS.h>
#include <ace/TP_Reactor.h>
#include <ace/Time_Value.h>
#include <assert.h>

#include "../common/Utility.h"
#include "TimerHandler.h"

////////////////////////////////////////////////////////////////
/// TimerEvent
////////////////////////////////////////////////////////////////
TimerEvent::TimerEvent(bool callOnce, const std::shared_ptr<TimerHandler> timerObj, const std::function<void(void)> &handler)
	: m_timerObj(timerObj), m_handler(handler), m_callOnce(callOnce)
{
}

int TimerEvent::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
	const static char fname[] = "TimerEvent::handle_timeout() ";

	if (act)
	{
		if (act != (void *)this)
		{
			LOG_ERR << fname << "invalid timer, target not match act: <" << act << ">, this <" << this << ">";
			return -1;
		}
		// call timer function
		m_handler();
		if (m_callOnce)
		{
			LOG_DBG << fname << "one-time timer <" << this << "> removed";
			// stop timer - will call handle_close()
			return -1;
		}
	}
	else
	{
		LOG_ERR << fname << "invalid timer triggered <" << this << ">";
		return -1;
	}
	// continue till next interval
	return 0;
}

int TimerEvent::handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask)
{
	const static char fname[] = "TimerEvent::handle_close() ";
	LOG_DBG << fname << "timer <" << this << ">";
	// self destruct
	delete this;
	return 0;
}

////////////////////////////////////////////////////////////////
/// TimerManager
////////////////////////////////////////////////////////////////
TimerManager::TimerManager()
	: m_reactor(new ACE_TP_Reactor(), true)
{
	const static char fname[] = "TimerManager::TimerManager() ";
	LOG_DBG << fname;
}

TimerManager::~TimerManager()
{
	const static char fname[] = "TimerManager::~TimerManager() ";
	LOG_DBG << fname;
}

ACE_Reactor *TimerManager::reactor()
{
	return &m_reactor;
}

long TimerManager::registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::string &from, const std::shared_ptr<TimerHandler> timerObj, const std::function<void(void)> &handler)
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
	TimerEvent *timer = new TimerEvent(callOnce, timerObj, handler);
	long timerId = m_reactor.schedule_timer(timer, (void *)timer, delay, interval);
	LOG_DBG << fname << from << " " << timer << " register timer <" << timerId << "> delay seconds <" << (delayMillisecond / 1000) << "> interval seconds <" << intervalSeconds << ">.";
	if (timerId < 0)
	{
		timer->handle_close(ACE_INVALID_HANDLE, (ACE_Reactor_Mask)0); // self-destruct
		LOG_ERR << fname << from << " failed register timer with error: " << std::strerror(errno);
	}
	return timerId;
}

bool TimerManager::cancelTimer(long &timerId)
{
	const static char fname[] = "TimerManager::cancelTimer() ";

	if (timerId <= INVALID_TIMER_ID)
	{
		return false;
	}
	TimerEvent *timer = nullptr;
	auto cancled = this->reactor()->cancel_timer(timerId, (const void **)&timer);
	LOG_DBG << fname << "timer <" << timerId << "> cancled <" << cancled << ">.";

	if (cancled == 1 && timer)
	{
		timer->handle_close(ACE_INVALID_HANDLE, ACE_Event_Handler::TIMER_MASK);
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

////////////////////////////////////////////////////////////////
/// TimerHandler
////////////////////////////////////////////////////////////////
TimerHandler::~TimerHandler()
{
}

long TimerHandler::registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::function<void(void)> &handler, const std::string &from)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMillisecond, intervalSeconds, from, this->shared_from_this(), handler);
}

bool TimerHandler::cancelTimer(long &timerId)
{
	return TIMER_MANAGER::instance()->cancelTimer(timerId);
}
