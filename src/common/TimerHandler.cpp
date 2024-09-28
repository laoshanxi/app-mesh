#include <ace/OS.h>
#include <ace/Time_Value.h>
#include <assert.h>

#include "../common/Utility.h"
#include "TimerHandler.h"

////////////////////////////////////////////////////////////////
/// TimerEvent
////////////////////////////////////////////////////////////////
TimerEvent::TimerEvent(bool isOneShot, const std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
	: m_timerObj(timerObj), m_handler(handler), m_isOneShot(isOneShot)
{
	const static char fname[] = "TimerEvent::TimerEvent() ";
	LOG_DBG << fname << "timer <" << this << ">";
}

int TimerEvent::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
	const static char fname[] = "TimerEvent::handle_timeout() ";

	// Validate act 'magic cookie'
	if (act != static_cast<const void *>(this))
	{
		LOG_ERR << fname << "invalid timer triggered, act: <" << act << "> != this <" << this << ">";
		return -1;
	}

	// Execute timer callback (true to continue, false to stop)
	bool timerContinue = m_handler();

	if (m_isOneShot)
	{
		LOG_DBG << fname << "one-shot timer <" << this << "> removed";
		return -1; // Stop timer - will call handle_close()
	}

	if (!timerContinue)
	{
		LOG_DBG << fname << "timer <" << this << "> removed due to callback return value";
		return -1; // Stop timer - will call handle_close()
	}

	return 0; // Continue till next interval
}

int TimerEvent::handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask)
{
	const static char fname[] = "TimerEvent::handle_close() ";
	LOG_DBG << fname << "timer <" << this << ">";

	delete this; // Self-destruct
	return 0;
}

////////////////////////////////////////////////////////////////
/// TimerManager
////////////////////////////////////////////////////////////////
TimerManager::TimerManager()
	: m_timerQueue(ACE_Thread_Manager::instance())
{
	const static char fname[] = "TimerManager::TimerManager() ";
	LOG_DBG << fname;
	m_timerQueue.activate();
}

TimerManager::~TimerManager()
{
	const static char fname[] = "TimerManager::~TimerManager() ";
	LOG_DBG << fname;
}

long TimerManager::registerTimer(long int delayMilliseconds, std::size_t intervalSeconds, const std::string &from, const std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
{
	const static char fname[] = "TimerManager::registerTimer() ";

	bool isOneShot = (intervalSeconds == 0);
	ACE_Time_Value future = (delayMilliseconds == 0) ? ACE_Time_Value::zero : ACE_OS::gettimeofday() + ACE_Time_Value(delayMilliseconds / 1000, (delayMilliseconds % 1000) * 1000);
	ACE_Time_Value interval = (intervalSeconds == 0) ? ACE_Time_Value::zero : ACE_Time_Value(intervalSeconds);

	// Pass TimerEvent as both ACE_Event_Handler and 'magic cookie' act
	// Memory will be released in TimerEvent::handle_close()
	TimerEvent *timer = new TimerEvent(isOneShot, timerObj, handler);
	long timerId = m_timerQueue.schedule(timer, (void *)timer, future, interval);

	LOG_DBG << fname << from << " object <" << timerObj.get() << "> registered timer ID <" << timerId << ">, delay <" << (delayMilliseconds / 1000) << ">s interval <" << intervalSeconds << ">s";

	if (timerId < 0)
	{
		timer->handle_close(ACE_INVALID_HANDLE, ACE_Event_Handler::TIMER_MASK); // Self-destruct
		LOG_ERR << fname << from << " failed to register timer: " << std::strerror(errno);
	}
	return timerId;
}

bool TimerManager::cancelTimer(long &timerId)
{
	const static char fname[] = "TimerManager::cancelTimer() ";

	if (!IS_VALID_TIMER_ID(timerId))
	{
		return false;
	}

	TimerEvent *timer = nullptr;
	auto canceled = m_timerQueue.cancel(timerId, (const void **)(&timer));
	LOG_DBG << fname << "timer ID <" << timerId << "> cancel result <" << canceled << ">";

	if (canceled > 0 && timer)
	{
		// Call handle_close() on successful cancellation
		// ACE_Thread_Timer_Queue_Adapter::cancel() does not pass proper dont_call_handle_close
		timer->handle_close(ACE_INVALID_HANDLE, ACE_Event_Handler::TIMER_MASK);
		CLEAR_TIMER_ID(timerId);
	}
	else
	{
		LOG_ERR << fname << "failed to cancel timer ID <" << timerId << ">";
	}

	return canceled;
}

////////////////////////////////////////////////////////////////
/// TimerHandler
////////////////////////////////////////////////////////////////
TimerHandler::~TimerHandler() {}

long TimerHandler::registerTimer(long int delayMilliseconds, std::size_t intervalSeconds, const TimerCallback &handler, const std::string &from)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMilliseconds, intervalSeconds, from, this->shared_from_this(), handler);
}

bool TimerHandler::cancelTimer(std::atomic_long &timerId)
{
	long thisId = timerId.exchange(INVALID_TIMER_ID);
	if (IS_VALID_TIMER_ID(thisId))
		return TIMER_MANAGER::instance()->cancelTimer(thisId);
	return false;
}
