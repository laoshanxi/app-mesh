#include <ace/OS.h>
#include <ace/Time_Value.h>

#include "../common/Utility.h"
#include "TimerHandler.h"

////////////////////////////////////////////////////////////////
/// TimerEvent
////////////////////////////////////////////////////////////////
TimerEvent::TimerEvent(bool isOneShot, std::shared_ptr<TimerHandler> timerObj, TimerCallback handler) noexcept
	: m_timerObj(std::move(timerObj)), m_handler(std::move(handler)), m_isOneShot(isOneShot)
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
	if (!m_handler() || m_isOneShot)
	{
		LOG_DBG << fname << "timer <" << this << "> removed due to " << (m_isOneShot ? "one-shot" : "callback return");
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
	m_timerQueue.deactivate();
	m_timerQueue.wait();
}

long TimerManager::registerTimer(long delayMilliseconds, std::size_t intervalSeconds, std::string from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
{
	const static char fname[] = "TimerManager::registerTimer() ";

	ACE_Time_Value future = (delayMilliseconds == 0) ? ACE_Time_Value::zero : ACE_OS::gettimeofday() + ACE_Time_Value(delayMilliseconds / 1000, (delayMilliseconds % 1000) * 1000);
	ACE_Time_Value interval(intervalSeconds);

	// Pass TimerEvent as both ACE_Event_Handler and 'magic cookie' act
	// Memory will be released in TimerEvent::handle_close()
	bool isOneShot = (intervalSeconds == 0);
	auto *timer = new TimerEvent(isOneShot, std::move(timerObj), handler);
	long timerId = m_timerQueue.schedule(timer, timer, future, interval);

	LOG_DBG << fname << from << " registered timer ID <" << timerId << ">, delay <" << (delayMilliseconds / 1000) << ">s interval <" << intervalSeconds << ">s";

	if (timerId < 0)
	{
		timer->handle_close(ACE_INVALID_HANDLE, ACE_Event_Handler::TIMER_MASK); // Self-destruct
		LOG_ERR << fname << from << " failed to register timer: " << last_error_msg();
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
	const int canceled = m_timerQueue.cancel(timerId, (const void **)&timer);
	LOG_DBG << fname << "timer ID <" << timerId << "> cancel result <" << canceled << ">";

	if (canceled > 0 && timer)
	{
		// Call handle_close() on successful cancellation
		// ACE_Thread_Timer_Queue_Adapter::cancel() does not pass proper dont_call_handle_close
		timer->handle_close(ACE_INVALID_HANDLE, ACE_Event_Handler::TIMER_MASK);
		CLEAR_TIMER_ID(timerId);
		return true;
	}

	LOG_ERR << fname << "failed to cancel timer ID <" << timerId << ">";
	return false;
}

////////////////////////////////////////////////////////////////
/// TimerHandler
////////////////////////////////////////////////////////////////

long TimerHandler::registerTimer(long delayMilliseconds, std::size_t intervalSeconds, const TimerCallback &handler, const std::string from)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMilliseconds, intervalSeconds, from, shared_from_this(), handler);
}

bool TimerHandler::cancelTimer(std::atomic_long &timerId)
{
	long thisId = timerId.exchange(INVALID_TIMER_ID);
	return IS_VALID_TIMER_ID(thisId) && TIMER_MANAGER::instance()->cancelTimer(thisId);
}
