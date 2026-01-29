// src/common/TimerHandler.cpp
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
	LOG_DBG << fname << "timer <" << this << "> oneShot <" << m_isOneShot << "> hasObject <" << (m_timerObj != nullptr) << ">";
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

	// Validate handler
	if (!m_handler)
	{
		LOG_ERR << fname << "timer <" << this << "> has no valid handler";
		return -1; // Stop timer - will call handle_close()
	}

	// Execute callback with exception safety
	bool shouldContinue = false;
	try
	{
		shouldContinue = m_handler();
	}
	catch (const std::exception &ex)
	{
		LOG_ERR << fname << "timer <" << this << "> callback threw exception: " << ex.what();
		return -1; // Stop timer on exception
	}
	catch (...)
	{
		LOG_ERR << fname << "timer <" << this << "> callback threw unknown exception";
		return -1; // Stop timer on exception
	}

	// Stop if one-shot or handler returned false
	if (m_isOneShot || !shouldContinue)
	{
		LOG_DBG << fname << "timer <" << this << "> removed due to " << (m_isOneShot ? "one-shot" : "callback returned false");
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

	// Validate handler
	if (!handler)
	{
		LOG_ERR << fname << from << " failed to register timer: handler is null";
		return INVALID_TIMER_ID;
	}

	// Calculate future time for first trigger
	ACE_Time_Value future = (delayMilliseconds == 0) ? ACE_Time_Value::zero : ACE_OS::gettimeofday() + ACE_Time_Value(delayMilliseconds / 1000, (delayMilliseconds % 1000) * 1000);
	ACE_Time_Value interval(intervalSeconds);

	// TimerEvent passed as both handler and 'magic cookie' act; released in handle_close()
	bool isOneShot = (intervalSeconds == 0);
	auto *timer = new TimerEvent(isOneShot, std::move(timerObj), handler);
	long timerId = m_timerQueue.schedule(timer, timer, future, interval);

	LOG_DBG << fname << from << " registered timer ID <" << timerId << ">, delay <" << delayMilliseconds << ">ms interval <" << intervalSeconds << ">s";

	if (timerId < 0)
	{
		timer->handle_close(ACE_INVALID_HANDLE, ACE_Event_Handler::TIMER_MASK); // Self-destruct
		LOG_ERR << fname << from << " failed to register timer: " << last_error_msg();
	}

	return timerId;
}

long TimerManager::registerTimer(long delayMilliseconds, std::size_t intervalSeconds, std::string from, const TimerCallback &handler)
{
	return registerTimer(delayMilliseconds, intervalSeconds, std::move(from), nullptr, handler);
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

	if (canceled > 0)
	{
		// Call handle_close() on successful cancellation
		// ACE_Thread_Timer_Queue_Adapter::cancel() does not pass proper dont_call_handle_close
		if (timer)
		{
			timer->handle_close(ACE_INVALID_HANDLE, ACE_Event_Handler::TIMER_MASK);
		}
		else
		{
			LOG_ERR << fname << "timer ID <" << timerId << "> missing TimerEvent instance";
		}
		CLEAR_TIMER_ID(timerId);
		return true;
	}

	LOG_ERR << fname << "failed to cancel timer ID <" << timerId << ">";
	return false;
}

bool TimerManager::cancelTimer(std::atomic_long &timerId)
{
	long thisId = timerId.exchange(INVALID_TIMER_ID);
	return IS_VALID_TIMER_ID(thisId) && cancelTimer(thisId);
}

////////////////////////////////////////////////////////////////
/// TimerHandler
////////////////////////////////////////////////////////////////

long TimerHandler::registerTimer(long delayMilliseconds, std::size_t intervalSeconds, const std::string from, const TimerCallback &handler)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMilliseconds, intervalSeconds, from, shared_from_this(), handler);
}

bool TimerHandler::cancelTimer(std::atomic_long &timerId)
{
	return TIMER_MANAGER::instance()->cancelTimer(timerId);
}

////////////////////////////////////////////////////////////////
/// Standalone Functions
////////////////////////////////////////////////////////////////

long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, const std::string &from, const TimerCallback &handler)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMilliseconds, intervalSeconds, from, nullptr, handler);
}

bool cancelTimer(std::atomic_long &timerId)
{
	return TIMER_MANAGER::instance()->cancelTimer(timerId);
}
