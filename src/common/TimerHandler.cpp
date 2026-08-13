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
	reference_counting_policy().value(ACE_Event_Handler::Reference_Counting_Policy::ENABLED);
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

	bool shouldContinue = false;
	try
	{
		if (!m_handler)
		{
			LOG_ERR << fname << "timer <" << this << "> has no valid handler";
			return -1; // Stop timer - will call handle_close()
		}

		shouldContinue = m_handler();
	}
	catch (const std::exception &ex)
	{
		LOG_ERR << fname << "timer callback threw exception: " << ex.what();
		return -1;
	}
	catch (...)
	{
		LOG_ERR << fname << "timer callback threw unknown exception";
		return -1;
	}

	if (m_isOneShot)
		return 0; // ACE releases a completed one-shot timer after this upcall.
	if (!shouldContinue)
		return -1; // Stop timer - will call handle_close()
	return 0;	   // Continue till next interval
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

long TimerManager::registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, std::string from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
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
	ACE_Time_Value interval(intervalMilliseconds / 1000, (intervalMilliseconds % 1000) * 1000);

	// The queue and each active upcall retain their own ACE references.
	bool isOneShot = (intervalMilliseconds == 0);
	auto *timer = new TimerEvent(isOneShot, std::move(timerObj), handler);
	long timerId = m_timerQueue.schedule(timer, timer, future, interval);
	timer->remove_reference(); // Release the creator reference.

	LOG_DBG << fname << from << " registered timer ID <" << timerId << ">, delay <" << delayMilliseconds << ">ms interval <" << intervalMilliseconds << ">ms";

	if (timerId < 0)
	{
		LOG_ERR << fname << from << " failed to register timer: " << last_error_msg();
	}

	return timerId;
}

long TimerManager::registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, std::string from, const TimerCallback &handler)
{
	return this->registerTimer(delayMilliseconds, intervalMilliseconds, std::move(from), nullptr, handler);
}

bool TimerManager::cancelTimer(long timerId)
{
	const static char fname[] = "TimerManager::cancelTimer() ";

	if (!isValidTimerId(timerId))
	{
		return false;
	}

	const int canceled = m_timerQueue.cancel(timerId);
	LOG_DBG << fname << "timer ID <" << timerId << "> cancel result <" << canceled << ">";

	if (canceled > 0)
	{
		return true;
	}

	LOG_WAR << fname << "failed to cancel timer ID <" << timerId << ">, timer may have already expired";
	return false;
}

bool TimerManager::cancelTimer(std::atomic_long &timerId)
{
	long thisId = timerId.exchange(INVALID_TIMER_ID);
	return isValidTimerId(thisId) && cancelTimer(thisId);
}

////////////////////////////////////////////////////////////////
/// TimerHandler
////////////////////////////////////////////////////////////////

long TimerHandler::registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, const std::string from, const TimerCallback &handler)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMilliseconds, intervalMilliseconds, from, shared_from_this(), handler);
}

bool TimerHandler::cancelTimer(std::atomic_long &timerId)
{
	return TIMER_MANAGER::instance()->cancelTimer(timerId);
}
