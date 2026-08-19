// src/common/TimerHandler.cpp
#include <ace/Guard_T.h>
#include <ace/OS.h>
#include <ace/Time_Value.h>

#include <limits>
#include <stdexcept>

#include "../common/Utility.h"
#include "TimerHandler.h"

////////////////////////////////////////////////////////////////
/// TimerEvent
////////////////////////////////////////////////////////////////
TimerEvent::TimerEvent(
	TimerManager &manager, bool isOneShot, std::atomic_long *ownerTimerId,
	std::shared_ptr<TimerHandler> timerObj, TimerCallback handler)
	: m_manager(manager), m_timerObj(std::move(timerObj)), m_handler(std::move(handler)),
	  m_ownerTimerId(ownerTimerId), m_isOneShot(isOneShot)
{
	reference_counting_policy().value(ACE_Event_Handler::Reference_Counting_Policy::ENABLED);
	const static char fname[] = "TimerEvent::TimerEvent() ";
	LOG_DBG << fname << "timer <" << this << "> oneShot <" << m_isOneShot << "> hasObject <" << (m_timerObj != nullptr) << ">";
}

TimerEvent::~TimerEvent()
{
	releaseTimerToken();
}

void TimerEvent::bindTimerToken(long timerToken) noexcept
{
	m_timerToken = timerToken;
}

void TimerEvent::releaseTimerToken() noexcept
{
	const long timerToken = m_timerToken;
	m_timerToken = INVALID_TIMER_ID;
	if (!isValidTimerId(timerToken))
		return;

	if (m_ownerTimerId != nullptr)
	{
		// A replaced timer may finish after a new token was published in the same slot.
		// Clear only our own token so the old callback cannot erase the replacement.
		long expected = timerToken;
		m_ownerTimerId->compare_exchange_strong(expected, INVALID_TIMER_ID, std::memory_order_acq_rel, std::memory_order_acquire);
	}
	m_manager.releaseTimerToken(timerToken, this);
}

int TimerEvent::handle_timeout(const ACE_Time_Value &current_time, const void *act)
{
	const static char fname[] = "TimerEvent::handle_timeout() ";

	// Validate act 'magic cookie'
	if (act != static_cast<const void *>(this))
	{
		LOG_ERR << fname << "invalid timer triggered, act: <" << act << "> != this <" << this << ">";
		releaseTimerToken();
		return -1;
	}
	if (m_isOneShot)
		releaseTimerToken();

	bool shouldContinue = false;
	try
	{
		if (!m_handler)
		{
			LOG_ERR << fname << "timer <" << this << "> has no valid handler";
			releaseTimerToken();
			return -1; // Stop timer - will call handle_close()
		}

		shouldContinue = m_handler();
	}
	catch (const std::exception &ex)
	{
		LOG_ERR << fname << "timer callback threw exception: " << ex.what();
		releaseTimerToken();
		return -1;
	}
	catch (...)
	{
		LOG_ERR << fname << "timer callback threw unknown exception";
		releaseTimerToken();
		return -1;
	}

	if (m_isOneShot)
		return 0; // ACE releases a completed one-shot timer after this upcall.
	if (!shouldContinue)
	{
		releaseTimerToken();
		return -1; // Stop timer - will call handle_close()
	}
	return 0; // Continue till next interval
}

////////////////////////////////////////////////////////////////
/// TimerManager
////////////////////////////////////////////////////////////////
TimerManager::TimerManager()
	: m_timerQueue(ACE_Thread_Manager::instance())
{
	const static char fname[] = "TimerManager::TimerManager() ";
	LOG_DBG << fname;
	// The adapter owns the dedicated timer-dispatch thread. It is deliberately
	// independent of both daemon reactors; TimerManager itself is not an ACE task.
	if (m_timerQueue.activate() == -1)
	{
		LOG_CRT << fname << "FATAL: failed to start the timer-dispatch thread";
		throw std::runtime_error("failed to start timer-dispatch thread");
	}
}

TimerManager::~TimerManager()
{
	const static char fname[] = "TimerManager::~TimerManager() ";
	LOG_DBG << fname;
	m_timerQueue.deactivate();
	m_timerQueue.wait();
	std::map<long, ACE_Event_Handler_var> remainingTimers;
	{
		std::lock_guard<std::mutex> registryGuard(m_timerRegistryMutex);
		remainingTimers.swap(m_timerRegistry);
	}
	remainingTimers.clear();
}

long TimerManager::allocateTimerToken() noexcept
{
	std::lock_guard<std::mutex> registryGuard(m_timerRegistryMutex);
	if (!isValidTimerId(m_nextTimerToken))
		return INVALID_TIMER_ID;

	const long timerToken = m_nextTimerToken;
	// Never reuse a public token. ACE may recycle its heap ID as soon as a
	// one-shot is dequeued, so generation-safe cancellation cannot use that ID.
	m_nextTimerToken = (m_nextTimerToken == std::numeric_limits<long>::max())
						   ? INVALID_TIMER_ID
						   : m_nextTimerToken + 1;
	return timerToken;
}

void TimerManager::releaseTimerToken(long timerToken, const TimerEvent *timer) noexcept
{
	if (!isValidTimerId(timerToken))
		return;

	std::lock_guard<std::mutex> registryGuard(m_timerRegistryMutex);
	const auto registered = m_timerRegistry.find(timerToken);
	if (registered != m_timerRegistry.end() && registered->second.handler() == timer)
		m_timerRegistry.erase(registered);
}

long TimerManager::registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
{
	return registerTimerImpl(nullptr, delayMilliseconds, intervalMilliseconds, from, std::move(timerObj), handler);
}

long TimerManager::registerTimer(std::atomic_long &timerId, long delayMilliseconds, std::size_t intervalMilliseconds,
								 const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
{
	std::lock_guard<std::mutex> idGuard(m_timerIdMutex);
	const long previousId = timerId.exchange(INVALID_TIMER_ID, std::memory_order_acq_rel);
	if (isValidTimerId(previousId))
		cancelTimer(previousId);
	return registerTimerImpl(&timerId, delayMilliseconds, intervalMilliseconds, from, std::move(timerObj), handler);
}

long TimerManager::registerTimerImpl(std::atomic_long *ownerTimerId, long delayMilliseconds, std::size_t intervalMilliseconds,
									 const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
{
	const static char fname[] = "TimerManager::registerTimer() ";

	if (!handler)
	{
		LOG_CRT << fname << from << " failed to register timer: handler is null";
		return INVALID_TIMER_ID;
	}

	const long timerToken = allocateTimerToken();
	if (!isValidTimerId(timerToken))
	{
		LOG_CRT << fname << from << " failed to register timer: logical token space exhausted";
		return INVALID_TIMER_ID;
	}

	ACE_Event_Handler_var timer;
	try
	{
		ACE_Time_Value future = (delayMilliseconds == 0) ? ACE_Time_Value::zero : ACE_OS::gettimeofday() + ACE_Time_Value(delayMilliseconds / 1000, (delayMilliseconds % 1000) * 1000);
		ACE_Time_Value interval(intervalMilliseconds / 1000, (intervalMilliseconds % 1000) * 1000);
		const bool isOneShot = (intervalMilliseconds == 0);
		timer = ACE::make_event_handler<TimerEvent>(*this, isOneShot, ownerTimerId, std::move(timerObj), handler);
		{
			std::lock_guard<std::mutex> registryGuard(m_timerRegistryMutex);
			const auto inserted = m_timerRegistry.emplace(timerToken, timer);
			if (!inserted.second)
			{
				LOG_CRT << fname << from << " failed to register timer: duplicate logical token <" << timerToken << ">";
				return INVALID_TIMER_ID;
			}
		}

		// The adapter releases its mutex while Timer_Heap::expire() dispatches.
		// Hold both locks in the adapter's normal order so a zero-delay callback
		// cannot clear its logical token before that token has been published.
		{
			ACE_Guard<ACE_SYNCH_RECURSIVE_MUTEX> adapterGuard(m_timerQueue.mutex());
			ACE_Guard<ACE_Recursive_Thread_Mutex> heapGuard(m_timerQueue.timer_queue()->mutex());
			const long scheduledId = m_timerQueue.schedule(timer.handler(), timer.handler(), future, interval);
			if (isValidTimerId(scheduledId))
			{
				static_cast<TimerEvent *>(timer.handler())->bindTimerToken(timerToken);
				if (ownerTimerId != nullptr)
					ownerTimerId->store(timerToken, std::memory_order_release);
				return timerToken;
			}
		}
		releaseTimerToken(timerToken, static_cast<TimerEvent *>(timer.handler()));
		LOG_CRT << fname << from << " failed to register timer: " << last_error_msg();
	}
	catch (const std::exception &ex)
	{
		if (timer.handler() != nullptr)
			releaseTimerToken(timerToken, static_cast<TimerEvent *>(timer.handler()));
		LOG_CRT << fname << from << " failed to register timer: " << ex.what();
	}
	catch (...)
	{
		if (timer.handler() != nullptr)
			releaseTimerToken(timerToken, static_cast<TimerEvent *>(timer.handler()));
		LOG_CRT << fname << from << " failed to register timer with unknown error";
	}
	return INVALID_TIMER_ID;
}

long TimerManager::registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, const TimerCallback &handler)
{
	return this->registerTimer(delayMilliseconds, intervalMilliseconds, from, nullptr, handler);
}

bool TimerManager::cancelTimer(long timerToken)
{
	const static char fname[] = "TimerManager::cancelTimer() ";

	if (!isValidTimerId(timerToken))
		return false;

	ACE_Event_Handler_var timer;
	{
		std::lock_guard<std::mutex> registryGuard(m_timerRegistryMutex);
		const auto registered = m_timerRegistry.find(timerToken);
		if (registered == m_timerRegistry.end())
		{
			LOG_DBG << fname << "timer token <" << timerToken << "> already released";
			return false;
		}
		timer = registered->second; // Pins the exact event while it leaves the queue.
		m_timerRegistry.erase(registered);
	}

	int canceled = 0;
	{
		ACE_Guard<ACE_SYNCH_RECURSIVE_MUTEX> adapterGuard(m_timerQueue.mutex());
		// Cancel by event identity, not ACE's reusable numeric heap ID. This is
		// what prevents an expired timer from canceling a newer timer (ABA).
		canceled = m_timerQueue.timer_queue()->cancel(timer.handler());
		// Identity cancellation bypasses the adapter wrapper; wake its wait so it
		// recomputes the next deadline just as numeric adapter cancellation does.
		m_timerQueue.cancel(INVALID_TIMER_ID);
	}
	LOG_DBG << fname << "timer token <" << timerToken << "> cancel result <" << canceled << ">";

	if (canceled > 0)
		return true;

	LOG_WAR << fname << "failed to cancel timer token <" << timerToken << ">, timer may already be dispatching";
	return false;
}

bool TimerManager::cancelTimer(std::atomic_long &timerId)
{
	std::lock_guard<std::mutex> idGuard(m_timerIdMutex);
	long thisId = timerId.exchange(INVALID_TIMER_ID);
	return isValidTimerId(thisId) && cancelTimer(thisId);
}

////////////////////////////////////////////////////////////////
/// TimerHandler
////////////////////////////////////////////////////////////////

long TimerHandler::registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, const TimerCallback &handler)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMilliseconds, intervalMilliseconds, from, shared_from_this(), handler);
}

long TimerHandler::registerTimer(std::atomic_long &timerId, long delayMilliseconds, std::size_t intervalMilliseconds,
								 const std::string &from, const TimerCallback &handler)
{
	return TIMER_MANAGER::instance()->registerTimer(timerId, delayMilliseconds, intervalMilliseconds, from, shared_from_this(), handler);
}

bool TimerHandler::cancelTimer(std::atomic_long &timerId)
{
	return TIMER_MANAGER::instance()->cancelTimer(timerId);
}
