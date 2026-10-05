// src/common/TimerHandler.cpp
#include <chrono>
#include <limits>
#include <stdexcept>

#include <boost/asio/error.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/steady_timer.hpp>

#include "../common/Utility.h"
#include "TimerHandler.h"

////////////////////////////////////////////////////////////////
/// TimerState
////////////////////////////////////////////////////////////////
/**
 * @class TimerState
 * @brief Internal per-timer state, owned by shared_ptr.
 *
 * steady_timer member calls happen only on the TimerManager io thread; arming
 * and cancellation are posted to the event loop.
 */
class TimerState : public std::enable_shared_from_this<TimerState>
{
public:
	TimerState(TimerManager &manager, long timerToken, std::size_t intervalMilliseconds,
			   std::atomic_long *ownerTimerId, std::shared_ptr<TimerHandler> timerObj, TimerCallback handler)
		: m_manager(manager), m_timer(manager.m_ioContext), m_timerObj(std::move(timerObj)), m_handler(std::move(handler)),
		  m_ownerTimerId(ownerTimerId), m_timerToken(timerToken), m_intervalMilliseconds(intervalMilliseconds)
	{
		const static char fname[] = "TimerState::TimerState() ";
		LOG_DBG << fname << "timer <" << this << "> oneShot <" << isOneShot() << "> hasObject <" << (m_timerObj != nullptr) << ">";
	}

	~TimerState()
	{
		releaseTimerToken();
	}

	bool isOneShot() const { return m_intervalMilliseconds == 0; }

	/// @brief (Re-)arms the wait. Runs on the TimerManager io thread.
	void arm(std::size_t delayMilliseconds)
	{
		m_timer.expires_after(std::chrono::milliseconds(delayMilliseconds));
		asyncWait();
	}

	/// @brief Cancels the pending wait. Runs on the TimerManager io thread.
	void cancel()
	{
		const static char fname[] = "TimerState::cancel() ";
		try
		{
			m_timer.cancel();
		}
		catch (const std::exception &ex)
		{
			LOG_ERR << fname << "timer <" << this << "> cancel failed: " << ex.what();
		}
	}

	void releaseTimerToken() noexcept
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
		m_manager.releaseTimerToken(timerToken);
	}

private:
	void asyncWait()
	{
		std::shared_ptr<TimerState> self = shared_from_this();
		m_timer.async_wait([self](const boost::system::error_code &ec) { self->onFired(ec); });
	}

	void onFired(const boost::system::error_code &ec)
	{
		const static char fname[] = "TimerState::onFired() ";
		if (ec)
		{
			if (ec != boost::asio::error::operation_aborted)
				LOG_ERR << fname << "timer <" << this << "> wait failed: " << ec.message();
			releaseTimerToken();
			return;
		}

		bool keepGoing = false;
		try
		{
			// A one-shot releases its token before the callback runs, so the slot
			// is already reset while the callback executes.
			if (isOneShot())
				releaseTimerToken();
			keepGoing = m_handler() && !isOneShot();
		}
		catch (const std::exception &ex)
		{
			LOG_ERR << fname << "timer callback threw exception: " << ex.what();
		}
		catch (...)
		{
			LOG_ERR << fname << "timer callback threw unknown exception";
		}

		if (!keepGoing)
		{
			releaseTimerToken(); // No-op for a one-shot that already released above.
			return;
		}

		// Recurring timers re-arm after the callback completes, so the interval
		// absorbs the callback duration.
		arm(m_intervalMilliseconds);
	}

	TimerManager &m_manager;						///< Owns the token registry and event loop for this timer.
	boost::asio::steady_timer m_timer;				///< Monotonic timer; member calls happen only on the io thread.
	const std::shared_ptr<TimerHandler> m_timerObj; ///< Holds the target TimerHandler instance to prevent premature deallocation (can be nullptr).
	const TimerCallback m_handler;					///< The callback function to be invoked on timer expiration.
	std::atomic_long *const m_ownerTimerId;			///< Optional retained ID slot; kept alive by m_timerObj or m_handler.
	long m_timerToken;								///< Stable TimerManager token; mutated only on the io thread or before publication.
	const std::size_t m_intervalMilliseconds;		///< Recurring interval in milliseconds; 0 for one-shot.
};

////////////////////////////////////////////////////////////////
/// TimerManager
////////////////////////////////////////////////////////////////
TimerManager::TimerManager()
	: m_workGuard(boost::asio::make_work_guard(m_ioContext))
{
	const static char fname[] = "TimerManager::TimerManager() ";
	LOG_DBG << fname;
	// Dedicated timer-dispatch thread, independent of the daemon reactors.
	try
	{
		m_ioThread = std::thread([this]() { m_ioContext.run(); });
	}
	catch (const std::exception &ex)
	{
		LOG_CRT << fname << "FATAL: failed to start the timer-dispatch thread: " << ex.what();
		throw std::runtime_error("failed to start timer-dispatch thread");
	}
}

TimerManager::~TimerManager()
{
	const static char fname[] = "TimerManager::~TimerManager() ";
	LOG_DBG << fname;
	m_workGuard.reset();
	m_ioContext.stop();
	if (m_ioThread.joinable())
		m_ioThread.join();
	std::map<long, std::shared_ptr<TimerState>> remainingTimers;
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
	// Public tokens are never reused.
	m_nextTimerToken = (m_nextTimerToken == std::numeric_limits<long>::max())
						   ? INVALID_TIMER_ID
						   : m_nextTimerToken + 1;
	return timerToken;
}

void TimerManager::releaseTimerToken(long timerToken) noexcept
{
	if (!isValidTimerId(timerToken))
		return;

	// Tokens are never reused, so a hit always names the releasing timer itself.
	std::lock_guard<std::mutex> registryGuard(m_timerRegistryMutex);
	m_timerRegistry.erase(timerToken);
}

long TimerManager::registerTimer(std::size_t delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
{
	return registerTimerImpl(nullptr, delayMilliseconds, intervalMilliseconds, from, std::move(timerObj), handler);
}

long TimerManager::registerTimer(std::atomic_long &timerId, std::size_t delayMilliseconds, std::size_t intervalMilliseconds,
								 const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
{
	std::lock_guard<std::mutex> idGuard(m_timerIdMutex);
	const long previousId = timerId.exchange(INVALID_TIMER_ID, std::memory_order_acq_rel);
	if (isValidTimerId(previousId))
		cancelTimer(previousId);
	return registerTimerImpl(&timerId, delayMilliseconds, intervalMilliseconds, from, std::move(timerObj), handler);
}

long TimerManager::registerTimerImpl(std::atomic_long *ownerTimerId, std::size_t delayMilliseconds, std::size_t intervalMilliseconds,
									 const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler)
{
	const static char fname[] = "TimerManager::registerTimer() ";

	if (!handler)
	{
		LOG_CRT << fname << from << " failed to register timer: handler is null";
		return INVALID_TIMER_ID;
	}
	if (m_ioContext.stopped())
	{
		LOG_CRT << fname << from << " failed to register timer: timer manager is stopped";
		return INVALID_TIMER_ID;
	}

	const long timerToken = allocateTimerToken();
	if (!isValidTimerId(timerToken))
	{
		LOG_CRT << fname << from << " failed to register timer: logical token space exhausted";
		return INVALID_TIMER_ID;
	}

	std::shared_ptr<TimerState> timer;
	try
	{
		timer = std::make_shared<TimerState>(*this, timerToken, intervalMilliseconds, ownerTimerId, std::move(timerObj), handler);
		{
			std::lock_guard<std::mutex> registryGuard(m_timerRegistryMutex);
			m_timerRegistry[timerToken] = timer;
		}
		// Publish the slot before the io thread can arm and fire the timer, so a
		// zero-delay callback can never clear its token before publication.
		if (ownerTimerId != nullptr)
			ownerTimerId->store(timerToken, std::memory_order_release);
		boost::asio::post(m_ioContext, [timer, delayMilliseconds]() { timer->arm(delayMilliseconds); });
		return timerToken;
	}
	catch (const std::exception &ex)
	{
		if (timer)
			timer->releaseTimerToken();
		LOG_CRT << fname << from << " failed to register timer: " << ex.what();
	}
	catch (...)
	{
		if (timer)
			timer->releaseTimerToken();
		LOG_CRT << fname << from << " failed to register timer with unknown error";
	}
	return INVALID_TIMER_ID;
}

long TimerManager::registerTimer(std::size_t delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, const TimerCallback &handler)
{
	return this->registerTimer(delayMilliseconds, intervalMilliseconds, from, nullptr, handler);
}

bool TimerManager::cancelTimer(long timerToken)
{
	const static char fname[] = "TimerManager::cancelTimer() ";

	if (!isValidTimerId(timerToken))
		return false;

	std::shared_ptr<TimerState> timer;
	{
		std::lock_guard<std::mutex> registryGuard(m_timerRegistryMutex);
		const auto registered = m_timerRegistry.find(timerToken);
		if (registered == m_timerRegistry.end())
		{
			LOG_DBG << fname << "timer token <" << timerToken << "> already released";
			return false;
		}
		timer = registered->second; // Pins the exact timer until the cancel runs on the io thread.
		m_timerRegistry.erase(registered);
	}

	// Cancel by timer identity on the io thread (posting into a stopped event
	// loop is a no-op). A callback already dispatched runs to completion; a
	// recurring timer canceled mid-dispatch stops when its re-arm is canceled.
	boost::asio::post(m_ioContext, [timer]() { timer->cancel(); });
	LOG_DBG << fname << "timer token <" << timerToken << "> canceled";
	return true;
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

long TimerHandler::registerTimer(std::size_t delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, const TimerCallback &handler)
{
	return TIMER_MANAGER::instance()->registerTimer(delayMilliseconds, intervalMilliseconds, from, shared_from_this(), handler);
}

long TimerHandler::registerTimer(std::atomic_long &timerId, std::size_t delayMilliseconds, std::size_t intervalMilliseconds,
								 const std::string &from, const TimerCallback &handler)
{
	return TIMER_MANAGER::instance()->registerTimer(timerId, delayMilliseconds, intervalMilliseconds, from, shared_from_this(), handler);
}

bool TimerHandler::cancelTimer(std::atomic_long &timerId)
{
	return TIMER_MANAGER::instance()->cancelTimer(timerId);
}
