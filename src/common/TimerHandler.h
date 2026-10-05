// src/common/TimerHandler.h
#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

/**
 * @brief Timer callback function type.
 * @return true to continue recurring timer, false to stop. Ignored for one-shot timers.
 */
using TimerCallback = std::function<bool(void)>;

constexpr long INVALID_TIMER_ID = -1L;

constexpr bool isValidTimerId(long timerId) noexcept
{
	return timerId != INVALID_TIMER_ID;
}

inline bool isValidTimerId(const std::atomic_long &timerId) noexcept
{
	return isValidTimerId(timerId.load(std::memory_order_acquire));
}

/**
 * @class TimerHandler
 * @brief Base class for objects requiring timer functionality.
 *
 * Uses std::enable_shared_from_this to prevent premature destruction while timers are active.
 * For lambda-only timers without an object, use TIMER_MANAGER directly.
 *
 * @note Does not support stack allocation due to enable_shared_from_this.
 */
class TimerHandler : public std::enable_shared_from_this<TimerHandler>
{
public:
	virtual ~TimerHandler() = default;

	/**
	 * @brief Registers a timer bound to this object.
	 *
	 * @param delayMilliseconds Initial delay in milliseconds.
	 * @param intervalMilliseconds Interval in milliseconds. 0 for one-shot timer.
	 * @param from Source identifier for logging.
	 * @param handler Callback invoked on expiration.
	 * @return Stable timer token (never reused), or INVALID_TIMER_ID on failure.
	 */
	long registerTimer(std::size_t delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, const TimerCallback &handler);

	/**
	 * @brief Registers a timer and publishes its token into the slot before the timer can fire.
	 *
	 * An existing timer in the same slot is canceled before the replacement is
	 * published. The slot must outlive the timer (member of the bound object or
	 * shared callback state).
	 */
	long registerTimer(std::atomic_long &timerId, std::size_t delayMilliseconds, std::size_t intervalMilliseconds,
					   const std::string &from, const TimerCallback &handler);

	/**
	 * @brief Cancels a timer.
	 *
	 * @param timerId Timer token (atomically reset to INVALID_TIMER_ID).
	 * @return true if the timer was still active. Cancellation takes effect on the
	 *         io thread asynchronously; a callback already dispatching runs to completion.
	 * @note Canceling the currently executing timer from its own callback is safe.
	 */
	bool cancelTimer(std::atomic_long &timerId);

protected:
	TimerHandler() = default;

private:
	// Prevent copying and assignment
	TimerHandler(const TimerHandler &) = delete;
	TimerHandler &operator=(const TimerHandler &) = delete;
};

class TimerState; // Internal per-timer state, defined in TimerHandler.cpp.

/**
 * @class TimerManager
 * @brief Singleton for managing all timer events.
 *
 * A dedicated thread runs a boost::asio::io_context of steady_timer instances
 * (monotonic clock). Callbacks execute on that thread without any lock held.
 */
class TimerManager
{
public:
	TimerManager();
	~TimerManager();

	/**
	 * @brief Registers a timer with optional TimerHandler binding.
	 *
	 * @param delayMilliseconds Initial delay in milliseconds.
	 * @param intervalMilliseconds Interval in milliseconds. 0 for one-shot.
	 * @param from Source identifier for logging.
	 * @param timerObj Optional shared_ptr to TimerHandler (nullptr for lambda-only), kept alive until the timer stops.
	 * @param handler Callback invoked on expiration.
	 * @return Stable timer token, or INVALID_TIMER_ID on failure (logged at CRITICAL here).
	 */
	long registerTimer(std::size_t delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);

	/// @brief Atomic-slot overload: cancels any timer already published in the slot before registering the replacement.
	long registerTimer(std::atomic_long &timerId, std::size_t delayMilliseconds, std::size_t intervalMilliseconds,
					   const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);

	/// @brief Convenience overload for lambda-only timers.
	long registerTimer(std::size_t delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, const TimerCallback &handler);

	/// @brief Cancels a logical timer token. Cancellation takes effect on the io thread asynchronously.
	bool cancelTimer(long timerToken);

	/// @brief Cancels timer (thread-safe); safe from the timer's own callback.
	bool cancelTimer(std::atomic_long &timerId);

private:
	friend class TimerState;

	// Prevent copying and assignment
	TimerManager(const TimerManager &) = delete;
	TimerManager &operator=(const TimerManager &) = delete;

	long registerTimerImpl(std::atomic_long *ownerTimerId, std::size_t delayMilliseconds, std::size_t intervalMilliseconds,
						   const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);
	long allocateTimerToken() noexcept;
	void releaseTimerToken(long timerToken) noexcept;

	boost::asio::io_context m_ioContext;												  ///< Timer event loop. All steady_timer member calls happen on m_ioThread.
	boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_workGuard; ///< Keeps the event loop alive until shutdown.
	std::thread m_ioThread;																  ///< Dedicated timer-dispatch thread.
	std::mutex m_timerIdMutex;															  ///< Serializes retained-token publication and cancellation.
	std::mutex m_timerRegistryMutex;													  ///< Protects only token ownership; released before posting to the event loop.
	std::map<long, std::shared_ptr<TimerState>> m_timerRegistry;						  ///< Stable token to exact timer identity.
	long m_nextTimerToken{1};
};

/// @brief Process-wide TimerManager singleton (thread-safe function-local static).
struct TIMER_MANAGER
{
	static TimerManager *instance()
	{
		static TimerManager manager;
		return &manager;
	}
};
