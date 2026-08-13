// src/common/TimerHandler.h
#pragma once

#include <atomic>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <ace/Event_Handler.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/Singleton.h>
#include <ace/Timer_Heap.h>
#include <ace/Timer_Queue_Adapters.h>

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
	 * @return Stable timer token, or INVALID_TIMER_ID on failure.
	 *
	 * @note The returned ID is a TimerManager token, not ACE's reusable heap index.
	 *       Use the atomic-ID overload whenever an ID is retained.
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, const TimerCallback &handler);

	/**
	 * @brief Registers a timer and publishes its token before the timer can fire.
	 *
	 * Use this overload when the ID is retained for cancellation. An existing
	 * timer in the same slot is canceled before the replacement is published;
	 * registration and cancellation are serialized by TimerManager.
	 * The slot must be a member of the bound object or shared callback state so
	 * it remains alive until the TimerEvent releases it.
	 */
	long registerTimer(std::atomic_long &timerId, long delayMilliseconds, std::size_t intervalMilliseconds,
					   const std::string &from, const TimerCallback &handler);

	/**
	 * @brief Cancels a timer.
	 *
	 * @param timerId Timer token (atomically reset to INVALID_TIMER_ID).
	 * @return true if canceled successfully.
	 *
	 * @warning Do not cancel the currently executing timer from its own callback.
	 */
	bool cancelTimer(std::atomic_long &timerId);

protected:
	TimerHandler() = default;

private:
	// Prevent copying and assignment
	TimerHandler(const TimerHandler &) = delete;
	TimerHandler &operator=(const TimerHandler &) = delete;
};

class TimerManager;

/**
 * @class TimerEvent
 * @brief Internal ACE event handler for timer expiration.
 */
class TimerEvent final : public ACE_Event_Handler
{
public:
	explicit TimerEvent(TimerManager &manager, bool isOneShot, std::atomic_long *ownerTimerId,
						std::shared_ptr<TimerHandler> timerObj, TimerCallback handler);
	~TimerEvent() override;

	/// @brief Binds the stable TimerManager token before the queue can dispatch this event.
	void bindTimerToken(long timerToken) noexcept;

	/**
	 * @brief Callback function invoked when the timer expires.
	 *
	 * @param current_time The time at which the timer expired.
	 * @param act The 'magic cookie' argument passed in when the timer was registered.
	 * @return int 0 on success (continue recurring timer), or -1 to stop the timer.
	 */
	int handle_timeout(const ACE_Time_Value &current_time, const void *act = nullptr) override;

private:
	void releaseTimerToken() noexcept;

	TimerManager &m_manager;						///< Owns the token registry for this event.
	const std::shared_ptr<TimerHandler> m_timerObj; ///< Holds the target TimerHandler instance to prevent premature deallocation (can be nullptr).
	const TimerCallback m_handler;					///< The callback function to be invoked on timer expiration.
	std::atomic_long *const m_ownerTimerId;			///< Optional retained ID slot; kept alive by m_timerObj or m_handler.
	long m_timerToken{INVALID_TIMER_ID};			///< Immutable after bindTimerToken and before dispatch.
	const bool m_isOneShot;							///< Indicates if the timer should be triggered only once.
};

/**
 * @class TimerManager
 * @brief Singleton for managing all timer events.
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
	 * @return Stable timer token, or INVALID_TIMER_ID on failure.
	 * @note Registration failures are logged here at CRITICAL level and return
	 *       INVALID_TIMER_ID; callers do not need to duplicate the failure log.
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);

	/// @brief Convenience overload for lambda-only timers.
	long registerTimer(long delayMilliseconds, std::size_t intervalMilliseconds, const std::string &from, const TimerCallback &handler);

	/// @brief Cancels a logical timer token already detached from its owner.
	bool cancelTimer(long timerToken);

	/**
	 * @brief Cancels timer (thread-safe).
	 * @warning Do not cancel the currently executing timer from its own callback.
	 */
	bool cancelTimer(std::atomic_long &timerId);

private:
	friend class TimerEvent;
	friend class TimerHandler;

	using Upcall = ACE_Event_Handler_Handle_Timeout_Upcall;
	using Timer_Heap = ACE_Timer_Heap_T<ACE_Event_Handler *, Upcall, ACE_Recursive_Thread_Mutex>;
	using Thread_Timer_Queue = ACE_Thread_Timer_Queue_Adapter<Timer_Heap>;

	long registerTimer(std::atomic_long &timerId, long delayMilliseconds, std::size_t intervalMilliseconds,
					   const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);
	long registerTimerImpl(std::atomic_long *timerId, long delayMilliseconds, std::size_t intervalMilliseconds,
						   const std::string &from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);
	long allocateTimerToken() noexcept;
	void releaseTimerToken(long timerToken, const TimerEvent *timer) noexcept;

	std::mutex m_timerIdMutex;							   ///< Serializes retained-token publication and cancellation.
	std::mutex m_timerRegistryMutex;					   ///< Protects only token ownership; released before adapter operations/callbacks.
	std::map<long, ACE_Event_Handler_var> m_timerRegistry; ///< Stable token to exact event identity.
	long m_nextTimerToken{1};
	Thread_Timer_Queue m_timerQueue; ///< Queue for managing active timers. Destroyed before the registry locks.
};

using TIMER_MANAGER = ACE_Singleton<TimerManager, ACE_Null_Mutex>;
