// src/common/TimerHandler.h
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include <ace/Event_Handler.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/Singleton.h>
#include <ace/Task.h>
#include <ace/Timer_Heap.h>
#include <ace/Timer_Queue_Adapters.h>

/**
 * @brief Timer callback function type.
 * @return true to continue recurring timer, false to stop. Ignored for one-shot timers.
 */
using TimerCallback = std::function<bool(void)>;

constexpr long INVALID_TIMER_ID = -1L;
#define IS_VALID_TIMER_ID(id) ((id) != INVALID_TIMER_ID)
#define CLEAR_TIMER_ID(id) ((id) = INVALID_TIMER_ID)

/**
 * @class TimerHandler
 * @brief Base class for objects requiring timer functionality.
 *
 * Uses std::enable_shared_from_this to prevent premature destruction while timers are active.
 * For lambda-only timers without an object, use standalone registerTimer()/cancelTimer().
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
	 * @param intervalSeconds Interval in seconds. 0 for one-shot timer.
	 * @param from Source identifier for logging.
	 * @param handler Callback invoked on expiration.
	 * @return Timer ID, or INVALID_TIMER_ID on failure.
	 *         Store the return value in std::atomic_long for thread-safe access and later timer cancellation.
	 *
	 * @note Timer IDs will be reused to maintain a compact range. Ensure to reset your timer ID variable
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, const std::string from, const TimerCallback &handler);

	/**
	 * @brief Cancels a timer.
	 *
	 * @param timerId Timer ID (atomically reset to INVALID_TIMER_ID).
	 * @return true if canceled successfully.
	 *
	 * @warning Do not call from within TimerCallback.
	 */
	bool cancelTimer(std::atomic_long &timerId);

protected:
	TimerHandler() = default;

private:
	// Prevent copying and assignment
	TimerHandler(const TimerHandler &) = delete;
	TimerHandler &operator=(const TimerHandler &) = delete;
};

/**
 * @class TimerEvent
 * @brief Internal ACE event handler for timer expiration.
 */
class TimerEvent final : public ACE_Event_Handler
{
public:
	explicit TimerEvent(bool isOneShot, std::shared_ptr<TimerHandler> timerObj, TimerCallback handler) noexcept;

	/**
	 * @brief Callback function invoked when the timer expires.
	 *
	 * @param current_time The time at which the timer expired.
	 * @param act The 'magic cookie' argument passed in when the timer was registered.
	 * @return int 0 on success (continue recurring timer), or -1 to stop the timer.
	 */
	int handle_timeout(const ACE_Time_Value &current_time, const void *act = nullptr) override;

	/**
	 * @brief Called when a handle_*() method returns -1 or when remove_handler() is called on an ACE_Reactor.
	 *
	 * This method performs cleanup by deleting the TimerEvent instance.
	 *
	 * @param handle The ACE handle associated with the event.
	 * @param close_mask Indicates which event triggered the handle_close callback.
	 * @return int 0 on success.
	 */
	int handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask) override;

private:
	const std::shared_ptr<TimerHandler> m_timerObj; ///< Holds the target TimerHandler instance to prevent premature deallocation (can be nullptr).
	const TimerCallback m_handler;					///< The callback function to be invoked on timer expiration.
	const bool m_isOneShot;							///< Indicates if the timer should be triggered only once.
};

/**
 * @class TimerManager
 * @brief Singleton for managing all timer events.
 */
class TimerManager : public ACE_Task_Base
{
public:
	TimerManager();
	virtual ~TimerManager() override;

	/**
	 * @brief Registers a timer with optional TimerHandler binding.
	 *
	 * @param delayMilliseconds Initial delay in milliseconds.
	 * @param intervalSeconds Interval in seconds. 0 for one-shot.
	 * @param from Source identifier for logging.
	 * @param timerObj Optional shared_ptr to TimerHandler (nullptr for lambda-only), kept alive until the timer stops.
	 * @param handler Callback invoked on expiration.
	 * @return Timer ID, or INVALID_TIMER_ID on failure.
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, std::string from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);

	/// @brief Convenience overload for lambda-only timers.
	long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, std::string from, const TimerCallback &handler);

	/// @brief Cancels timer (non-thread-safe).
	bool cancelTimer(long &timerId);

	/**
	 * @brief Cancels timer (thread-safe).
	 * @warning Do not call from within TimerCallback.
	 */
	bool cancelTimer(std::atomic_long &timerId);

private:
	using Upcall = ACE_Event_Handler_Handle_Timeout_Upcall;
	using Timer_Heap = ACE_Timer_Heap_T<ACE_Event_Handler *, Upcall, ACE_Recursive_Thread_Mutex>;
	using Thread_Timer_Queue = ACE_Thread_Timer_Queue_Adapter<Timer_Heap>;

	Thread_Timer_Queue m_timerQueue; ///< Queue for managing active timers.
};

using TIMER_MANAGER = ACE_Singleton<TimerManager, ACE_Null_Mutex>;

/**
 * @brief Standalone timer registration for lambda-only timers.
 *
 * @param delayMilliseconds Initial delay in milliseconds.
 * @param intervalSeconds Interval in seconds. 0 for one-shot.
 * @param from Source identifier for logging.
 * @param handler Callback invoked on expiration.
 * @return Timer ID, or INVALID_TIMER_ID on failure.
 *
 * @example
 *   std::atomic_long timerId{INVALID_TIMER_ID};
 *   timerId = registerTimer(1000, 5, "my_lambda_timer", []() {
 *       std::cout << "Timer fired!" << std::endl;
 *       return true; // Continue timer
 *   });
 *   cancelTimer(timerId);
 */
long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, const std::string &from, const TimerCallback &handler);

/**
 * @brief Standalone timer cancellation.
 * @param timerId Timer ID (atomically reset to INVALID_TIMER_ID).
 * @return true if canceled successfully.
 * @warning Do not call from within TimerCallback.
 */
bool cancelTimer(std::atomic_long &timerId);
