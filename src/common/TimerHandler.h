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
 * @brief Alias for timer callback function.
 *
 * The callback function returns a boolean value to indicate whether
 * the timer manager should continue or stop this timer.
 *
 * @return bool True to continue the timer, false to stop it.
 */
using TimerCallback = std::function<bool(void)>;

constexpr long INVALID_TIMER_ID = -1L;
#define IS_VALID_TIMER_ID(id) ((id) != INVALID_TIMER_ID)
#define CLEAR_TIMER_ID(id) ((id) = INVALID_TIMER_ID)

/**
 * @class TimerHandler
 * @brief Base class for user-defined classes implementing timer functionality.
 *
 * This class provides methods to register and cancel timers. It uses std::enable_shared_from_this
 * to allow the creation of shared pointers to 'this' object safely.
 *
 * For lambda-only timers without an associated object, use the standalone registerTimer()
 * and cancelTimer() functions instead.
 *
 * @note The use of enable_shared_from_this does not support stack allocation!
 */
class TimerHandler : public std::enable_shared_from_this<TimerHandler>
{
public:
	virtual ~TimerHandler() = default;

	/**
	 * @brief Registers a timer for this object.
	 *
	 * This method registers a timer that is bound to this TimerHandler instance.
	 * The TimerHandler object will be kept alive until the timer is canceled or stops.
	 *
	 * @param delayMilliseconds Initial delay before the timer starts, in milliseconds.
	 * @param intervalSeconds Interval between timer triggers, in seconds.
	 *                        Set to 0 for one-shot timer (triggers only once).
	 * @param handler Callback function to handle the timer event.
	 *                Return value for recurring timers (intervalSeconds > 0):
	 *                  - true: continue the timer for the next interval
	 *                  - false: stop the timer (will call handle_close())
	 *                Return value is ignored for one-shot timers (always stop after execution).
	 * @param from String indicating the source or context of the timer registration.
	 * @return long Unique timer ID, or negative value if registration failed.
	 *              Store the return value in std::atomic_long for thread-safe access and
	 *              later use in timer cancellation operations.
	 *
	 * @note Timer IDs will be reused to maintain a compact range. Ensure to reset your timer ID variable
	 *       (e.g., timerId.store(-1)) in the TimerCallback to prevent cancellation mismatches.
	 *
	 * @example
	 *   std::atomic_long timerId{-1};
	 *   timerId = this->registerTimer(1000, 5, [&](){ ... return true; }, "my_timer");
	 *   this->cancelTimer(timerId);
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, const TimerCallback &handler, const std::string from);

	/**
	 * @brief Cancels a timer.
	 *
	 * @param timerId Reference to the unique ID of the timer to cancel.
	 *                Will be reset to INVALID_TIMER_ID atomically.
	 * @return true if cancellation was successful, false otherwise.
	 *
	 * @warning Avoid calling this method within the timer callback (TimerCallback) to prevent unexpected behavior.
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
 * @brief Represents a timer event with an optional associated TimerHandler object.
 *
 * This class extends ACE_Event_Handler to handle timer events. Can be used with or without
 * a TimerHandler object, allowing lambda-only timer registration.
 */
class TimerEvent final : public ACE_Event_Handler
{
public:
	/**
	 * @brief Construct a new TimerEvent object.
	 *
	 * @param isOneShot Whether the timer should be triggered only once.
	 * @param timerObj Optional shared pointer to the associated TimerHandler object.
	 *                 Can be nullptr for lambda-only timers.
	 * @param handler Callback function to be invoked on timer expiration.
	 */
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
 * @brief Global singleton container class for managing timer events.
 *
 * This class extends ACE_Task_Base and manages the lifecycle of timer events.
 * It supports both object-bound timers (via TimerHandler) and lambda-only timers.
 */
class TimerManager : public ACE_Task_Base
{
public:
	/**
	 * @brief Construct a new TimerManager object.
	 */
	TimerManager();

	/**
	 * @brief Destroy the TimerManager object.
	 */
	~TimerManager() override;

	/**
	 * @brief Registers a timer with an optional TimerHandler object.
	 *
	 * This is the primary registration method that supports both object-bound and lambda-only timers.
	 *
	 * @param delayMilliseconds Initial delay before the timer starts, in milliseconds.
	 * @param intervalSeconds Interval between timer triggers, in seconds. 0 means the timer will trigger only once.
	 * @param from String indicating the source or context of the timer registration.
	 * @param timerObj Optional shared pointer to the TimerHandler. Can be nullptr for lambda-only timers.
	 *                 If provided, the TimerHandler will be kept alive until the timer stops.
	 * @param handler Callback function executed when the timer expires.
	 * @return long Unique timer ID for the registered timer, or negative value on failure.
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, std::string from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);

	/**
	 * @brief Registers a lambda-only timer without a TimerHandler object.
	 *
	 * This is a convenience overload for timers that don't need to be bound to an object.
	 *
	 * @param delayMilliseconds Initial delay before the timer starts, in milliseconds.
	 * @param intervalSeconds Interval between timer triggers, in seconds. 0 means the timer will trigger only once.
	 * @param from String indicating the source or context of the timer registration.
	 * @param handler Callback function executed when the timer expires.
	 * @return long Unique timer ID for the registered timer, or negative value on failure.
	 *
	 * @example
	 *   std::atomic_long timerId{INVALID_TIMER_ID};
	 *   timerId = TIMER_MANAGER::instance()->registerTimer(1000, 5, "my_lambda_timer",
	 *       []() { std::cout << "Timer fired!" << std::endl; return true; });
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, std::string from, const TimerCallback &handler);

	/**
	 * @brief Cancels a timer using its unique ID (non-atomic version).
	 *
	 * @param timerId Reference to the unique ID of the timer to be canceled.
	 *                Will be reset to INVALID_TIMER_ID on successful cancellation.
	 * @return true if cancellation was successful, false otherwise.
	 *
	 * @warning This method is not thread-safe. Use the atomic version for concurrent access.
	 */
	bool cancelTimer(long &timerId);

	/**
	 * @brief Cancels a timer using its unique ID (atomic version).
	 *
	 * This method atomically exchanges the timer ID with INVALID_TIMER_ID before
	 * attempting cancellation, ensuring thread-safe operation.
	 *
	 * @param timerId Atomic reference to the unique ID of the timer to be canceled.
	 *                Will be reset to INVALID_TIMER_ID atomically.
	 * @return true if cancellation was successful, false otherwise.
	 *
	 * @warning Avoid calling this method within the timer callback (TimerCallback) to prevent unexpected behavior.
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
 * @brief Standalone function to register a lambda-only timer.
 *
 * This function provides a convenient way to register timers without needing
 * a TimerHandler object. Useful for simple scheduled tasks.
 *
 * @param delayMilliseconds Initial delay before the timer starts, in milliseconds.
 * @param intervalSeconds Interval between timer triggers, in seconds.
 *                        Set to 0 for one-shot timer (triggers only once).
 * @param handler Callback function to handle the timer event.
 *                Return value for recurring timers (intervalSeconds > 0):
 *                  - true: continue the timer for the next interval
 *                  - false: stop the timer
 *                Return value is ignored for one-shot timers (always stop after execution).
 * @param from String indicating the source or context of the timer registration.
 * @return long Unique timer ID, or negative value if registration failed.
 *
 * @example
 *   std::atomic_long timerId{INVALID_TIMER_ID};
 *   timerId = registerTimer(1000, 5, []() {
 *       std::cout << "Timer fired!" << std::endl;
 *       return true; // Continue timer
 *   }, "my_standalone_timer");
 *   cancelTimer(timerId);
 */
long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, const TimerCallback &handler, const std::string &from);

/**
 * @brief Standalone function to cancel a timer.
 *
 * This function provides a convenient way to cancel timers registered via
 * the standalone registerTimer() function.
 *
 * @param timerId Atomic reference to the unique ID of the timer to cancel.
 *                Will be reset to INVALID_TIMER_ID atomically.
 * @return true if cancellation was successful, false otherwise.
 *
 * @warning Avoid calling this function within the timer callback (TimerCallback) to prevent unexpected behavior.
 */
bool cancelTimer(std::atomic_long &timerId);
