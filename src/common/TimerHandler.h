#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <string>

#include <ace/Event_Handler.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/Singleton.h>
#include <ace/Task.h>
#include <ace/Test_and_Set.h>
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

using Upcall = ACE_Event_Handler_Handle_Timeout_Upcall;
using Timer_Heap = ACE_Timer_Heap_T<ACE_Event_Handler *, Upcall, ACE_Recursive_Thread_Mutex>;
using Thread_Timer_Queue = ACE_Thread_Timer_Queue_Adapter<Timer_Heap>;

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
 * @note The use of enable_shared_from_this does not support stack allocation!
 */
class TimerHandler : public std::enable_shared_from_this<TimerHandler>
{
public:
	virtual ~TimerHandler() = default;

	/**
	 * @brief Registers a timer for this object.
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
	 *   timerId = this->registerTimer(1000, 5, [&](){ ... }, "my_timer");
	 *   this->cancelTimer(timerId);
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, const TimerCallback &handler, const std::string from);

	/**
	 * @brief Cancels a timer.
	 *
	 * @param timerId Reference to the unique ID of the timer to cancel.
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
 * @brief Represents a timer associated with a TimerHandler object.
 *
 * This class extends ACE_Event_Handler to handle timer events.
 */
class TimerEvent final : public ACE_Event_Handler
{
public:
	/**
	 * @brief Construct a new TimerEvent object.
	 *
	 * @param isOneShot Whether the timer should be triggered only once.
	 * @param timerObj Shared pointer to the associated TimerHandler object.
	 * @param handler Callback function to be invoked on timer expiration.
	 */
	explicit TimerEvent(bool isOneShot, std::shared_ptr<TimerHandler> timerObj, TimerCallback handler) noexcept;

	/**
	 * @brief Callback function invoked when the timer expires.
	 *
	 * @param current_time The time at which the timer expired.
	 * @param act The 'magic cookie' argument passed in when the timer was registered.
	 * @return int 0 on success, or a negative value on failure.
	 */
	int handle_timeout(const ACE_Time_Value &current_time, const void *act = nullptr) override;

	/**
	 * @brief Called when a handle_*() method returns -1 or when remove_handler() is called on an ACE_Reactor.
	 *
	 * @param handle The ACE handle associated with the event.
	 * @param close_mask Indicates which event triggered the handle_close callback.
	 * @return int 0 on success, or a negative value on failure.
	 */
	int handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask) override;

private:
	const std::shared_ptr<TimerHandler> m_timerObj; ///< Holds the target TimerHandler instance to prevent premature deallocation.
	const TimerCallback m_handler;					///< The callback function to be invoked on timer expiration.
	const bool m_isOneShot;							///< Indicates if the timer should be triggered only once.
};

/**
 * @class TimerManager
 * @brief Global singleton container class for managing timer events.
 *
 * This class extends ACE_Task_Base and manages the lifecycle of timer events.
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
	 * @brief Registers a timer to timerObj.
	 *
	 * @param delayMilliseconds Initial delay before the timer starts, in milliseconds.
	 * @param intervalSeconds Interval between timer triggers, in seconds. 0 means the timer will trigger only once.
	 * @param from String indicating the source or context of the timer registration.
	 * @param timerObj Shared pointer to the TimerHandler that will handle the timer event.
	 * @param handler Callback function executed when the timer expires.
	 * @return long Unique timer ID for the registered timer.
	 */
	long registerTimer(long delayMilliseconds, std::size_t intervalSeconds, std::string from, std::shared_ptr<TimerHandler> timerObj, const TimerCallback &handler);

	/**
	 * @brief Cancels a timer using its unique ID.
	 *
	 * @param timerId Reference to the unique ID of the timer to be canceled.
	 * @return true if cancellation was successful, false otherwise.
	 */
	bool cancelTimer(long &timerId);

private:
	Thread_Timer_Queue m_timerQueue; ///< Queue for managing active timers.
};

using TIMER_MANAGER = ACE_Singleton<TimerManager, ACE_Null_Mutex>;
using QUIT_HANDLER = ACE_Singleton<ACE_Test_and_Set<ACE_Recursive_Thread_Mutex, sig_atomic_t>, ACE_Null_Mutex>;
