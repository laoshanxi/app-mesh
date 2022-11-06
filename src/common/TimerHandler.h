#pragma once

#include <functional>
#include <map>
#include <memory>
#include <string>

#include <ace/Event_Handler.h>
#include <ace/Null_Mutex.h>
#include <ace/Reactor.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/Singleton.h>
#include <ace/Test_and_Set.h>

// ACE_Test_and_Set Singleton.
typedef ACE_Singleton<ACE_Test_and_Set<ACE_Recursive_Thread_Mutex, sig_atomic_t>, ACE_Null_Mutex> QUIT_HANDLER;

#define INVALID_TIMER_ID -1L

class TimerHandler : public std::enable_shared_from_this<TimerHandler>
{
public:
	virtual ~TimerHandler();

	/// <summary>
	/// Register a timer to this object
	/// </summary>
	/// <param name="delaySeconds">Timer will start after delay milliseconds [1/1000 second].</param>
	/// <param name="intervalSeconds">Interval for the Timer, the value 0 means the timer will only triggered once.</param>
	/// <param name="handler">Function point to this object.</param>
	/// <return>Timer unique ID.</return>
	long registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::function<void(void)> &handler, const std::string &from);
	/// <summary>
	/// Cancel a timer
	/// </summary>
	/// <param name="timerId">Timer unique ID.</param>
	/// <return>Cancel success or not.</return>
	bool cancelTimer(long &timerId);
};

class TimerEvent : public ACE_Event_Handler
{
public:
	explicit TimerEvent(bool callOnce, const std::shared_ptr<TimerHandler> timerObj, const std::function<void(void)> &handler);
	/**
	 * Timer expire call back function, override from ACE
	 * Called when timer expires.  @a current_time represents the current
	 * time that the Event_Handler was selected for timeout
	 * dispatching and @a act is the asynchronous completion token that
	 * was passed in when <schedule_timer> was invoked.
	 */
	virtual int handle_timeout(const ACE_Time_Value &current_time, const void *act = 0) override final;

	/// Called when a handle_*() method returns -1 or when the
	/// remove_handler() method is called on an ACE_Reactor.  The
	/// @a close_mask indicates which event has triggered the
	/// handle_close() method callback on a particular @a handle.
	virtual int handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask) override final;

private:
	const std::shared_ptr<TimerHandler> m_timerObj; // used to hold the timer target instance avoid free
	const std::function<void(void)> m_handler;
	const bool m_callOnce;
};

//////////////////////////////////////////////////////////////////////////
/// Timer Event base class
/// The class which use timer event should implement from this class.
/// Note: enable_shared_from_this does not support stack allocation!
///       http://blog.chinaunix.net/uid-442138-id-2122464.html
//////////////////////////////////////////////////////////////////////////
class TimerManager
{
public:
	TimerManager();
	virtual ~TimerManager();
	ACE_Reactor *reactor();

	/// <summary>
	/// Register a timer to this object
	/// </summary>
	/// <param name="delaySeconds">Timer will start after delay milliseconds [1/1000 second].</param>
	/// <param name="intervalSeconds">Interval for the Timer, the value 0 means the timer will only triggered once.</param>
	/// <param name="handler">Function point to this object.</param>
	/// <return>Timer unique ID.</return>
	long registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::string &from, const std::shared_ptr<TimerHandler> timerObj, const std::function<void(void)> &handler);
	/// <summary>
	/// Cancel a timer
	/// </summary>
	/// <param name="timerId">Timer unique ID.</param>
	/// <return>Cancel success or not.</return>
	bool cancelTimer(long &timerId);

	/// <summary>
	/// Use ACE_Reactor for timer event, block function, should used in a thread
	/// </summary>
	static void runReactorEvent(ACE_Reactor *reactor);
	/// <summary>
	/// End ACE_Reactor
	/// </summary>
	static int endReactorEvent(ACE_Reactor *reactor);

private:
	ACE_Reactor m_reactor;
};

typedef ACE_Singleton<TimerManager, ACE_Recursive_Thread_Mutex> TIMER_MANAGER;
