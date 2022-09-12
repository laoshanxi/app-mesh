#pragma once

#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include <ace/Event_Handler.h>
#include <ace/Null_Mutex.h>
#include <ace/Reactor.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <ace/Singleton.h>
#include <ace/Test_and_Set.h>

// ACE_Test_and_Set Singleton.
typedef ACE_Singleton<ACE_Test_and_Set<ACE_Recursive_Thread_Mutex, sig_atomic_t>, ACE_Null_Mutex> QUIT_HANDLER;

#define INVALID_TIMER_ID -1

class TimerHandler : public std::enable_shared_from_this<TimerHandler>
{
public:
	/// <summary>
	/// Register a timer to this object
	/// </summary>
	/// <param name="delaySeconds">Timer will start after delay milliseconds [1/1000 second].</param>
	/// <param name="intervalSeconds">Interval for the Timer, the value 0 means the timer will only triggered once.</param>
	/// <param name="handler">Function point to this object.</param>
	/// <return>Timer unique ID.</return>
	int registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::function<void(int)> &handler, const std::string &from);
	/// <summary>
	/// Cancel a timer
	/// </summary>
	/// <param name="timerId">Timer unique ID.</param>
	/// <return>Cancel success or not.</return>
	bool cancelTimer(int &timerId);
};

//////////////////////////////////////////////////////////////////////////
/// Timer Event base class
/// The class which use timer event should implement from this class.
/// Note: enable_shared_from_this does not support stack allocation!
///       http://blog.chinaunix.net/uid-442138-id-2122464.html
//////////////////////////////////////////////////////////////////////////
class TimerManager : public ACE_Event_Handler
{
private:
	/// <summary>
	/// One timer event
	/// </summary>
	struct TimerEvent
	{
		/// <summary>
		/// TimerEvent construction
		/// </summary>
		/// <param name="timerId">timerId will be deleted in TimerEvent de-construction</param>
		/// <param name="handler">timer function</param>
		/// <param name="object">timer object</param>
		/// <param name="callOnce">only run one-time</param>
		explicit TimerEvent(int *timerId, std::function<void(int)> handler, const std::shared_ptr<TimerHandler> object, bool callOnce);
		const std::shared_ptr<int> m_timerId;
		std::function<void(int)> m_handler;
		const std::shared_ptr<TimerHandler> m_timerObject;
		const bool m_callOnce;
	};

	/**
	 * Timer expire call back function, override from ACE
	 * Called when timer expires.  @a current_time represents the current
	 * time that the Event_Handler was selected for timeout
	 * dispatching and @a act is the asynchronous completion token that
	 * was passed in when <schedule_timer> was invoked.
	 */
	virtual int handle_timeout(const ACE_Time_Value &current_time, const void *act = 0) override final;

public:
	TimerManager();
	virtual ~TimerManager();

	/// <summary>
	/// Register a timer to this object
	/// </summary>
	/// <param name="delaySeconds">Timer will start after delay milliseconds [1/1000 second].</param>
	/// <param name="intervalSeconds">Interval for the Timer, the value 0 means the timer will only triggered once.</param>
	/// <param name="handler">Function point to this object.</param>
	/// <return>Timer unique ID.</return>
	int registerTimer(long int delayMillisecond, std::size_t intervalSeconds, const std::function<void(int)> &handler, const std::string &from, const std::shared_ptr<TimerHandler> fromObj);
	/// <summary>
	/// Cancel a timer
	/// </summary>
	/// <param name="timerId">Timer unique ID.</param>
	/// <return>Cancel success or not.</return>
	bool cancelTimer(int &timerId);

	/// <summary>
	/// Use ACE_Reactor for timer event, block function, should used in a thread
	/// </summary>
	static void runReactorEvent(ACE_Reactor *reactor);
	/// <summary>
	/// End ACE_Reactor
	/// </summary>
	static int endReactorEvent(ACE_Reactor *reactor);

private:
	// key: timer ID point, must unique, value: function point
	std::map<const int *, std::shared_ptr<TimerEvent>> m_timers;

protected:
	mutable std::recursive_mutex m_timerMutex;
};

typedef ACE_Singleton<TimerManager, ACE_Null_Mutex> TIMER_MANAGER;
