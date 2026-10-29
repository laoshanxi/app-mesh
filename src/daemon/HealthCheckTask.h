#pragma once

#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
//////////////////////////////////////////////////////////////////////////
/// Do health check for applications
//////////////////////////////////////////////////////////////////////////
class HealthCheckTask
{
public:
	HealthCheckTask();
	virtual ~HealthCheckTask();
	static std::shared_ptr<HealthCheckTask> &instance();
	void doHealthCheck();
	/// Wake the resident worker for one round and return immediately. Health
	/// checks spawn processes and wait, so they must stay off the scheduler
	/// loop; triggers arriving while a round is running are coalesced.
	void trigger();

private:
	void run();

	std::thread m_worker;
	std::mutex m_mutex;
	std::condition_variable m_wakeup;
	bool m_triggered = false;
	bool m_stopped = false;
};
