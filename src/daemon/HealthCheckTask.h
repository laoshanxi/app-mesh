#pragma once

#include <atomic>
#include <memory>
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
	/// Run doHealthCheck() on its own thread so a slow or hung health command
	/// cannot stall the scheduler loop; skips when a check is already running.
	void runAsync();

private:
	std::atomic_flag m_checkRunning = ATOMIC_FLAG_INIT;
};
