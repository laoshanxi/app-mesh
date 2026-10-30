#pragma once

#include <memory>
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
	/// Spawn the resident worker: one round, then a fixed sleep, repeated.
	/// Health checks spawn processes and wait, so they must stay off the
	/// scheduler loop. Call once, after the startup readiness phases (which
	/// run doHealthCheck() inline).
	void start();

private:
	void run();

	std::thread m_worker;
};
