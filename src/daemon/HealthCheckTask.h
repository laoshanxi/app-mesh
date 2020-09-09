#pragma once

#include <memory>
#include "TimerHandler.h"
//////////////////////////////////////////////////////////////////////////
/// Do health check for applications
//////////////////////////////////////////////////////////////////////////
class HealthCheckTask : public TimerHandler
{
public:
	HealthCheckTask();
	virtual ~HealthCheckTask();
	static std::shared_ptr<HealthCheckTask> &instance();

	void initTimer();

private:
	void healthCheckTimer(int timerId = 0);
	int m_timerId;
};
