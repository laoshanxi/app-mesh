#pragma once

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
};
