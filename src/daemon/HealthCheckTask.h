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

	void healthCheckAllApp() const;

	static std::unique_ptr<HealthCheckTask>& instance();
};

