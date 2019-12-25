#pragma once
#include <ace/Task.h>
class HealthCheckTask :	public ACE_Task_Base
{
public:
	HealthCheckTask();
	virtual ~HealthCheckTask();
	static std::unique_ptr<HealthCheckTask>& instance();

	virtual int svc(void) override;
	virtual int open(void* args = 0) override;
	virtual int close(u_long flags = 0) override;

	virtual void healthCheckAllApp() const;

private:
	bool m_exit;
};

