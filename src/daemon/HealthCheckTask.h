#pragma once
#include <ace/Task.h>

class InfiniteQueue : public ACE_Message_Queue<ACE_MT_SYNCH>
{
public:
	InfiniteQueue() {}
	virtual ~InfiniteQueue() {}

	virtual bool is_full(void) override { return false; }
};

class HealthCheckTask : public ACE_Task<ACE_MT_SYNCH>
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

