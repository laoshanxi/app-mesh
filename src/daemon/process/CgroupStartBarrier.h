// src/daemon/process/CgroupStartBarrier.h
#pragma once

#include <functional>
#include <memory>

#include <ace/Process.h>

class CgroupStartBarrier final
{
public:
	using Setup = std::function<bool(pid_t)>;

	explicit CgroupStartBarrier(Setup setup);
	~CgroupStartBarrier();

	CgroupStartBarrier(const CgroupStartBarrier &) = delete;
	CgroupStartBarrier &operator=(const CgroupStartBarrier &) = delete;

	ACE_Managed_Process *managedProcess() const;
	bool releaseAfterRegistration();
	void abort();

private:
	class Gate;
	class ManagedProcess;

	std::shared_ptr<Gate> m_gate;
	std::unique_ptr<ManagedProcess> m_process;
};
