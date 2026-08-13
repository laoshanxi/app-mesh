// src/daemon/process/CgroupStartBarrier.cpp
#include "CgroupStartBarrier.h"

#include "../../common/Utility.h"

#include <cerrno>
#include <utility>

#include <unistd.h>

class CgroupStartBarrier::Gate final
{
public:
	explicit Gate(Setup setup)
		: m_setup(std::move(setup))
	{
		if (::pipe(m_pipe) != 0)
			m_pipe[0] = m_pipe[1] = ACE_INVALID_HANDLE;
	}

	~Gate()
	{
		closeHandle(m_pipe[0]);
		closeHandle(m_pipe[1]);
	}

	bool valid() const
	{
		return m_pipe[0] != ACE_INVALID_HANDLE && m_pipe[1] != ACE_INVALID_HANDLE;
	}

	void prepare(pid_t childPid)
	{
		closeHandle(m_pipe[0]);
		auto setup = std::move(m_setup);
		m_ready = setup && setup(childPid);
	}

	void waitInChild()
	{
		closeHandle(m_pipe[1]);
		char token = 0;
		ssize_t received;
		do
		{
			received = ::read(m_pipe[0], &token, sizeof(token));
		} while (received < 0 && errno == EINTR);
		closeHandle(m_pipe[0]);
		if (received != sizeof(token) || token != 1)
			::_exit(127);
	}

	bool release()
	{
		bool released = false;
		if (m_ready)
		{
			char token = 1;
			ssize_t written;
			do
			{
				written = ::write(m_pipe[1], &token, sizeof(token));
			} while (written < 0 && errno == EINTR);
			released = written == sizeof(token);
		}
		closeHandle(m_pipe[1]);
		return released;
	}

	void abort()
	{
		closeHandle(m_pipe[0]);
		closeHandle(m_pipe[1]);
	}

private:
	static void closeHandle(ACE_HANDLE &handle)
	{
		if (handle != ACE_INVALID_HANDLE)
		{
			::close(handle);
			handle = ACE_INVALID_HANDLE;
		}
	}

	ACE_HANDLE m_pipe[2]{ACE_INVALID_HANDLE, ACE_INVALID_HANDLE};
	Setup m_setup;
	bool m_ready{false};
};

class CgroupStartBarrier::ManagedProcess final : public ACE_Managed_Process
{
public:
	explicit ManagedProcess(std::shared_ptr<Gate> gate)
		: m_gate(std::move(gate)) {}

	int prepare(ACE_Process_Options &) override
	{
		return m_gate->valid() ? 0 : -1;
	}

	void parent(pid_t childPid) override
	{
		m_gate->prepare(childPid);
	}

	void child(pid_t) override
	{
		m_gate->waitInChild();
	}

private:
	std::shared_ptr<Gate> m_gate;
};

CgroupStartBarrier::CgroupStartBarrier(Setup setup)
	: m_gate(std::make_shared<Gate>(std::move(setup))),
	  m_process(std::make_unique<ManagedProcess>(m_gate))
{
}

CgroupStartBarrier::~CgroupStartBarrier() = default;

ACE_Managed_Process *CgroupStartBarrier::managedProcess() const
{
	return m_process.get();
}

bool CgroupStartBarrier::releaseAfterRegistration()
{
	m_process.release();
	return m_gate->release();
}

void CgroupStartBarrier::abort()
{
	m_gate->abort();
	m_process.reset();
}
