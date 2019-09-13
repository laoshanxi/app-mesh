#include <thread>
#include "Process.h"
#include "../common/Utility.h"
#include "../common/os/pstree.hpp"
#include "LinuxCgroup.h"

Process::Process()
	:m_killTimerId(0)
{
	m_uuid = Utility::createUUID();
}


Process::~Process()
{
}

void Process::attach(int pid)
{
	this->child_id_ = pid;
}

void Process::killgroup(int timerId)
{
	const static char fname[] = "Process::killgroup() ";

	LOG_INF << fname << "kill process <" << getpid() << ">.";

	if (timerId == 0 && m_killTimerId > 0)
	{
		// killed before timer event, cancle timer event
		this->cancleTimer(m_killTimerId);
		m_killTimerId = 0;
	}
	if (m_killTimerId > 0 && m_killTimerId == timerId)
	{
		// clean timer id, trigger-ing this time.
		m_killTimerId = 0;
	}

	if (this->running() && this->getpid() > 1)
	{
		ACE_OS::kill(-(this->getpid()), 9);
		this->terminate();
		if (this->wait() < 0 && errno != 10)	// 10 is ECHILD:No child processes
		{
			//avoid  zombie process (Interrupted system call)
			LOG_WAR << fname << "Wait process <" << getpid() << "> to exit failed with error : " << std::strerror(errno);
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
			if (this->wait() < 0)
			{
				LOG_ERR << fname << "Retry wait process <" << getpid() << "> failed with error : " << std::strerror(errno);
			}
			else
			{
				LOG_INF << fname << "Retry wait process <" << getpid() << "> success";
			}
		}
	}
}

void Process::setCgroup(std::string appName, int index, std::shared_ptr<ResourceLimitation>& limit)
{
	// https://blog.csdn.net/u011547375/article/details/9851455
	if (limit != nullptr)
	{
		m_cgroup = std::make_shared<LinuxCgroup>(limit->m_memoryMb, limit->m_memoryVirtMb - limit->m_memoryMb, limit->m_cpuShares);
		m_cgroup->setCgroup(appName, getpid(), index);
	}
}

const std::string Process::getuuid() const
{
	return m_uuid;
}

void Process::regKillTimer(size_t timeout, const std::string from)
{
	m_killTimerId = this->registerTimer(timeout, 0, std::bind(&Process::killgroup, this, std::placeholders::_1), from);
}


void Process::getSysProcessList(std::map<std::string, int>& processList, const void * pt)
{
	const static char fname[] = "Process::getSysProcessList() ";

	std::shared_ptr<os::ProcessTree> ptree;
	const os::ProcessTree* tree;
	if (pt == nullptr)
	{
		// 1 is linux root process
		ptree = os::pstree(1);
		tree = ptree.get();
	}
	else
	{
		tree = (os::ProcessTree*)pt;
	}

	auto pname = Utility::stdStringTrim(tree->process.command);
	processList[pname] = tree->process.pid;

	LOG_DBG << fname << "Process: <" << pname << "> pid: " << tree->process.pid;

	for (auto it = tree->children.begin(); it != tree->children.end(); ++it)
	{
		getSysProcessList(processList, &(*it));
	}
}
