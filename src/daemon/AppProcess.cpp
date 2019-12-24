#include <thread>
#include "AppProcess.h"
#include "../common/Utility.h"
#include "../common/os/pstree.hpp"
#include "LinuxCgroup.h"

AppProcess::AppProcess(int cacheOutputLines)
	:m_cacheOutputLines(cacheOutputLines), m_killTimerId(0)
{
	m_uuid = Utility::createUUID();
}


AppProcess::~AppProcess()
{
	if (this->running())
	{
		killgroup();
	}
}

void AppProcess::attach(int pid)
{
	this->child_id_ = pid;
}

void AppProcess::detach()
{
	attach(ACE_INVALID_PID);
}

pid_t AppProcess::getpid(void) const
{
	return ACE_Process::getpid();
}

void AppProcess::killgroup(int timerId)
{
	const static char fname[] = "AppProcess::killgroup() ";

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

void AppProcess::setCgroup(std::shared_ptr<ResourceLimitation>& limit)
{
	// https://blog.csdn.net/u011547375/article/details/9851455
	if (limit != nullptr)
	{
		m_cgroup = std::make_unique<LinuxCgroup>(limit->m_memoryMb, limit->m_memoryVirtMb - limit->m_memoryMb, limit->m_cpuShares);
		m_cgroup->setCgroup(limit->n_name, getpid(), ++(limit->m_index));
	}
}

const std::string AppProcess::getuuid() const
{
	return m_uuid;
}

void AppProcess::regKillTimer(size_t timeout, const std::string from)
{
	m_killTimerId = this->registerTimer(timeout, 0, std::bind(&AppProcess::killgroup, this, std::placeholders::_1), from);
}


int AppProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit)
{
	const static char fname[] = "AppProcess::spawnProcess() ";

	int pid = -1;
	
	envMap[ENV_APP_MANAGER_LAUNCH_TIME] = Utility::getFmtTimeSeconds(std::chrono::system_clock::now(), DATE_TIME_FORMAT);
	size_t cmdLenth = cmd.length() + ACE_Process_Options::DEFAULT_COMMAND_LINE_BUF_LEN;
	int totalEnvSize = 0;
	int totalEnvArgs = 0;
	Utility::getEnvironmentSize(envMap, totalEnvSize, totalEnvArgs);
	ACE_Process_Options option(1, cmdLenth, totalEnvSize, totalEnvArgs);
	option.command_line(cmd.c_str());
	//option.avoid_zombies(1);
	if (user.length())
	{
		unsigned int gid, uid;
		if (Utility::getUid(user, uid, gid))
		{
			option.seteuid(uid);
			option.setruid(uid);
			option.setegid(gid);
			option.setrgid(gid);
		}
		else
		{
			return ACE_INVALID_PID;
		}
	}
	option.setgroup(0);
	option.inherit_environment(true);
	option.handle_inheritance(0);
	if (workDir.length()) option.working_directory(workDir.c_str());
	std::for_each(envMap.begin(), envMap.end(), [&option](const std::pair<std::string, std::string>& pair)
	{
		option.setenv(pair.first.c_str(), "%s", pair.second.c_str());
		LOG_DBG << "spawnProcess env: " << pair.first.c_str() << "=" << pair.second.c_str();
	});
	// do not inherit LD_LIBRARY_PATH to child
	static const std::string ldEnv = ::getenv("LD_LIBRARY_PATH");
	if (!ldEnv.empty())
	{
		std::string env = ldEnv;
		env = Utility::stringReplace(env, "/opt/appmanager/lib64:", "");
		env = Utility::stringReplace(env, ":/opt/appmanager/lib64", "");
		option.setenv("LD_LIBRARY_PATH", "%s", env.c_str());
	}
	if (this->spawn(option) >= 0)
	{
		pid = this->getpid();
		LOG_INF << fname << "Process <" << cmd << "> started with pid <" << pid << ">.";
		this->setCgroup(limit);
	}
	else
	{
		pid = -1;
		LOG_ERR << fname << "Process:<" << cmd << "> start failed with error : " << std::strerror(errno);
	}
	return pid;
}

void AppProcess::getSysProcessList(std::map<std::string, int>& processList, const void * pt)
{
	const static char fname[] = "AppProcess::getSysProcessList() ";

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

std::string AppProcess::getOutputMsg()
{
	return std::string();
}

std::string AppProcess::fetchOutputMsg()
{
	return std::string();
}
