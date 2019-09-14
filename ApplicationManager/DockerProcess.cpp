#include <thread>
#include "DockerProcess.h"
#include "../common/Utility.h"
#include "../common/os/pstree.hpp"
#include "LinuxCgroup.h"

DockerProcess::DockerProcess(std::string dockerImage)
	: m_dockerImage(dockerImage)
{
}


DockerProcess::~DockerProcess()
{
	killgroup();
}

void DockerProcess::killgroup(int timerId)
{
	const static char fname[] = "DockerProcess::killgroup() ";
	if (!m_containerId.empty())
	{
		std::string cmd = "docker rm -f " + m_containerId;
		LOG_DBG << fname << "system <" << cmd << ">";
		::system(cmd.c_str());
		m_containerId.clear();
	}
}

int DockerProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit)
{
	int pid = -1;

	// build docker start command line
	std::string dockerCommand = "docker run -d";
	for(auto env: envMap)
	{
		dockerCommand += " --env ";
		dockerCommand += env.first;
		dockerCommand += "=";
		dockerCommand += env.second;
	}
	if (limit != nullptr)
	{
		if (limit->m_memoryMb)
		{
			dockerCommand += " --memory " + std::to_string(limit->m_memoryMb) + "M";
			if (limit->m_memoryVirtMb && limit->m_memoryVirtMb > limit->m_memoryMb)
			{
				dockerCommand += " --memory-swap " + std::to_string(limit->m_memoryVirtMb - limit->m_memoryVirtMb) + "M";
			}
		}
		if (limit->m_cpuShares)
		{
			dockerCommand += " --cpu-shares " + std::to_string(limit->m_cpuShares);
		}
	}
	dockerCommand += " " + m_dockerImage;
	dockerCommand += " " + cmd;

	// start docker container
	auto containerId = Utility::runShellCommand(dockerCommand);
	dockerCommand = "docker inspect -f '{{.State.Pid}}' " + containerId;
	auto pidStr = Utility::runShellCommand(dockerCommand);
	if (Utility::isNumber(pidStr))
	{
		pid = std::stoi(pidStr);
		this->attach(pid);
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		m_containerId = containerId;
	}
	else
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		m_containerId = containerId;
		killgroup();
	}
	return pid;
}
