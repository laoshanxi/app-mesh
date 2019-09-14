#include <thread>
#include "DockerProcess.h"
#include "../common/Utility.h"
#include "../common/os/pstree.hpp"
#include "LinuxCgroup.h"

DockerProcess::DockerProcess(int cacheOutputLines, std::string dockerImage)
	: Process(cacheOutputLines), m_dockerImage(dockerImage), m_lastFetchTime(std::chrono::system_clock::now())
{
}


DockerProcess::~DockerProcess()
{
	killgroup();
}

void DockerProcess::killgroup(int timerId)
{
	const static char fname[] = "DockerProcess::killgroup() ";
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
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
	killgroup();
	int pid = -1;
	// construct container name
	static int dockerIndex = 0;
	std::string dockerName = "app-mgr-" + std::to_string(++dockerIndex) + "-" + m_dockerImage;
	if (limit != nullptr) dockerName += (std::string("-") + limit->n_name);
	// build docker start command line
	std::string dockerCommand = std::string("docker run -d ") + "--name " + dockerName;
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

std::string DockerProcess::getOutputMsg()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_containerId.length())
	{
		std::string dockerCommand = "docker logs --tail " + std::to_string(m_cacheOutputLines) + " " + m_containerId;
		return Utility::runShellCommand(dockerCommand);
	}
	return std::string();
}

std::string DockerProcess::fetchOutputMsg()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_containerId.length())
	{
		std::string dockerCommand = "docker logs --since " + std::to_string(m_lastFetchTime.time_since_epoch().count()) + " " + m_containerId;
		auto msg = Utility::runShellCommand(dockerCommand);
		m_lastFetchTime = std::chrono::system_clock::now();
		return std::move(msg);
	}
	return std::string();
}
