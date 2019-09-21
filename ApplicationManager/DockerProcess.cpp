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
	DockerProcess::killgroup();
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

int DockerProcess::asyncSpawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit)
{
	const static char fname[] = "DockerProcess::asyncSpawnProcess() ";

	killgroup();
	int pid = -1;
	// construct container name
	static int dockerIndex = 0;
	std::string dockerName = "app-mgr-" + this->getuuid();

	// check docker image
	std::string dockerCommand = "docker inspect -f '{{.Size}}' " + m_dockerImage;
	auto imageSize = Utility::runShellCommand(dockerCommand);
	Utility::trimLineBreak(imageSize);
	if (!Utility::isNumber(imageSize) || std::stoi(imageSize) < 1)
	{
		LOG_ERR << fname << "docker image <" << m_dockerImage << "> not exist";
		return -1;
	}

	// build docker start command line
	dockerCommand = std::string("docker run -d ") + "--name " + dockerName;
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
	Utility::trimLineBreak(containerId);
	dockerCommand = "docker inspect -f '{{.State.Pid}}' " + containerId;
	auto pidStr = Utility::runShellCommand(dockerCommand);
	Utility::trimLineBreak(pidStr);
	if (Utility::isNumber(pidStr))
	{
		pid = std::stoi(pidStr);
		if (pid > 1)
		{
			this->attach(pid);
			std::lock_guard<std::recursive_mutex> guard(m_mutex);
			m_containerId = containerId;
			return pid;
		}
	}
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_containerId = containerId;
	killgroup();
	return pid;
}

int DockerProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit)
{
	const static char fname[] = "DockerProcess::spawnProcess() ";
	if (m_spawnThread != nullptr)
	{
		return -1;
	}
	struct SpawnParams
	{
		std::string cmd;
		std::string user;
		std::string workDir;
		std::map<std::string, std::string> envMap;
		std::shared_ptr<ResourceLimitation> limit;
		std::shared_ptr<DockerProcess> thisProc;
	};
	auto param = std::make_shared<SpawnParams>();
	param->cmd = cmd;
	param->user = user;
	param->workDir = workDir;
	param->envMap = envMap;
	param->limit = limit;
	param->thisProc = std::dynamic_pointer_cast<DockerProcess>(this->shared_from_this());

	m_spawnThread = std::make_shared<std::thread>(
		[param, this]()
		{
			const static char fname[] = "DockerProcess::m_spawnThread() ";
			LOG_DBG << fname << "Entered";
			param->thisProc->asyncSpawnProcess(param->cmd, param->user, param->workDir, param->envMap, param->limit);
			param->thisProc->wait();
			param->thisProc->m_spawnThread = nullptr;
			param->thisProc = nullptr;
			LOG_DBG << fname << "Exited";
		}
	);
	m_spawnThread->detach();
	const int startTimeoutSeconds = 5;
	this->registerTimer(startTimeoutSeconds, 0, std::bind(&DockerProcess::checkStartThreadTimer, this, std::placeholders::_1), fname);
	this->attach(1);
	return 1;
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
		//auto microsecondsUTC = std::chrono::duration_cast<std::chrono::seconds>(m_lastFetchTime.time_since_epoch()).count();
		auto timeSince = Utility::getRfc3339Time(m_lastFetchTime);
		std::string dockerCommand = "docker logs --since " + timeSince + " " + m_containerId;
		auto msg = Utility::runShellCommand(dockerCommand);
		m_lastFetchTime = std::chrono::system_clock::now();
		return std::move(msg);
	}
	return std::string();
}

void DockerProcess::checkStartThreadTimer(int timerId)
{
	if (this->getpid() == 1)
	{
		killgroup();
	}
}
