#include <thread>
#include <ace/Barrier.h>
#include "DockerProcess.h"
#include "../common/Utility.h"
#include "../common/os/pstree.hpp"
#include "LinuxCgroup.h"
#include "MonitoredProcess.h"

DockerProcess::DockerProcess(int cacheOutputLines, std::string dockerImage)
	: AppProcess(cacheOutputLines), m_dockerImage(dockerImage), m_lastFetchTime(std::chrono::system_clock::now())
{
}


DockerProcess::~DockerProcess()
{
	DockerProcess::killgroup();
}

void DockerProcess::killgroup(int timerId)
{
	const static char fname[] = "DockerProcess::killgroup() ";

	// get and clean container id
	std::string containerId;
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		containerId = m_containerId;
		m_containerId.clear();
	}

	// clean docker container
	if (!containerId.empty())
	{
		std::string cmd = "docker rm -f " + containerId;
		AppProcess proc(0);
		proc.spawnProcess(cmd, "", "", {}, nullptr);
		if (proc.wait(ACE_Time_Value(3)) <= 0)
		{
			LOG_ERR << fname << "cmd <" << cmd << "> killed due to timeout";
			proc.killgroup();
		}
	}
}

int DockerProcess::syncSpawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit)
{
	const static char fname[] = "DockerProcess::syncSpawnProcess() ";

	killgroup();
	int pid = ACE_INVALID_PID;
	ACE_Time_Value tv(5);

	// 1. check docker image
	std::string dockerName = "app-mgr-" + this->getuuid();
	std::string dockerCommand = "docker inspect -f '{{.Size}}' " + m_dockerImage;
	setDockerCliProcess(std::make_shared<MonitoredProcess>(32));
	auto dockerProcess = getDockerCliProcess();
	pid = dockerProcess->spawnProcess(dockerCommand, "", "", {}, nullptr);
	{
		dockerProcess->wait(tv);
		if (dockerProcess->running())
		{
			this->attach(ACE_INVALID_PID);
			dockerProcess->killgroup();
			return ACE_INVALID_PID;
		}
	}
	auto imageSizeStr = dockerProcess->fetchOutputMsg();
	Utility::trimLineBreak(imageSizeStr);
	if (!Utility::isNumber(imageSizeStr) || std::stoi(imageSizeStr) < 1)
	{
		LOG_ERR << fname << "docker image <" << m_dockerImage << "> not exist";
		return ACE_INVALID_PID;
	}

	// 2. build docker start command line
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

	// 3. start docker container
	setDockerCliProcess(std::make_shared<MonitoredProcess>(32));
	dockerProcess = getDockerCliProcess();
	pid = dockerProcess->spawnProcess(dockerCommand, "", "", {}, nullptr);
	{
		dockerProcess->wait(tv);
		if (dockerProcess->running())
		{
			this->attach(ACE_INVALID_PID);
			dockerProcess->killgroup();
			return ACE_INVALID_PID;
		}
	}
	auto containerId = dockerProcess->fetchOutputMsg();
	Utility::trimLineBreak(containerId);

	// 4. get docker root pid
	dockerCommand = "docker inspect -f '{{.State.Pid}}' " + containerId;
	setDockerCliProcess(std::make_shared<MonitoredProcess>(32));
	dockerProcess = getDockerCliProcess();
	pid = dockerProcess->spawnProcess(dockerCommand, "", "", {}, nullptr);
	{
		dockerProcess->wait(tv);
		if (dockerProcess->running())
		{
			this->attach(ACE_INVALID_PID);
			dockerProcess->killgroup();
			return ACE_INVALID_PID;
		}
	}
	auto pidStr = dockerProcess->fetchOutputMsg();
	Utility::trimLineBreak(pidStr);
	if (Utility::isNumber(pidStr))
	{
		pid = std::stoi(pidStr);
		if (pid > 1)
		{
			this->attach(pid);
			std::lock_guard<std::recursive_mutex> guard(m_mutex);
			m_containerId = containerId;
			LOG_INF << fname << "started pid <" << pid << "> for container :" << m_containerId;
			return pid;
		}
	}
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_containerId = containerId;
	killgroup();
	return pid;
}

std::string DockerProcess::containerId()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_containerId.length() > 12 ? m_containerId.substr(0, 12) : m_containerId;
}

void DockerProcess::containerId(std::string containerId)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_containerId = containerId;
}

int DockerProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit)
{
	const static char fname[] = "DockerProcess::spawnProcess() ";
	// start a set of process in a thread
	const int startTimeoutSeconds = 5;

	if (m_spawnThread != nullptr) return ACE_INVALID_PID;

	struct SpawnParams
	{
		std::string cmd;
		std::string user;
		std::string workDir;
		std::map<std::string, std::string> envMap;
		std::shared_ptr<ResourceLimitation> limit;
		std::shared_ptr<DockerProcess> thisProc;
		std::shared_ptr<ACE_Barrier> barrier;
	};
	auto param = std::make_shared<SpawnParams>();
	param->cmd = cmd;
	param->user = user;
	param->workDir = workDir;
	param->envMap = envMap;
	param->limit = limit;
	param->barrier = std::make_shared<ACE_Barrier>(2);
	param->thisProc = std::dynamic_pointer_cast<DockerProcess>(this->shared_from_this());

	m_spawnThread = std::make_shared<std::thread>(
		[param]()
		{
			const static char fname[] = "DockerProcess::m_spawnThread() ";
			LOG_DBG << fname << "Entered";
			param->thisProc->syncSpawnProcess(param->cmd, param->user, param->workDir, param->envMap, param->limit);
			param->barrier->wait();	// wait here for m_spawnThread->detach() finished
			param->thisProc->m_spawnThread = nullptr;
			param->thisProc = nullptr;
			LOG_DBG << fname << "Exited";
		}
	);
	m_spawnThread->detach();
	param->barrier->wait();
	this->registerTimer(startTimeoutSeconds, 0, std::bind(&DockerProcess::checkDockerCliProcess, this, std::placeholders::_1), fname);
	// TBD: Docker app should not support short running here, since short running have kill and bellow attach is not real pid
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

std::shared_ptr<MonitoredProcess> DockerProcess::getDockerCliProcess()
{
	std::shared_ptr<MonitoredProcess> monitorProc;
	return m_dockerCliProcess;
}

void DockerProcess::setDockerCliProcess(std::shared_ptr<MonitoredProcess> proc)
{
	std::shared_ptr<MonitoredProcess> monitorProc;
	m_dockerCliProcess = proc;
}

void DockerProcess::checkDockerCliProcess(int timerId)
{
	auto monitorProc = getDockerCliProcess();
	if (monitorProc != nullptr && monitorProc->running())
	{
		monitorProc->killgroup();
	}
	if (this->getpid() == 1)
	{
		this->attach(ACE_INVALID_PID);
	}
}
