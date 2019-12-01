#include <thread>
#include <ace/Barrier.h>
#include "DockerProcess.h"
#include "../common/Utility.h"
#include "../common/os/pstree.hpp"
#include "LinuxCgroup.h"
#include "MonitoredProcess.h"

DockerProcess::DockerProcess(int cacheOutputLines, std::string dockerImage, std::string appName)
	: AppProcess(cacheOutputLines), m_dockerImage(dockerImage),
	m_appName(appName), m_lastFetchTime(std::chrono::system_clock::now())
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

	if (m_imagePullProc != nullptr && m_imagePullProc->running())
	{
		m_imagePullProc->killgroup();
	}
}

int DockerProcess::syncSpawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit)
{
	const static char fname[] = "DockerProcess::syncSpawnProcess() ";

	killgroup();
	int pid = ACE_INVALID_PID;
	const int dockerCliTimeoutSec = 5;
	std::string containerName = "appmgr-" + m_appName;

	// 0. clean old docker contianer (docker container will left when host restart)
	std::string dockerCommand = "docker rm -f " + containerName;
	AppProcess proc(0);
	proc.spawnProcess(dockerCommand, "", "", {}, nullptr);
	proc.wait();

	// 1. check docker image
	dockerCommand = "docker inspect -f '{{.Size}}' " + m_dockerImage;
	auto dockerProcess = std::make_shared<MonitoredProcess>(32, false);
	pid = dockerProcess->spawnProcess(dockerCommand, "", "", {}, nullptr);
	dockerProcess->regKillTimer(dockerCliTimeoutSec, fname);
	dockerProcess->runPipeReaderThread();
	auto imageSizeStr = dockerProcess->fetchOutputMsg();
	Utility::trimLineBreak(imageSizeStr);
	imageSizeStr = getFirstLine(imageSizeStr);
	if (!Utility::isNumber(imageSizeStr) || std::stoi(imageSizeStr) < 1)
	{
		LOG_ERR << fname << "docker image <" << m_dockerImage << "> not exist, try to pull.";

		// pull docker image
		if (envMap.count(ENV_APP_MANAGER_DOCKER_IMG_PULL_TIMEOUT))
		{
			int pullTimeout = std::stoi(envMap[ENV_APP_MANAGER_DOCKER_IMG_PULL_TIMEOUT]);
			m_imagePullProc = std::make_shared<MonitoredProcess>(m_cacheOutputLines);
			m_imagePullProc->spawnProcess("docker pull " + m_dockerImage, "root", workDir, {}, nullptr);
			m_imagePullProc->regKillTimer(pullTimeout, fname);	// TBD: set timeout of docker image pull to 15 minutes for now
			this->attach(m_imagePullProc->getpid());
			return m_imagePullProc->getpid();
		}
		else
		{
			throw std::invalid_argument("Docker image does not exits");
		}
	}

	// 2. build docker start command line
	dockerCommand = std::string("docker run -d ") + "--name " + containerName;
	for (auto env : envMap)
	{
		if (env.first == ENV_APP_MANAGER_DOCKER_PARAMS)
		{
			// used for -p -v parameter
			dockerCommand.append(" ");
			dockerCommand.append(env.second);
		}
		else
		{
			dockerCommand += " -e ";
			dockerCommand += env.first;
			dockerCommand += "='";
			dockerCommand += env.second;
			dockerCommand += "'";
		}
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
	dockerProcess = std::make_shared<MonitoredProcess>(32, false);
	pid = dockerProcess->spawnProcess(dockerCommand, "", "", {}, nullptr);
	dockerProcess->regKillTimer(dockerCliTimeoutSec, fname);
	dockerProcess->runPipeReaderThread();
	auto containerId = dockerProcess->fetchOutputMsg();
	Utility::trimLineBreak(containerId);
	containerId = getFirstLine(containerId);
	{
		// set container id here for future clean
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		m_containerId = containerId;
	}

	// 4. get docker root pid
	dockerCommand = "docker inspect -f '{{.State.Pid}}' " + containerId;
	dockerProcess = std::make_shared<MonitoredProcess>(32, false);
	pid = dockerProcess->spawnProcess(dockerCommand, "", "", {}, nullptr);
	dockerProcess->regKillTimer(dockerCliTimeoutSec, fname);
	dockerProcess->runPipeReaderThread();
	auto pidStr = dockerProcess->fetchOutputMsg();
	Utility::trimLineBreak(pidStr);
	pidStr = getFirstLine(pidStr);
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
	this->detach();
	killgroup();
	return pid;
}

pid_t DockerProcess::getpid(void) const
{
	if (ACE_Process::getpid() == 1)
		return ACE_INVALID_PID;
	else
		return ACE_Process::getpid();
}

std::string DockerProcess::containerId()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_containerId;
}

void DockerProcess::containerId(std::string containerId)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_containerId = containerId;
}

int DockerProcess::spawnProcess(std::string cmd, std::string user, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit)
{
	const static char fname[] = "DockerProcess::spawnProcess() ";
	LOG_DBG << fname << "Entered";

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
			param->barrier->wait();	// wait here for m_spawnThread->detach() finished
			param->thisProc->syncSpawnProcess(param->cmd, param->user, param->workDir, param->envMap, param->limit);
			param->thisProc->m_spawnThread = nullptr;
			param->thisProc = nullptr;
			LOG_DBG << fname << "Exited";
		}
	);
	m_spawnThread->detach();
	param->barrier->wait();
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

std::string DockerProcess::getFirstLine(const std::string& str)
{
	char* line = const_cast <char*> (str.c_str());
	size_t start = 0;
	while ((*line) != '\r' && (*line) != '\n' && (*line) != '\0')
	{
		++line;
		++start;
	}
	return str.substr(0, start);
}
