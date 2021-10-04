
#include "DockerProcess.h"
#include "../../common/DateTime.h"
#include "../../common/Utility.h"
#include "../../common/os/pstree.hpp"
#include "../ResourceLimitation.h"
#include "LinuxCgroup.h"

DockerProcess::DockerProcess(const std::string &dockerImage, const std::string &appName)
	: m_dockerImage(dockerImage), m_containerName(appName)
{
	const static char fname[] = "DockerProcess::DockerProcess() ";
	LOG_DBG << fname << "Entered";
}

DockerProcess::~DockerProcess()
{
	const static char fname[] = "DockerProcess::~DockerProcess() ";
	LOG_DBG << fname << "Entered";

	DockerProcess::killgroup();
}

void DockerProcess::killgroup(int timerId)
{
	const static char fname[] = "DockerProcess::killgroup() ";

	// get and clean container id
	std::string containerId = this->containerId();
	this->containerId("");

	// clean docker container
	if (!containerId.empty())
	{
		auto cmd = Utility::stringFormat("docker rm -f %s", containerId.c_str());
		auto proc = std::make_shared<AppProcess>();
		proc->spawnProcess(cmd, "root", "", {}, nullptr);
		if (proc->wait(ACE_Time_Value(3)) <= 0)
		{
			LOG_ERR << fname << "cmd <" << cmd << "> killed due to timeout";
			proc->killgroup();
		}
	}

	if (m_imagePullProc != nullptr && m_imagePullProc->running())
	{
		m_imagePullProc->killgroup();
	}
	// detach manually
	this->detach();
}

int DockerProcess::syncSpawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, std::string stdoutFile)
{
	const static char fname[] = "DockerProcess::syncSpawnProcess() ";

	// always use root user to talk to start docker cli
	killgroup();
	int pid = ACE_INVALID_PID;
	constexpr int dockerCliTimeoutSec = 5;
	std::string containerName = m_containerName;

	// 0. clean old docker container (docker container will left when host restart)
	std::string dockerCommand = Utility::stringFormat("docker rm -f %s", containerName.c_str());
	{
		auto dockerProcess = std::make_shared<AppProcess>();
		dockerProcess->spawnProcess(dockerCommand, "root", "", {}, nullptr, stdoutFile);
		dockerProcess->wait();
	}

	// 1. check docker image
	dockerCommand = Utility::stringFormat("docker inspect -f '{{.Size}}' %s", m_dockerImage.c_str());
	{
		auto dockerProcess = std::make_shared<AppProcess>();
		pid = dockerProcess->spawnProcess(dockerCommand, "root", "", {}, nullptr, stdoutFile, EMPTY_STR_JSON, 0);
		dockerProcess->delayKill(dockerCliTimeoutSec, fname);
		dockerProcess->wait();
		dockerProcess->killgroup();
		m_imagePullProc.reset();
		auto imageSizeStr = Utility::stdStringTrim(dockerProcess->getOutputMsg(0, 10240, true));
		dockerProcess.reset();
		if (!Utility::isNumber(imageSizeStr) || std::stoi(imageSizeStr) < 1)
		{
			LOG_WAR << fname << "docker image <" << m_dockerImage << "> not exist, try to pull.";
			startError(Utility::stringFormat("docker image <%s> not exist, try to pull.", m_dockerImage.c_str()));

			// pull docker image
			return this->execPullDockerImage(envMap, m_dockerImage, stdoutFile, workDir);
		}
	}

	// 2. build docker start command line
	dockerCommand = Utility::stringFormat("docker run -d --name %s ", containerName.c_str());
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
			bool containSpace = (env.second.find(' ') != env.second.npos);

			dockerCommand += " -e ";
			dockerCommand += env.first;
			dockerCommand += "=";
			if (containSpace)
				dockerCommand.append("'");
			dockerCommand += env.second;
			if (containSpace)
				dockerCommand.append("'");
		}
	}
	// TODO: should match with format from ShellAppFileGen::ShellAppFileGen
	if (Utility::startWith(cmd, "sh -l "))
	{
		auto scriptFileName = Utility::stdStringTrim(cmd.substr(strlen("sh -l")));
		scriptFileName = Utility::stdStringTrim(scriptFileName, '\'');
		if (Utility::isFileExist(scriptFileName))
		{
			// mount shell mode script to container
			dockerCommand.append(" -v ").append(scriptFileName).append(":").append(scriptFileName);
		}
	}
	if (limit != nullptr)
	{
		if (limit->m_memoryMb)
		{
			dockerCommand.append(" --memory ").append(std::to_string(limit->m_memoryMb)).append("M");
			if (limit->m_memoryVirtMb && limit->m_memoryVirtMb > limit->m_memoryMb)
			{
				dockerCommand.append(" --memory-swap ").append(std::to_string(limit->m_memoryVirtMb - limit->m_memoryMb)).append("M");
			}
		}
		if (limit->m_cpuShares)
		{
			dockerCommand.append(" --cpu-shares ").append(std::to_string(limit->m_cpuShares));
		}
	}
	// Docker container does not restrict container user
	//if (!execUser.empty()) dockerCommand.append(" --user ").append(execUser);
	dockerCommand += " " + m_dockerImage;
	dockerCommand += " " + cmd;
	LOG_DBG << fname << "dockerCommand: " << dockerCommand;

	// 3. start docker container
	bool startSuccess = false;
	std::string containerId;
	{
		auto dockerProcess = std::make_shared<AppProcess>();
		pid = dockerProcess->spawnProcess(dockerCommand, "root", "", {}, nullptr, stdoutFile);
		dockerProcess->delayKill(dockerCliTimeoutSec, fname);
		dockerProcess->wait();
		dockerProcess->killgroup();
		if (dockerProcess->returnValue() == 0)
		{
			const auto outmsg = dockerProcess->getOutputMsg(0, 10240, true);
			containerId = Utility::stdStringTrim(outmsg);
			startSuccess = (containerId.length() > 0);
			if (!startSuccess)
			{
				startError(Utility::stringFormat("failed get docker container <%s> from output <%s>", dockerCommand.c_str(), outmsg.c_str()));
			}
		}
		else
		{
			const auto outmsg = dockerProcess->getOutputMsg(0, 10240, false);
			LOG_WAR << fname << "started container <" << dockerCommand << "failed :" << outmsg;
			startError(Utility::stringFormat("started docker container <%s> failed with error <%s>", dockerCommand.c_str(), outmsg.c_str()));
		}
		dockerProcess->killgroup();
		// set container id here for future clean
		this->containerId(containerId);
	}

	// 4. get docker root pid
	if (startSuccess)
	{
		dockerCommand = Utility::stringFormat("docker inspect -f '{{.State.Pid}}' %s", containerId.c_str());
		auto dockerProcess = std::make_shared<AppProcess>();
		pid = dockerProcess->spawnProcess(dockerCommand, "root", "", {}, nullptr, stdoutFile, EMPTY_STR_JSON, 0);
		dockerProcess->delayKill(dockerCliTimeoutSec, fname);
		dockerProcess->wait();
		if (dockerProcess->returnValue() == 0)
		{
			auto pidStr = Utility::stdStringTrim(dockerProcess->getOutputMsg(0, 10240, true));
			if (Utility::isNumber(pidStr))
			{
				pid = std::stoi(pidStr);
				if (pid > 1)
				{
					// Success
					this->attach(pid);
					this->containerId(containerId);
					LOG_INF << fname << "started pid <" << pid << "> for container :" << containerId;
					//startError("");
					return this->getpid();
				}
				else
				{
					startError(Utility::stringFormat("failed get docker container pid <%s> from output <%s>", dockerCommand.c_str(), pidStr.c_str()));
				}
			}
			else
			{
				LOG_WAR << fname << "can not get correct container pid :" << pidStr;
				startError(Utility::stringFormat("failed get docker container pid <%s> from output <%s>", dockerCommand.c_str(), pidStr.c_str()));
			}
		}
		else
		{
			const auto output = dockerProcess->getOutputMsg(0, 10240, false);
			LOG_WAR << fname << "started container <" << dockerCommand << "failed :" << output;
			startError(Utility::stringFormat("start docker container <%s> failed <%s>", dockerCommand.c_str(), output.c_str()));
		}
		dockerProcess->killgroup();
	}

	// failed
	this->containerId(containerId);
	this->detach();
	killgroup();
	return this->getpid();
}

int DockerProcess::execPullDockerImage(std::map<std::string, std::string> &envMap, const std::string &dockerImage, const std::string &stdoutFile, const std::string &workDir)
{
	const static char fname[] = "DockerProcess::execPullDockerImage() ";

	int pullTimeout = 5 * 60; //set default image pull timeout to 5 minutes
	if (envMap.count(ENV_APP_MANAGER_DOCKER_IMG_PULL_TIMEOUT) && Utility::isNumber(envMap[ENV_APP_MANAGER_DOCKER_IMG_PULL_TIMEOUT]))
	{
		pullTimeout = std::stoi(envMap[ENV_APP_MANAGER_DOCKER_IMG_PULL_TIMEOUT]);
	}
	else
	{
		LOG_WAR << fname << "use default APP_MANAGER_DOCKER_IMG_PULL_TIMEOUT <" << pullTimeout << ">";
	}
	m_imagePullProc = std::make_shared<AppProcess>();
	m_imagePullProc->spawnProcess("docker pull " + dockerImage, "root", workDir, {}, nullptr, stdoutFile, EMPTY_STR_JSON, 0);
	m_imagePullProc->delayKill(pullTimeout, fname);
	this->attach(m_imagePullProc->getpid());
	return this->getpid();
}

pid_t DockerProcess::getpid(void) const
{
	if (ACE_Process::getpid() == 1)
		return ACE_INVALID_PID;
	else
		return ACE_Process::getpid();
}

std::string DockerProcess::containerId() const
{
	std::lock_guard<std::recursive_mutex> guard(m_processMutex);
	return m_containerId;
}

void DockerProcess::containerId(const std::string &containerId)
{
	std::lock_guard<std::recursive_mutex> guard(m_processMutex);
	m_containerId = containerId;
}

int DockerProcess::returnValue(void) const
{
	const static char fname[] = "DockerProcess::returnValue() ";

	auto dockerCommand = Utility::stringFormat("docker inspect %s --format='{{.State.ExitCode}}'", m_containerId.c_str());
	auto dockerProcess = std::make_shared<AppProcess>();
	dockerProcess->spawnProcess(dockerCommand, "root", "", {}, nullptr, m_containerId);
	dockerProcess->wait();
	if (dockerProcess->returnValue() == 0)
	{
		auto msg = dockerProcess->getOutputMsg(0, 512, true);
		if (Utility::isNumber(msg))
		{
			return std::atoi(msg.c_str());
		}
		else
		{
			LOG_WAR << fname << "docker inspect exit code from container " << m_containerId << " failed with output: " << msg;
		}
	}
	else
	{
		LOG_WAR << fname << "docker inspect exit code from container " << m_containerId << " failed with exit code: " << dockerProcess->returnValue();
	}
	return -200;
}

int DockerProcess::spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile, const web::json::value &stdinFileContent, const int maxStdoutSize)
{
	const static char fname[] = "DockerProcess::spawnProcess() ";
	LOG_DBG << fname << "Entered";
	return syncSpawnProcess(cmd, execUser, workDir, envMap, limit, stdoutFile);
}

const std::string DockerProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	std::lock_guard<std::recursive_mutex> guard(m_processMutex);
	if (m_containerId.length())
	{
		// --since: RFC3339 OR UNIX timestamp
		auto secondsUTC = 0L;
		if (position)
			secondsUTC = *position;
		auto dockerCommand = Utility::stringFormat("docker logs --since %llu %s", secondsUTC, m_containerId.c_str());
		auto dockerProcess = std::make_shared<AppProcess>();
		dockerProcess->spawnProcess(dockerCommand, "root", "", {}, nullptr, m_containerId);
		dockerProcess->wait();
		auto msg = dockerProcess->getOutputMsg(0, maxSize, readLine);
		if (position)
		{
			*position = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		}
		return msg;
	}
	return std::string();
}