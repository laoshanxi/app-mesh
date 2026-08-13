// src/daemon/process/DockerProcess.cpp
#include "DockerProcess.h"

#include <chrono>
#include <sstream>
#include <utility>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../ResourceLimitation.h"

namespace
{
	const char *const CONTAINER_DOCKER = "docker";
	const char *const CONTAINER_PODMAN = "podman";
	constexpr int DOCKER_CLI_TIMEOUT_SEC = 5;
	constexpr int DOCKER_COMMAND_ERROR = -200;

	struct DockerCommandResult
	{
		bool started = false;
		bool completed = false;
		int exitCode = DOCKER_COMMAND_ERROR;
		std::string output;
		std::string error;
	};

	template <typename Integer>
	bool parseInteger(const std::string &text, Integer &value)
	{
		if (text.empty())
			return false;

		Integer parsed{};
		std::istringstream input(text);
		input >> std::noskipws >> parsed;
		if (input.fail() || !input.eof())
			return false;

		value = parsed;
		return true;
	}

	DockerCommandResult runDockerCli(const std::string &command, int timeoutSeconds = DOCKER_CLI_TIMEOUT_SEC,
									 int maxOutput = 10240, bool readLine = false)
	{
		DockerCommandResult result;
		const auto outputFile = (fs::path(Configuration::instance()->getWorkDir()) / APPMESH_WORK_TMP_DIR /
								 ("docker." + Utility::shortID() + ".out"))
									.string();
		{
			auto process = std::make_shared<AppProcess>(std::weak_ptr<Application>());
			const auto start = process->start(command, "root", "", {}, nullptr, outputFile, EMPTY_STR_JSON, 0);
			result.started = start.accepted;
			result.error = start.error;
			if (result.started)
			{
				process->scheduleTermination(timeoutSeconds, "runDockerCli");
				result.completed = process->wait(ACE_Time_Value(timeoutSeconds + 1)) > 0;
				if (!result.completed)
				{
					process->terminate();
					process->wait(ACE_Time_Value(1));
					result.error = "docker command timed out";
				}
				else
				{
					result.exitCode = process->returnValue();
					result.output = process->getOutputMsg(nullptr, maxOutput, readLine);
				}
			}
		}
		Utility::removeFile(outputFile);
		return result;
	}

	void launchDockerCleanup(const std::string &command)
	{
		const static char fname[] = "launchDockerCleanup() ";
		auto process = std::make_shared<AppProcess>(std::weak_ptr<Application>());
		const auto start = process->start(command, "root", "", {}, nullptr, "", EMPTY_STR_JSON, 0);
		if (!start.accepted)
		{
			LOG_ERR << fname << "failed to launch <" << command << ">: " << start.error;
			return;
		}

		// The termination timer owns the helper until it exits or reaches the timeout.
		// Cleanup is best effort, so the caller never waits for Docker CLI completion.
		process->scheduleTermination(3, fname);
	}
}

DockerProcess::DockerProcess(std::weak_ptr<Application> owner, const std::string &containerName, const std::string &dockerImage)
	: AppProcess(std::move(owner)), m_containerName(containerName), m_dockerImage(dockerImage), m_containerEngine(CONTAINER_DOCKER)
{
	const static char fname[] = "DockerProcess::DockerProcess() ";
	LOG_DBG << fname << "Entered";
}

DockerProcess::~DockerProcess()
{
	const static char fname[] = "DockerProcess::~DockerProcess() ";
	LOG_DBG << fname << "Entered";

	// Destruction has no shared owner; skip lifecycle callbacks.
	DockerProcess::terminateImpl();
}

void DockerProcess::terminateImpl()
{
	std::string containerId;
	std::string containerEngine;
	{
		std::lock_guard<std::mutex> guard(m_dockerMutex);
		containerId = std::move(m_containerId);
		m_containerId.clear();
		containerEngine = m_containerEngine;
	}
	if (containerId.empty())
	{
		// Image pulls are native child processes owned by this instance.
		AppProcess::terminateImpl();
		return;
	}

	// Clean docker container
	auto cmd = Utility::stringFormat("%s rm -f %s", containerEngine.c_str(), containerId.c_str());
	launchDockerCleanup(cmd);

	// Detach manually
	this->detach();
}

pid_t DockerProcess::startContainer(const std::string &cmd, const std::string &workDir,
									const std::map<std::string, std::string> &envMap,
									const std::shared_ptr<ResourceLimitation> &limit, const std::string &stdoutFile)
{
	const static char fname[] = "DockerProcess::startContainer() ";

	std::string containerEngine;
	{
		std::lock_guard<std::mutex> guard(m_dockerMutex);
		containerEngine = m_containerEngine;
	}

	// Step 0: Clean old docker container (containers may remain after host restart)
	std::string dockerCommand = Utility::stringFormat("%s rm -f %s", containerEngine.c_str(), m_containerName.c_str());
	runDockerCli(dockerCommand); // Best effort: docker run reports a name conflict if cleanup failed.

	// Step 1: Check if docker image exists
	dockerCommand = Utility::stringFormat("%s image inspect -f '{{.Size}}' %s", containerEngine.c_str(), m_dockerImage.c_str());
	{
		const auto imageInspect = runDockerCli(dockerCommand);
		if (!imageInspect.started)
		{
			setStartError(imageInspect.error.empty() ? "failed to launch docker image inspect" : imageInspect.error);
			return ACE_INVALID_PID;
		}
		if (!imageInspect.completed)
		{
			setStartError(imageInspect.error);
			return ACE_INVALID_PID;
		}
		auto imageSizeStr = Utility::stdStringTrim(imageInspect.output);
		int64_t imageSize = 0;
		if (imageInspect.exitCode != 0 || !parseInteger(imageSizeStr, imageSize) || imageSize < 1)
		{
			LOG_WAR << fname << "docker image <" << m_dockerImage << "> does not exist, trying to pull";
			return startImagePull(envMap, m_dockerImage, workDir, stdoutFile);
		}
	}

	// Step 2: Build docker start command line
	dockerCommand = Utility::stringFormat("%s run -d --name %s ", containerEngine.c_str(), m_containerName.c_str());

	for (const auto &env : envMap)
	{
		if (env.first == ENV_APPMESH_DOCKER_PARAMS)
		{
			// Used for -p -v parameters
			dockerCommand.append(" ").append(env.second);
		}
		else
		{
			const bool containSpace = (env.second.find(' ') != env.second.npos);
			dockerCommand.append(" -e ").append(env.first).append("=");
			if (containSpace)
				dockerCommand.append("'");
			dockerCommand.append(env.second);
			if (containSpace)
				dockerCommand.append("'");
		}
	}

	// Mount shell mode script to container if needed
	if (Utility::startWith(cmd, "sh -l "))
	{
		auto scriptFileName = Utility::stdStringTrim(cmd.substr(strlen("sh -l")));
		scriptFileName = Utility::stdStringTrim(scriptFileName, '\'');
		if (Utility::isFileExist(scriptFileName))
		{
			dockerCommand.append(" -v ").append(scriptFileName).append(":").append(scriptFileName);
		}
	}

	// Apply resource limitations
	if (limit)
	{
		if (limit->m_memoryMb)
		{
			dockerCommand.append(" --memory ").append(std::to_string(limit->m_memoryMb)).append("M");
			if (limit->m_memoryVirtSpecified)
			{
				dockerCommand.append(" --memory-swap ").append(std::to_string(limit->m_memoryVirtMb)).append("M");
			}
		}
		if (limit->m_cpuShares)
		{
			dockerCommand.append(" --cpu-shares ").append(std::to_string(limit->m_cpuShares));
		}
	}

	// Docker container does not restrict container user
	dockerCommand.append(" ").append(m_dockerImage).append(" ").append(cmd);
	LOG_DBG << fname << "dockerCommand: " << dockerCommand;

	// Step 3: Start docker container
	bool startSuccess = false;
	std::string containerId;
	{
		const auto run = runDockerCli(dockerCommand);
		if (!run.started)
		{
			setStartError(run.error.empty() ? "failed to launch docker run command" : run.error);
		}
		else if (!run.completed)
		{
			setStartError(run.error);
		}
		else if (run.exitCode == 0)
		{
			containerId = Utility::stdStringTrim(run.output);
			startSuccess = !containerId.empty();
			if (!startSuccess)
				setStartError(Utility::stringFormat("failed get docker container <%s> from output <%s>", dockerCommand.c_str(), run.output.c_str()));
		}
		else
		{
			LOG_WAR << fname << "start container command <" << dockerCommand << "> failed: " << run.output;
			setStartError(Utility::stringFormat("started docker container <%s> failed with error <%s>", dockerCommand.c_str(), run.output.c_str()));
		}

		// Set container id here for future cleanup
		setContainerId(containerId);
	}

	// Step 4: Get docker root pid
	if (startSuccess)
	{
		dockerCommand = Utility::stringFormat(
			"%s inspect -f '{{.State.Pid}} {{.State.Running}} {{.State.ExitCode}}' %s",
			containerEngine.c_str(), containerId.c_str());
		const auto inspect = runDockerCli(dockerCommand);
		if (!inspect.started)
		{
			setStartError(inspect.error.empty() ? "failed to launch docker inspect command" : inspect.error);
			setContainerId(containerId);
			terminate();
			return ACE_INVALID_PID;
		}
		if (!inspect.completed)
		{
			setStartError(inspect.error);
			setContainerId(containerId);
			terminate();
			return ACE_INVALID_PID;
		}

		if (inspect.exitCode == 0)
		{
			const auto stateText = Utility::stdStringTrim(inspect.output);
			std::istringstream stateStream(stateText);
			int hostPid = 0;
			int exitCode = DOCKER_COMMAND_ERROR;
			std::string runningText;
			if (stateStream >> hostPid >> runningText >> exitCode)
			{
				if (runningText == "false")
				{
					setContainerId(containerId);
					LOG_INF << fname << "container <" << containerId
							<< "> completed before host PID inspection, exit code <" << exitCode << ">";
					reportEarlyExit(exitCode);
					return ACE_INVALID_PID;
				}
				if (runningText == "true" && hostPid > 1)
				{
					this->attach(hostPid);
					setContainerId(containerId);
					LOG_INF << fname << "started pid <" << hostPid << "> for container: " << containerId;
					return this->getpid();
				}
				setStartError(Utility::stringFormat("container running without valid host pid, inspect output <%s>", stateText.c_str()));
			}
			else
			{
				LOG_WAR << fname << "failed to parse container state from output <" << stateText << ">";
				setStartError(Utility::stringFormat("failed get docker container state <%s> from output <%s>", dockerCommand.c_str(), stateText.c_str()));
			}
		}
		else
		{
			LOG_WAR << fname << "inspect container pid command <" << dockerCommand << "> failed: " << inspect.output;
			setStartError(Utility::stringFormat("start docker container <%s> failed <%s>", dockerCommand.c_str(), inspect.output.c_str()));
		}
	}

	// Failed
	setContainerId(containerId);
	this->detach();
	terminate();
	return this->getpid();
}

pid_t DockerProcess::startImagePull(const std::map<std::string, std::string> &envMap, const std::string &dockerImage,
									std::string workDir, const std::string &stdoutFile)
{
	const static char fname[] = "DockerProcess::startImagePull() ";

	int pullTimeout = 5 * 60; // Default image pull timeout: 5 minutes
	const auto timeoutSetting = envMap.find(ENV_APPMESH_DOCKER_IMG_PULL_TIMEOUT);
	int configuredTimeout = 0;
	if (timeoutSetting != envMap.end() && parseInteger(timeoutSetting->second, configuredTimeout) && configuredTimeout > 0)
	{
		pullTimeout = configuredTimeout;
	}
	else
	{
		LOG_DBG << fname << "image pull timeout not configured, using default <" << pullTimeout << "> seconds";
	}

	std::string containerEngine;
	{
		std::lock_guard<std::mutex> guard(m_dockerMutex);
		containerEngine = m_containerEngine;
	}
	const pid_t pid = AppProcess::startImpl(
		containerEngine + " pull " + dockerImage, "root", std::move(workDir), {}, nullptr,
		stdoutFile, EMPTY_STR_JSON, 0);
	if (pid > 1)
		scheduleTermination(pullTimeout, fname);
	return pid;
}

pid_t DockerProcess::getpid() const
{
	// Return invalid PID if process ID is 1 (init/systemd)
	if (AppProcess::getpid() == 1)
	{
		return ACE_INVALID_PID;
	}
	return AppProcess::getpid();
}

std::string DockerProcess::containerId() const
{
	std::lock_guard<std::mutex> guard(m_dockerMutex);
	return m_containerId;
}

void DockerProcess::setContainerId(const std::string &containerId)
{
	std::lock_guard<std::mutex> guard(m_dockerMutex);
	m_containerId = containerId;
}

std::string DockerProcess::takeContainerId()
{
	std::lock_guard<std::mutex> guard(m_dockerMutex);
	auto containerId = std::move(m_containerId);
	m_containerId.clear();
	return containerId;
}

int DockerProcess::returnValue() const
{
	const static char fname[] = "DockerProcess::returnValue() ";

	std::string containerId;
	std::string containerEngine;
	{
		std::lock_guard<std::mutex> guard(m_dockerMutex);
		containerId = m_containerId;
		containerEngine = m_containerEngine;
	}
	if (containerId.empty())
		return AppProcess::returnValue();
	auto dockerCommand = Utility::stringFormat("%s inspect %s --format='{{.State.ExitCode}}'", containerEngine.c_str(), containerId.c_str());
	const auto inspect = runDockerCli(dockerCommand, DOCKER_CLI_TIMEOUT_SEC, 512, true);
	if (!inspect.started)
	{
		LOG_WAR << fname << "failed to launch docker inspect: " << inspect.error;
		return DOCKER_COMMAND_ERROR;
	}
	if (!inspect.completed)
	{
		LOG_WAR << fname << "docker inspect timed out for container <" << containerId << ">";
		return DOCKER_COMMAND_ERROR;
	}

	if (inspect.exitCode == 0)
	{
		int exitCode = 0;
		if (parseInteger(Utility::stdStringTrim(inspect.output), exitCode))
			return exitCode;
		LOG_WAR << fname << "docker inspect exit code from container <" << containerId << "> failed with output: " << inspect.output;
	}
	else
	{
		LOG_WAR << fname << "docker inspect exit code from container <" << containerId << "> failed with exit code: " << inspect.exitCode;
	}

	return DOCKER_COMMAND_ERROR;
}

pid_t DockerProcess::startImpl(std::string cmd, std::string execUser, std::string workDir,
							   std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							   const std::string &stdoutFile, const nlohmann::json &stdinFileContent, int maxStdoutSize)
{
	const static char fname[] = "DockerProcess::startImpl() ";
	LOG_DBG << fname << "Entered";

	// Check for podman engine
	if (CONTAINER_PODMAN == GET_JSON_STR_VALUE(stdinFileContent, "engine"))
	{
		std::lock_guard<std::mutex> guard(m_dockerMutex);
		m_containerEngine = CONTAINER_PODMAN;
	}

	return startContainer(cmd, workDir, envMap, limit, stdoutFile);
}

const std::string DockerProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	const static char fname[] = "DockerProcess::getOutputMsg() ";
	std::string containerId;
	std::string containerEngine;
	{
		std::lock_guard<std::mutex> guard(m_dockerMutex);
		containerId = m_containerId;
		containerEngine = m_containerEngine;
	}

	if (!containerId.empty())
	{
		// Get logs since timestamp (RFC3339 or UNIX timestamp)
		auto secondsUTC = 0L;
		if (position)
		{
			secondsUTC = *position;
		}

		auto dockerCommand = Utility::stringFormat("%s logs --since %ld %s", containerEngine.c_str(), secondsUTC, containerId.c_str());
		const auto logs = runDockerCli(dockerCommand, DOCKER_CLI_TIMEOUT_SEC, maxSize, readLine);
		if (!logs.started)
		{
			LOG_WAR << fname << "failed to launch docker logs: " << logs.error;
			return {};
		}
		if (!logs.completed)
		{
			LOG_WAR << fname << "docker logs timed out for container <" << containerId << ">";
			return {};
		}

		if (position)
		{
			*position = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		}
		return logs.output;
	}

	return AppProcess::getOutputMsg(position, maxSize, readLine);
}
