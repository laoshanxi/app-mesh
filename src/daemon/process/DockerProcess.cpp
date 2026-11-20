// src/daemon/process/DockerProcess.cpp
#include "DockerProcess.h"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <fstream>
#include <chrono>
#include <optional>
#include <utility>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../ResourceLimitation.h"
#include "../application/Application.h"

namespace
{
	const char *const CONTAINER_DOCKER = "docker";
	const char *const CONTAINER_PODMAN = "podman";
	constexpr int DOCKER_CLI_TIMEOUT_SEC = 5;

	struct DockerCommandResult
	{
		bool started = false;
		bool completed = false;
		int exitCode = DOCKER_COMMAND_ERROR;
		std::string output;
		std::string error;
	};

	template <typename Integer> std::optional<Integer> parseInteger(const std::string &text)
	{
		if (text.empty())
			return std::nullopt;

		Integer parsed{};
		const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
		if (result.ec != std::errc{} || result.ptr != text.data() + text.size())
			return std::nullopt;

		return parsed;
	}

	std::string upperCase(std::string text)
	{
		std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::toupper(c)); });
		return text;
	}

	std::string lowerCase(std::string text)
	{
		std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		return text;
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
				result.completed = process->wait(std::chrono::seconds(timeoutSeconds + 1)) > 0;
				if (!result.completed)
				{
					process->terminate();
					process->wait(std::chrono::seconds(1));
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

	void launchDockerCleanup(const std::string &command, std::size_t timeoutSeconds = 3)
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
		process->scheduleTermination(timeoutSeconds, fname);
	}
}

// High-risk host-facing settings the Docker.HostSecurityPolicy gate looks for.
std::vector<std::string> dockerHostSecurityFindings(const Json::Value &createBody)
{
	std::vector<std::string> findings;
	if (!createBody.isObject())
		return findings;
	const auto &hostConfig = createBody["HostConfig"];
	if (!hostConfig.isObject())
		return findings;
	if (hostConfig["Privileged"].isBool() && hostConfig["Privileged"].asBool())
		findings.push_back("privileged container");
	const auto pidMode = upperCase(GET_JSON_STR_VALUE(hostConfig, "PidMode"));
	if (pidMode == "HOST")
		findings.push_back("host PID namespace (pid=host)");
	const auto ipcMode = upperCase(GET_JSON_STR_VALUE(hostConfig, "IpcMode"));
	if (ipcMode == "HOST" || ipcMode == "SHAREABLE")
		findings.push_back("shared host IPC namespace (ipc=" + lowerCase(ipcMode) + ")");
	// docker network semantics: host/none/container:<id> bypass the bridge.
	const auto networkMode = lowerCase(GET_JSON_STR_VALUE(hostConfig, "NetworkMode"));
	if (networkMode == "host")
		findings.push_back("host network namespace (network=host)");
	// Binds and Mounts are two spellings of the same host-path exposure; normalize so '//' and '/./' cannot disguise '/'.
	const auto riskyBindSource = [](std::string source)
	{
		std::string normalized;
		for (size_t i = 0; i < source.size(); i++)
		{
			if (source[i] == '/' && !normalized.empty() && normalized.back() == '/')
				continue;
			normalized += source[i];
		}
		// Collapse '/./' segments and a trailing '/.'.
		const auto dotSlash = normalized.find("/./");
		if (dotSlash != std::string::npos)
			normalized = normalized.substr(0, dotSlash) + normalized.substr(dotSlash + 2);
		if (Utility::endWith(normalized, "/."))
			normalized.resize(normalized.size() - 2);
		return normalized == "/" || normalized == "/var/run" || normalized == "/run" ||
			   Utility::endWith(normalized, "/docker.sock");
	};
	if (hostConfig["Binds"].isArray())
	{
		for (const auto &bind : hostConfig["Binds"])
		{
			if (!bind.isString())
				continue;
			const auto source = bind.asString().substr(0, bind.asString().find(':'));
			if (riskyBindSource(source))
				findings.push_back("bind of host path <" + source + ">");
		}
	}
	if (hostConfig["Mounts"].isArray())
	{
		for (const auto &mount : hostConfig["Mounts"])
		{
			// Read-only mounts still expose host content; every bind type counts.
			if (!mount.isObject() || lowerCase(GET_JSON_STR_VALUE(mount, "Type")) != "bind")
				continue;
			const auto source = GET_JSON_STR_VALUE(mount, "Source");
			if (riskyBindSource(source))
				findings.push_back("Mount of host path <" + source + ">");
		}
	}
	// Volumes-from or raw host-device mapping is a host-facing capability by construction.
	if (hostConfig["VolumesFrom"].isArray() && hostConfig["VolumesFrom"].size() > 0)
		findings.push_back("volumes inherited from another container (volumes-from)");
	if (hostConfig["Devices"].isArray() && hostConfig["Devices"].size() > 0)
		findings.push_back("host device mapping (device)");
	if (hostConfig["SecurityOpt"].isArray())
	{
		for (const auto &opt : hostConfig["SecurityOpt"])
		{
			// apparmor/seccomp/systempaths "unconfined" and label disabling are the profile-escape spellings.
			if (opt.isString())
			{
				const auto text = lowerCase(opt.asString());
				if (text.find("unconfined") != std::string::npos || text.find("label=disable") == 0 ||
					text.find("label:disable") != std::string::npos)
					findings.push_back("security opt <" + opt.asString() + ">");
			}
		}
	}
	if (hostConfig["CapAdd"].isArray())
	{
		for (const auto &cap : hostConfig["CapAdd"])
		{
			if (!cap.isString())
				continue;
			const auto name = upperCase(cap.asString());
			if (name == "ALL" || name == "SYS_ADMIN" || name == "SYS_PTRACE")
				findings.push_back("CapAdd " + cap.asString());
		}
	}
	return findings;
}

// Namespaced so an App Mesh container can never collide with an operator container.
std::string DockerProcess::namespacedContainerName(const std::string &appName)
{
	return std::string("appmesh-").append(appName);
}

// SIGTERM grace before SIGKILL, docker's own default when the app sets none.
int DockerProcess::stopGraceSeconds() const
{
	if (const auto ownerApplication = owner().lock())
	{
		const auto grace = ownerApplication->stopGraceSeconds();
		if (grace > 0)
			return grace;
	}
	return 10;
}

DockerProcess::DockerProcess(std::weak_ptr<Application> owner, const std::string &containerName,
							 const std::string &dockerImage)
	: AppProcess(std::move(owner)), m_containerName(containerName), m_dockerImage(dockerImage),
	  m_containerEngine(CONTAINER_DOCKER),
	  // A namespaced name implies its pre-namespacing original; anything else
	  // (direct constructions) keeps the name itself, a harmless duplicate.
	  m_legacyContainerName(containerName.rfind("appmesh-", 0) == 0 ? containerName.substr(strlen("appmesh-"))
																	: containerName)
{
	const static char fname[] = "DockerProcess::DockerProcess() ";
	LOG_DBG << fname << "Entered";
}

DockerProcess::~DockerProcess()
{
	const static char fname[] = "DockerProcess::~DockerProcess() ";
	LOG_DBG << fname << "Entered";

	// Destructors must not throw: cleanup is best-effort during teardown.
	try
	{
		// Destruction has no shared owner; skip lifecycle callbacks.
		DockerProcess::terminateImpl();
	}
	catch (...)
	{
	}
}

void DockerProcess::terminateImpl()
{
	std::string containerId;
	std::string containerEngine;
	{
		std::lock_guard guard(m_dockerMutex);
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

	// SIGTERM grace first: docker stop returns as soon as the container exits,
	// so the grace is only the upper bound of this bounded synchronous call.
	const auto grace = stopGraceSeconds();
	auto cmd = Utility::stringFormat("%s stop -t %d %s", containerEngine.c_str(), grace, containerId.c_str());
	const auto stopResult = runDockerCli(cmd, grace + 5);
	if (!stopResult.started || !stopResult.completed || stopResult.exitCode != 0)
	{
		LOG_WAR << "DockerProcess::terminateImpl() graceful stop of container <" << containerId
				<< "> failed: " << stopResult.error;
	}

	// Persist the container's final logs before the delete removes them.
	archiveContainerLogs(containerId);

	// Clean docker container
	cmd = Utility::stringFormat("%s rm -f %s", containerEngine.c_str(), containerId.c_str());
	launchDockerCleanup(cmd);

	// Detach manually
	this->detach();
}

pid_t DockerProcess::startContainer(const std::string &cmd, const std::string &execUser, const std::string &workDir,
									const std::map<std::string, std::string> &envMap,
									const std::shared_ptr<ResourceLimitation> &limit, const std::string &stdoutFile,
									const Json::Value &createBody)
{
	const static char fname[] = "DockerProcess::startContainer() ";

	std::string containerEngine;
	{
		std::lock_guard guard(m_dockerMutex);
		containerEngine = m_containerEngine;
	}

	// Step 0: Clean this app's own leftover containers after a restart; only ownership-labeled ones are removed,
	// so a foreign occupant of the name stays untouched and docker run fails loudly with the name conflict.
	for (const auto &candidate : std::vector<std::string>{m_containerName, m_legacyContainerName})
	{
		const auto owned = runDockerCli(Utility::stringFormat("%s ps -aq --filter name=^/%s$ --filter label=%s=true --filter label=%s=%s",
															  containerEngine.c_str(), candidate.c_str(), DOCKER_LABEL_MANAGED,
															  DOCKER_LABEL_APP, m_legacyContainerName.c_str()));
		const auto ownedIds = Utility::stdStringTrim(owned.output);
		if ((owned.started && owned.completed && owned.exitCode == 0) && !ownedIds.empty())
		{
			launchDockerCleanup(Utility::stringFormat("%s rm -f %s", containerEngine.c_str(), ownedIds.c_str()));
		}
	}

	// Step 1: Check if docker image exists
	std::string dockerCommand =
		Utility::stringFormat("%s image inspect -f '{{.Size}}' %s", containerEngine.c_str(), m_dockerImage.c_str());
	{
		const auto imageInspect = runDockerCli(dockerCommand);
		if (!imageInspect.started)
		{
			setStartError(imageInspect.error.empty() ? "failed to launch docker image inspect" : imageInspect.error);
			return INVALID_PID;
		}
		if (!imageInspect.completed)
		{
			setStartError(imageInspect.error);
			return INVALID_PID;
		}
		const auto imageSizeStr = Utility::stdStringTrim(imageInspect.output);
		const auto imageSize = parseInteger<int64_t>(imageSizeStr);
		if (imageInspect.exitCode != 0 || !imageSize || *imageSize < 1)
		{
			LOG_WAR << fname << "docker image <" << m_dockerImage << "> does not exist, trying to pull";
			return startImagePull(envMap, m_dockerImage, workDir, stdoutFile);
		}
	}

	// Step 2: Build docker start command line
	dockerCommand = Utility::stringFormat("%s run -d --name %s --label %s=true --label %s=%s ", containerEngine.c_str(),
										  m_containerName.c_str(), DOCKER_LABEL_MANAGED, DOCKER_LABEL_APP,
										  m_legacyContainerName.c_str());

	for (const auto &[key, value] : envMap)
	{
		if (key == ENV_APPMESH_DOCKER_PARAMS)
		{
			// Used for -p -v parameters; selects this CLI backend and is appended
			// verbatim, so point operators at the structured alternative.
			LOG_WAR << fname << ENV_APPMESH_DOCKER_PARAMS
					<< " is appended verbatim to `docker run`; prefer the docker_ports/docker_volumes fields";
			dockerCommand.append(" ").append(value);
		}
		else if (key == ENV_APPMESH_DOCKER_REGISTRY_SERVER || key == ENV_APPMESH_DOCKER_REGISTRY_USER ||
				 key == ENV_APPMESH_DOCKER_REGISTRY_PASSWORD)
		{
			// Daemon-side registry credentials never reach the container.
			continue;
		}
		else
		{
			// The daemon spawns without a shell: str2argv keeps quote-protected
			// text as one token, so the quotes must wrap the whole value.
			dockerCommand.append(" -e ").append(key).append("='").append(value).append("'");
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

	// Container user follows the application's execution_user; an explicit
	// metadata User still wins (same rule as the API backend).
	{
		const auto containerUser = createBody.isObject() ? GET_JSON_STR_VALUE(createBody, "User") : std::string();
		if (!containerUser.empty())
			dockerCommand.append(" --user '").append(containerUser).append("'");
		else if (execUser.length())
			dockerCommand.append(" --user '").append(execUser).append("'");
	}

	// First-class wiring compiled by the application into HostConfig; translated
	// back to their docker run spellings here.
	if (createBody.isObject() && createBody["HostConfig"].isObject())
	{
		const auto &hostConfig = createBody["HostConfig"];
		if (hostConfig["PortBindings"].isObject())
		{
			for (const auto &containerPort : hostConfig["PortBindings"].getMemberNames())
			{
				for (const auto &binding : hostConfig["PortBindings"][containerPort])
				{
					dockerCommand.append(" -p ");
					if (HAS_JSON_FIELD(binding, "HostIp") && binding["HostIp"].isString() && binding["HostIp"].asString().length())
						dockerCommand.append(binding["HostIp"].asString()).append(":");
					dockerCommand.append(GET_JSON_STR_VALUE(binding, "HostPort")).append(":").append(containerPort);
				}
			}
		}
		if (hostConfig["Binds"].isArray())
		{
			for (const auto &bind : hostConfig["Binds"])
			{
				if (bind.isString() && bind.asString().length())
					dockerCommand.append(" -v '").append(bind.asString()).append("'");
			}
		}
		const auto networkMode = GET_JSON_STR_VALUE(hostConfig, "NetworkMode");
		if (networkMode.length())
			dockerCommand.append(" --network '").append(networkMode).append("'");
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
		if (limit->m_cpuCores > 0)
		{
			// --cpus takes fractional cores; clamp up so a tiny value never formats to "0.00" (docker rejects it)
			const auto cpus = std::max(limit->m_cpuCores, 0.01);
			dockerCommand.append(" --cpus ").append(Utility::stringFormat("%.2f", cpus));
		}
	}

	// Docker container does not restrict container user
	dockerCommand.append(" ").append(m_dockerImage).append(" ").append(cmd);
	LOG_DBG << fname << "dockerCommand: " << dockerCommand;

	// The CLI backend reaches the same risks through its HostConfig fields and raw APP_DOCKER_OPTS flags.
	{
		const auto policy = Configuration::instance()->getDockerHostSecurityPolicy();
		if (policy != "off")
		{
			const auto optsIt = envMap.find(ENV_APPMESH_DOCKER_PARAMS);
			const auto opts = optsIt == envMap.end() ? std::string() : optsIt->second;
			std::vector<std::string> hits = dockerHostSecurityFindings(createBody);
			if (opts.find("--privileged") != std::string::npos)
				hits.push_back("privileged container");
			if (opts.find("--pid=host") != std::string::npos || opts.find("--pid host") != std::string::npos)
				hits.push_back("host PID namespace");
			if (opts.find("--network=host") != std::string::npos || opts.find("--network host") != std::string::npos ||
				opts.find("--net=host") != std::string::npos || opts.find("--net host") != std::string::npos)
				hits.push_back("host network namespace");
			if (opts.find("--cap-add") != std::string::npos || opts.find("--device") != std::string::npos ||
				opts.find("--volumes-from") != std::string::npos || opts.find("--security-opt") != std::string::npos)
				hits.push_back("capability/device/profile option in " + std::string(ENV_APPMESH_DOCKER_PARAMS));
			if (opts.find("-v /:") == 0 || opts.find(" -v /:") != std::string::npos ||
				opts.find("--volume /:") != std::string::npos || opts.find(" --volume /:") != std::string::npos)
				hits.push_back("bind of host path </>");
			if (!hits.empty())
			{
				std::string joined;
				for (const auto &h : hits)
					joined += (joined.empty() ? "" : "; ") + h;
				if (policy == "enforce")
				{
					setStartError("Docker.HostSecurityPolicy=enforce rejected the container definition: " + joined);
					LOG_WAR << fname << startError();
					return INVALID_PID;
				}
				LOG_WAR << fname << "Docker.HostSecurityPolicy=audit: container <" << m_containerName << "> uses "
						<< joined;
			}
		}
	}

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
				setStartError(Utility::stringFormat("failed get docker container <%s> from output <%s>",
													dockerCommand.c_str(), run.output.c_str()));
		}
		else
		{
			LOG_WAR << fname << "start container command <" << dockerCommand << "> failed: " << run.output;
			setStartError(Utility::stringFormat("started docker container <%s> failed with error <%s>",
												dockerCommand.c_str(), run.output.c_str()));
		}

		// Set container id here for future cleanup
		setContainerId(containerId);
	}

	// Step 4: Get docker root pid
	if (startSuccess)
	{
		dockerCommand = Utility::stringFormat("%s inspect -f '{{.State.Pid}} {{.State.Running}} {{.State.ExitCode}}' %s",
											  containerEngine.c_str(), containerId.c_str());
		const auto inspect = runDockerCli(dockerCommand);
		if (!inspect.started)
		{
			setStartError(inspect.error.empty() ? "failed to launch docker inspect command" : inspect.error);
			setContainerId(containerId);
			terminate();
			return INVALID_PID;
		}
		if (!inspect.completed)
		{
			setStartError(inspect.error);
			setContainerId(containerId);
			terminate();
			return INVALID_PID;
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
					LOG_INF << fname << "container <" << containerId << "> completed before host PID inspection, exit code <"
							<< exitCode << ">";
					reportEarlyExit(exitCode);
					return INVALID_PID;
				}
				if (runningText == "true" && hostPid > 1)
				{
					this->attach(hostPid);
					m_hostPidVisible.store(AppProcess::running(), std::memory_order_release);
					m_containerRunning.store(true, std::memory_order_release);
					setContainerId(containerId);
					LOG_INF << fname << "started pid <" << hostPid << "> for container: " << containerId;
					return this->getpid();
				}
				setStartError(Utility::stringFormat("container running without valid host pid, inspect output <%s>",
													stateText.c_str()));
			}
			else
			{
				LOG_WAR << fname << "failed to parse container state from output <" << stateText << ">";
				setStartError(Utility::stringFormat("failed get docker container state <%s> from output <%s>",
													dockerCommand.c_str(), stateText.c_str()));
			}
		}
		else
		{
			LOG_WAR << fname << "inspect container pid command <" << dockerCommand << "> failed: " << inspect.output;
			setStartError(Utility::stringFormat("start docker container <%s> failed <%s>", dockerCommand.c_str(),
												inspect.output.c_str()));
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
	auto parsedTimeout = std::optional<int>{};
	if (auto timeoutSetting = envMap.find(ENV_APPMESH_DOCKER_IMG_PULL_TIMEOUT); timeoutSetting != envMap.end())
		parsedTimeout = parseInteger<int>(timeoutSetting->second);
	if (parsedTimeout && *parsedTimeout > 0)
		pullTimeout = *parsedTimeout;
	else
		LOG_DBG << fname << "image pull timeout not configured, using default <" << pullTimeout << "> seconds";

	std::string containerEngine;
	{
		std::lock_guard guard(m_dockerMutex);
		containerEngine = m_containerEngine;
	}
	const pid_t pid = AppProcess::startImpl(containerEngine + " pull " + dockerImage, "root", std::move(workDir), {},
											nullptr, stdoutFile, EMPTY_STR_JSON, 0, false);
	if (pid > 1)
		scheduleTermination(pullTimeout, fname);
	return pid;
}

pid_t DockerProcess::getpid() const
{
	// Return invalid PID if process ID is 1 (init/systemd)
	if (AppProcess::getpid() == 1)
	{
		return INVALID_PID;
	}
	return AppProcess::getpid();
}

std::optional<int> DockerProcess::containerHealthVerdict()
{
	std::string containerId;
	std::string containerEngine;
	{
		std::lock_guard guard(m_dockerMutex);
		containerId = m_containerId;
		containerEngine = m_containerEngine;
	}
	if (containerId.empty())
		return std::nullopt;

	// Empty output (or a non-zero exit) means the image defines no HEALTHCHECK.
	const auto result = runDockerCli(
		Utility::stringFormat("%s inspect -f '{{.State.Health.Status}}' %s", containerEngine.c_str(), containerId.c_str()),
		15, 128, true);
	if (!result.started || !result.completed || result.exitCode != 0)
		return std::nullopt;
	const auto status = Utility::stdStringTrim(result.output);
	if (status == "healthy")
		return 0;
	if (status == "unhealthy")
		return 1;
	if (status == "starting")
		return 0; // Docker's own start-period leniency
	return std::nullopt;
}

bool DockerProcess::needsAlwaysExitPoll() const
{
	std::lock_guard guard(m_dockerMutex);
	return !m_containerId.empty() && !m_hostPidVisible.load(std::memory_order_acquire);
}

void DockerProcess::adoptRecoveredContainer()
{
	const static char fname[] = "DockerProcess::adoptRecoveredContainer() ";
	if (!containerId().empty())
		return;

	std::string containerEngineName;
	{
		std::lock_guard guard(m_dockerMutex);
		containerEngineName = m_containerEngine;
	}
	// Same ownership proof as the API backend: only a container labeled for this app is adopted.
	const auto owned = runDockerCli(Utility::stringFormat("%s ps -aq --filter name=^/%s$ --filter label=%s=true --filter label=%s=%s",
														  containerEngineName.c_str(), m_containerName.c_str(), DOCKER_LABEL_MANAGED,
														  DOCKER_LABEL_APP, m_legacyContainerName.c_str()));
	const auto adoptedId = Utility::stdStringTrim(owned.output);
	if (!owned.started || !owned.completed || owned.exitCode != 0 || adoptedId.empty())
		return;

	setContainerId(adoptedId);
	const auto state = runDockerCli(Utility::stringFormat("%s inspect -f '{{.State.Running}}' %s",
														  containerEngineName.c_str(), adoptedId.c_str()),
									10, 32, true);
	if (state.started && state.completed && state.exitCode == 0)
		m_containerRunning.store(Utility::stdStringTrim(state.output) == "true", std::memory_order_release);
	m_hostPidVisible.store(AppProcess::running(), std::memory_order_release);
	LOG_INF << fname << "adopted recovered container <" << adoptedId << "> for application <" << m_legacyContainerName
			<< ">";
}

bool DockerProcess::running() const
{
	if (m_pullInFlight.load(std::memory_order_acquire))
		return true;
	{
		std::lock_guard guard(m_dockerMutex);
		if (!m_containerId.empty() && !m_hostPidVisible.load(std::memory_order_acquire))
			return m_containerRunning.load(std::memory_order_acquire);
	}
	return AppProcess::running();
}

void DockerProcess::reportBackendExit()
{
	std::string containerId;
	std::string containerEngine;
	{
		std::lock_guard guard(m_dockerMutex);
		containerId = m_containerId;
		containerEngine = m_containerEngine;
	}
	if (containerId.empty())
	{
		// A pull child or native fallback: the OS answer is authoritative.
		onExit(returnValue());
		return;
	}

	// Docker decides: a still-running container only refreshes the cache.
	const auto inspect = runDockerCli(
		Utility::stringFormat("%s inspect -f '{{.State.Running}} {{.State.ExitCode}}' %s", containerEngine.c_str(),
							  containerId.c_str()),
		15, 256, true);
	if (!inspect.started || !inspect.completed || inspect.exitCode != 0)
	{
		// Channel failure must not fabricate an exit; retry on the next tick.
		LOG_WAR << "DockerProcess::reportBackendExit() inspect failed for <" << containerId << ">: " << inspect.error;
		return;
	}
	std::istringstream stateStream(Utility::stdStringTrim(inspect.output));
	std::string runningText;
	int exitCode = DOCKER_COMMAND_ERROR;
	if (stateStream >> runningText >> exitCode)
	{
		if (runningText == "true")
		{
			m_containerRunning.store(true, std::memory_order_release);
			return;
		}
		m_containerRunning.store(false, std::memory_order_release);
		onExit(exitCode);
	}
}

std::optional<int> DockerProcess::execHealthProbe(const std::string &cmd)
{
	const static char fname[] = "DockerProcess::execHealthProbe() ";
	std::string containerId;
	std::string containerEngine;
	{
		std::lock_guard guard(m_dockerMutex);
		containerId = m_containerId;
		containerEngine = m_containerEngine;
	}
	if (containerId.empty() || cmd.empty())
		return std::nullopt;

	const auto result = runDockerCli(
		Utility::stringFormat("%s exec %s %s", containerEngine.c_str(), containerId.c_str(), cmd.c_str()), 15, 512, true);
	if (!result.started || !result.completed)
	{
		LOG_WAR << fname << "docker exec probe did not complete: " << result.error;
		return std::nullopt;
	}
	return result.exitCode;
}

void DockerProcess::archiveContainerLogs(const std::string &containerId)
{
	const static char fname[] = "DockerProcess::archiveContainerLogs() ";
	if (m_stdoutFile.empty() || containerId.empty())
		return;
	try
	{
		std::string containerEngine;
		{
			std::lock_guard guard(m_dockerMutex);
			containerEngine = m_containerEngine;
		}
		const auto logs = runDockerCli(
			Utility::stringFormat("%s logs --tail 2000 %s", containerEngine.c_str(), containerId.c_str()), 15,
			256 * 1024, false);
		if (logs.started && logs.completed && !logs.output.empty())
		{
			std::ofstream out(m_stdoutFile, std::ios::app);
			out << logs.output;
		}
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "failed: " << ex.what();
	}
}

std::string DockerProcess::containerId() const
{
	std::lock_guard guard(m_dockerMutex);
	return m_containerId;
}

void DockerProcess::setContainerId(const std::string &containerId)
{
	std::lock_guard guard(m_dockerMutex);
	m_containerId = containerId;
}

std::string DockerProcess::takeContainerId()
{
	std::lock_guard guard(m_dockerMutex);
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
		std::lock_guard guard(m_dockerMutex);
		containerId = m_containerId;
		containerEngine = m_containerEngine;
	}
	if (containerId.empty())
		return AppProcess::returnValue();
	auto dockerCommand =
		Utility::stringFormat("%s inspect %s --format='{{.State.ExitCode}}'", containerEngine.c_str(), containerId.c_str());
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
		if (auto exitCode = parseInteger<int>(Utility::stdStringTrim(inspect.output)))
			return *exitCode;
		LOG_WAR << fname << "docker inspect exit code from container <" << containerId
				<< "> failed with output: " << inspect.output;
	}
	else
	{
		LOG_WAR << fname << "docker inspect exit code from container <" << containerId
				<< "> failed with exit code: " << inspect.exitCode;
	}

	return DOCKER_COMMAND_ERROR;
}

pid_t DockerProcess::startImpl(std::string cmd, std::string execUser, std::string workDir,
							   std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							   const std::string &stdoutFile, const Json::Value &stdinFileContent, int maxStdoutSize,
							   bool stdinPipe)
{
	const static char fname[] = "DockerProcess::startImpl() ";
	LOG_DBG << fname << "Entered";
	(void)stdinPipe; // registration rejects pipe stdin for container apps

	// Check for podman engine
	if (CONTAINER_PODMAN == GET_JSON_STR_VALUE(stdinFileContent, "engine"))
	{
		std::lock_guard guard(m_dockerMutex);
		m_containerEngine = CONTAINER_PODMAN;
	}
	m_stdoutFile = stdoutFile;

	return startContainer(cmd, execUser, workDir, envMap, limit, stdoutFile, stdinFileContent);
}

const std::string DockerProcess::getOutputMsg(long *position, int maxSize, bool readLine)
{
	const static char fname[] = "DockerProcess::getOutputMsg() ";
	std::string containerId;
	std::string containerEngine;
	{
		std::lock_guard guard(m_dockerMutex);
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

		auto dockerCommand =
			Utility::stringFormat("%s logs --since %ld %s", containerEngine.c_str(), secondsUTC, containerId.c_str());
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
			*position = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
							.count();
		}
		return logs.output;
	}

	return AppProcess::getOutputMsg(position, maxSize, readLine);
}
