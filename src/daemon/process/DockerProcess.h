// src/daemon/process/DockerProcess.h
#pragma once

#include <chrono>
#include <map>
#include <string>

#include "AppProcess.h"

// Docker command line process object
class DockerProcess : public AppProcess, public ACE_Process
{
public:
	DockerProcess(const std::string &containerName, const std::string &dockerImage);
	~DockerProcess();

	// Override with docker cli behavior
	void terminate() override;

	// Override with docker cli spawn behavior
	int spawnProcess(std::string cmd, std::string execUser, std::string workDir,
					 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
					 const std::string &stdoutFile = "", const nlohmann::json &stdinFileContent = EMPTY_STR_JSON,
					 int maxStdoutSize = 0) override;

	// Returns docker container PID from inspect
	pid_t getpid() const override;

	// Get/set container ID
	std::string containerId() const override;
	void containerId(const std::string &containerId) override;

	// Get process exit code from container inspect
	int returnValue() const override;

	// Get stdout content from docker logs
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false) override;

protected:
	// Run docker pull cli
	int execPullDockerImage(std::map<std::string, std::string> &envMap, const std::string &dockerImage,
							const std::string &stdoutFile, const std::string &workDir);

private:
	// Synchronously spawn docker container start process
	virtual int syncSpawnProcess(std::string cmd, std::string execUser, std::string workDir,
								 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
								 std::string stdoutFile) noexcept(false);

protected:
	const std::string m_containerName;
	const std::string m_dockerImage;
	std::string m_containerId;
	std::string m_containerEngine; // docker or podman

	std::shared_ptr<AppProcess> m_imagePull;
	mutable std::recursive_mutex m_processMutex;
};
