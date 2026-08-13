// src/daemon/process/DockerProcess.h
#pragma once

#include <map>
#include <string>

#include "AppProcess.h"

// Docker command line process object
class DockerProcess : public AppProcess
{
public:
	DockerProcess(std::weak_ptr<Application> owner, const std::string &containerName, const std::string &dockerImage);
	~DockerProcess() override;

	// Returns docker container PID from inspect
	pid_t getpid() const override;

	// Get container ID
	std::string containerId() const override;

	// Get process exit code from container inspect
	int returnValue() const override;

	// Get stdout content from docker logs
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false) override;

protected:
	pid_t startImpl(std::string cmd, std::string execUser, std::string workDir,
					std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
					const std::string &stdoutFile, const nlohmann::json &stdinFileContent,
					int maxStdoutSize) override;
	void terminateImpl() override;

	// A pull is its own managed run, with this AppProcess owning its PID and exit callback.
	pid_t startImagePull(const std::map<std::string, std::string> &envMap, const std::string &dockerImage,
						 std::string workDir, const std::string &stdoutFile);
	void setContainerId(const std::string &containerId);
	std::string takeContainerId();
	// Immutable container identity shared with the API implementation.
	const std::string m_containerName;
	const std::string m_dockerImage;

private:
	pid_t startContainer(const std::string &cmd, const std::string &workDir,
						 const std::map<std::string, std::string> &envMap,
						 const std::shared_ptr<ResourceLimitation> &limit, const std::string &stdoutFile);
	std::string m_containerId;
	std::string m_containerEngine; // docker or podman

	// Guards container id and engine selection.
	mutable std::mutex m_dockerMutex;
};
