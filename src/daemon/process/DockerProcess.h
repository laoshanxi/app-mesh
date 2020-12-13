#pragma once

#include <chrono>
#include <string>
#include <thread>

#include "AppProcess.h"

/// <summary>
/// Docker Process Object
/// </summary>
class DockerProcess : public AppProcess
{
public:
	/// <summary>
	/// constructor
	/// </summary>
	/// <param name="dockerImage"></param>
	/// <param name="appName"></param>
	DockerProcess(const std::string &dockerImage, const std::string &containerName);
	virtual ~DockerProcess();

	// override with docker behavior
	virtual void killgroup(int timerId = 0) override;
	virtual int spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile = "", const std::string &stdinFileContent = "") override;

	virtual pid_t getpid(void) const override;
	virtual std::string containerId() const override;
	virtual void containerId(const std::string &containerId) override;

	// docker logs
	virtual const std::string fetchOutputMsg() override;
	virtual const std::string fetchLine() override;

private:
	virtual int syncSpawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, std::string stdoutFile) noexcept(false);

private:
	std::string m_dockerImage;
	std::string m_containerId;
	std::string m_containerName;
	std::shared_ptr<std::thread> m_spawnThread;
	std::shared_ptr<AppProcess> m_imagePullProc;
	mutable std::recursive_mutex m_processMutex;
	std::chrono::system_clock::time_point m_lastFetchTime;
};
