#pragma once

#include <string>
#include <chrono>
#include <thread>
#include "AppProcess.h"

class MonitoredProcess;
//////////////////////////////////////////////////////////////////////////
/// Docker Process Object
//////////////////////////////////////////////////////////////////////////
class DockerProcess : public AppProcess
{
public:
	DockerProcess(const std::string &dockerImage, const std::string &appName);
	virtual ~DockerProcess();

	// override with docker behavior
	virtual void killgroup(int timerId = 0) override;
	virtual int spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, std::string stdoutFile) override;
	virtual int syncSpawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, std::string stdoutFile) noexcept(false);
	virtual pid_t getpid(void) const override;
	virtual std::string containerId() override;
	virtual void containerId(std::string containerId) override;

	// docker logs
	virtual std::string fetchOutputMsg() override;
	virtual std::string fetchLine() override;

private:
	std::string m_dockerImage;
	std::string m_containerId;
	std::string m_appName;
	std::shared_ptr<std::thread> m_spawnThread;
	std::shared_ptr<AppProcess> m_imagePullProc;
	mutable std::recursive_mutex m_processMutex;
	std::chrono::system_clock::time_point m_lastFetchTime;
};
