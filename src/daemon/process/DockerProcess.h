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
	virtual int spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile = "", const web::json::value &stdinFileContent = EMPTY_STR_JSON, const int maxStdoutSize = 0) override;

	virtual pid_t getpid(void) const override;
	virtual std::string containerId() const override;
	virtual void containerId(const std::string &containerId) override;
	
	/// <summary>
	/// get all std out content from stdoutFile with given position
	/// </summary>
	/// <returns></returns>
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false) const override;

private:
	virtual int syncSpawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, std::string stdoutFile) noexcept(false);

private:
	std::string m_dockerImage;
	std::string m_containerId;
	std::string m_containerName;
	std::shared_ptr<std::thread> m_spawnThread;
	std::shared_ptr<AppProcess> m_imagePullProc;
	mutable std::recursive_mutex m_processMutex;
};
