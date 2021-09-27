#pragma once

#include <chrono>
#include <map>
#include <string>

#include "AppProcess.h"

/// <summary>
/// Docker command line process object
/// </summary>
class DockerProcess : public AppProcess
{
public:
	/// <summary>
	/// constructor
	/// </summary>
	/// <param name="dockerImage"></param>
	/// <param name="containerName"></param>
	DockerProcess(const std::string &dockerImage, const std::string &containerName);
	virtual ~DockerProcess();

	/// <summary>
	/// override with docker cli behavior
	/// </summary>
	/// <param name="timerId"></param>
	virtual void killgroup(int timerId = 0) override;

	/// <summary>
	/// override with docker cli behavior
	/// </summary>
	/// <param name="cmd"></param>
	/// <param name="execUser"></param>
	/// <param name="workDir"></param>
	/// <param name="envMap"></param>
	/// <param name="limit"></param>
	/// <param name="stdoutFile"></param>
	/// <param name="stdinFileContent"></param>
	/// <param name="maxStdoutSize"></param>
	/// <returns></returns>
	virtual int spawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, const std::string &stdoutFile = "", const web::json::value &stdinFileContent = EMPTY_STR_JSON, const int maxStdoutSize = 0) override;

	/// <summary>
	/// override with docker cli behavior
	/// 1. return docker pull cli pid
	/// 2. return docker container pid get from inspect
	/// </summary>
	/// <param name=""></param>
	/// <returns></returns>
	virtual pid_t getpid(void) const override;

	/// <summary>
	/// get container id
	/// </summary>
	/// <returns></returns>
	virtual std::string containerId() const override;
	/// <summary>
	/// set container id
	/// </summary>
	/// <param name="containerId"></param>
	virtual void containerId(const std::string &containerId) override;

	/// <summary>
	/// get process exit code
	/// </summary>
	/// <param name=""></param>
	/// <returns></returns>
	virtual int returnValue(void) const override;

	/// <summary>
	/// get all std out content from stdoutFile with given position
	/// </summary>
	/// <param name="position"></param>
	/// <param name="maxSize"></param>
	/// <param name="readLine"></param>
	/// <returns></returns>
	const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false) override;

protected:
	/// <summary>
	/// run docker pull cli
	/// </summary>
	/// <param name="envMap"></param>
	/// <param name="dockerImage"></param>
	/// <param name="stdoutFile"></param>
	/// <param name="workDir"></param>
	/// <returns></returns>
	int execPullDockerImage(std::map<std::string, std::string> &envMap, const std::string &dockerImage, const std::string &stdoutFile, const std::string &workDir);

private:
	/// <summary>
	/// synchronize run docker container start process
	/// </summary>
	/// <param name="cmd"></param>
	/// <param name="execUser"></param>
	/// <param name="workDir"></param>
	/// <param name="envMap"></param>
	/// <param name="limit"></param>
	/// <param name="stdoutFile"></param>
	/// <returns></returns>
	virtual int syncSpawnProcess(std::string cmd, std::string execUser, std::string workDir, std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit, std::string stdoutFile) noexcept(false);

protected:
	std::string m_dockerImage;
	std::string m_containerId;
	std::string m_containerName;
	std::unique_ptr<AppProcess> m_imagePullProc;
	mutable std::recursive_mutex m_processMutex;
};
