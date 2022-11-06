#pragma once

#include <map>
#include <string>
#include <tuple>

#include <ace/Process.h>

#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"

class LinuxCgroup;
class ResourceLimitation;
/// <summary>
/// Process Object, inherit from ACE_Process
/// Support:
///  1. cgroup
///  2. pipe
///  3. auto kill
///  4. timer kill
/// </summary>
class AppProcess : public ACE_Process, public TimerHandler
{
public:
	AppProcess();
	virtual ~AppProcess();

	/// <summary>
	/// Override function
	/// </summary>
	/// <param name=""></param>
	/// <returns></returns>
	virtual pid_t getpid(void) const;

	/// <summary>
	/// Get process exit code
	/// </summary>
	/// <returns></returns>
	virtual int returnValue(void) const;

	/// <summary>
	/// Process UUID
	/// </summary>
	/// <returns></returns>
	const std::string getuuid() const;

	/// <summary>
	/// Get Docker container ID
	/// </summary>
	/// <returns></returns>
	virtual std::string containerId() const { return std::string(); };

	/// <summary>
	/// Set Docker container ID
	/// </summary>
	/// <param name="containerId"></param>
	virtual void containerId(const std::string &containerId){};

	/// <summary>
	/// get process memory and cpu usage
	/// </summary>
	/// <returns>
	/// tuple
	/// - bool: get success or fail
	/// - uint64_t: total memory bytes
	/// - float: cpu usage
	/// - uint64_t: total file descriptors
	/// - std::string: pstree string
	/// </returns>
	std::tuple<bool, uint64_t, float, uint64_t, std::string> getProcessDetails(void *ptree = nullptr);

	/// <summary>
	/// Attach a existing pid to AppProcess to manage
	/// </summary>
	/// <param name="pid">process id</param>
	void attach(int pid);

	/// <summary>
	/// avoid de-constructure kill process
	/// </summary>
	void detach(void);

	/// <summary>
	/// kill the process group
	/// </summary>
	virtual void killgroup();

	/// <summary>
	/// set resource limitation
	/// </summary>
	/// <param name="limit"></param>
	virtual void setCgroup(std::shared_ptr<ResourceLimitation> &limit);
	/// <summary>
	/// kill after a time period
	/// </summary>
	/// <param name="timeoutSec">seconds</param>
	/// <param name="from"></param>
	void delayKill(std::size_t timeoutSec, const std::string &from);

	/// <summary>
	/// register check stdout timer
	/// </summary>
	void registerCheckStdoutTimer();

	/// <summary>
	/// check stdout file size
	/// </summary>
	void checkStdout();

	/// <summary>
	/// Start process
	/// </summary>
	/// <param name="cmd">full command line with arguments</param>
	/// <param name="user">Linux user name</param>
	/// <param name="workDir">working directory</param>
	/// <param name="envMap">environment variables</param>
	/// <param name="limit">cgroup limitation</param>
	/// <param name="stdoutFile">std out output file</param>
	/// <param name="stdinFileContent">std in string content</param>
	/// <param name="maxStdoutSize">max stdout log file size, default is 100MB</param>
	/// <returns>process id</returns>
	virtual int spawnProcess(std::string cmd, std::string user, std::string workDir,
							 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							 const std::string &stdoutFile = "", const nlohmann::json &stdinFileContent = EMPTY_STR_JSON,
							 const int maxStdoutSize = APP_STD_OUT_MAX_FILE_SIZE);

	/// <summary>
	/// get all std out content from stdoutFile with given position
	/// </summary>
	/// <returns></returns>
	virtual const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false);

	/// <summary>
	/// save last error
	/// </summary>
	/// <param name="err">error string</param>
	void startError(const std::string &err);
	/// <summary>
	/// get last error
	/// </summary>
	/// <returns></returns>
	const std::string startError() const;

protected:
	/// <summary>
	/// Parse command line, get cmdRoot and parameters
	/// </summary>
	/// <param name="cmd"></param>
	/// <returns>tuple: 1 cmdRoot, 2 parameters</returns>
	std::tuple<std::string, std::string> extractCommand(const std::string &cmd);

private:
	long m_delayKillTimerId;
	long m_stdOutSizeTimerId;
	off_t m_stdOutMaxSize;
	mutable std::recursive_mutex m_processMutex; //checkStdout, delayKill, killgroup

	ACE_HANDLE m_stdinHandler;
	ACE_HANDLE m_stdoutHandler;
	std::string m_stdinFileName;
	std::string m_stdoutFileName;
	mutable std::recursive_mutex m_outFileMutex;

	mutable std::recursive_mutex m_cpuMutex;
	uint64_t m_lastProcCpuTime;
	uint64_t m_lastSysCpuTime;

	std::unique_ptr<LinuxCgroup> m_cgroup;
	const std::string m_uuid;
	std::string m_startError;
};
