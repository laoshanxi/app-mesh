#pragma once

#include <map>
#include <string>
#include <tuple>

#include <ace/Process.h>
#include <ace/Process_Manager.h>

#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#if defined(_WIN32)
#include "../../common/os/jobobject.hpp"
#endif

class LinuxCgroup;
class ResourceLimitation;

/// <summary>
/// Construct a ACE_Process with a given pid
/// </summary>
class AttachProcess : public ACE_Process
{
public:
	explicit AttachProcess(pid_t pid);
	virtual ~AttachProcess();
};

/// <summary>
/// ACE_Process_Manager with Thread_Mutex
/// </summary>
class Process_Manager : public ACE_Process_Manager
{
public:
	virtual ~Process_Manager();
	static Process_Manager *instance();
	ACE_Recursive_Thread_Mutex &mutex();

private:
	ACE_Recursive_Thread_Mutex m_mutex;
};

/// <summary>
/// Used to register to ACE_Process_Manager
/// handle_exit() will be triggered when process exit
/// </summary>
class ProcessExitHandler : public ACE_Event_Handler, public TimerHandler
{
public:
	ProcessExitHandler();
	virtual ~ProcessExitHandler();
	virtual int handle_exit(ACE_Process *process) override;
	void terminate(pid_t pid);

private:
	bool onProcessExit();

private:
	std::atomic<pid_t> m_exitPid;
	std::atomic<int> m_exitCode;
};

/// <summary>
/// Process Object, inherit from ACE_Process
/// Support:
///  1. cgroup
///  2. pipe
///  3. auto kill
///  4. timer kill
/// </summary>
class AppProcess : public ProcessExitHandler
{
public:
	AppProcess(void *owner);
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
	/// Set process exit code
	/// </summary>
	virtual void onExit(int exitCode);
	bool onTimerAppExit();

	/// <summary>
	/// Process running status
	/// </summary>
	/// <returns></returns>
	virtual bool running() const;
	static bool running(pid_t pid);

	pid_t wait(const ACE_Time_Value &tv, ACE_exitcode *status = 0);
	pid_t wait(ACE_exitcode *status = 0);

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
	virtual void containerId(const std::string &) {};

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
	/// - pid_t: leaf process id
	/// </returns>
	std::tuple<bool, uint64_t, float, uint64_t, std::string, pid_t> getProcessDetails(void *ptree = nullptr);

	/// <summary>
	/// Attach a existing pid to AppProcess to manage
	/// </summary>
	/// <param name="pid">process id</param>
	/// <param name="stdoutFile">std output save file path</param>
	void attach(int pid, const std::string &stdoutFile = "");

	/// <summary>
	/// avoid de-constructure kill process
	/// </summary>
	void detach(void);

	/// <summary>
	/// kill the process group
	/// </summary>
	virtual void terminate();

	/// <summary>
	/// terminate for Timer
	/// </summary>
	bool onTimerTerminate();

	/// <summary>
	/// clean OS resources
	/// </summary>
	void cleanResource();

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
	bool onTimerCheckStdout();

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

	// overwrite ACE_Process spawn method
	virtual pid_t spawn(ACE_Process_Options &options);

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
	const void *m_owner;

private:
	std::atomic_long m_timerTerminateId;
	std::atomic_long m_timerCheckStdoutId;
	off_t m_stdOutMaxSize;
	mutable std::recursive_mutex m_processMutex; // onTimerCheckStdout, terminate, spawnProcess

	std::atomic<ACE_HANDLE> m_stdinHandler;
	std::atomic<ACE_HANDLE> m_stdoutHandler;
	std::string m_stdinFileName;
	std::string m_stdoutFileName;
	mutable std::recursive_mutex m_outFileMutex;
#if defined(_WIN32)
	SharedHandle m_job;
#endif

	mutable std::recursive_mutex m_cpuMutex;
	uint64_t m_lastProcCpuTime;
	uint64_t m_lastSysCpuTime;

	std::unique_ptr<LinuxCgroup> m_cgroup;
	const std::string m_uuid;
	std::string m_startError;
	std::atomic<pid_t> m_pid;
	std::atomic<int> m_returnValue;
};
