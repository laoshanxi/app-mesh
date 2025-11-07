#pragma once

#include <map>
#include <string>
#include <tuple>

#include <ace/Process.h>
#include <ace/Process_Manager.h>
#include <boost/smart_ptr/atomic_shared_ptr.hpp>
#include <boost/thread/synchronized_value.hpp>

#include "../../common/AtomicHandleGuard.hpp"
#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#if defined(_WIN32)
#include "../../common/os/jobobject.hpp"
#endif

class LinuxCgroup;
class ResourceLimitation;
class Application;

// Construct an ACE_Process with a given pid
class AttachProcess : public ACE_Process
{
public:
	explicit AttachProcess(pid_t pid);
	~AttachProcess() = default;
};

// ACE_Process_Manager with Thread_Mutex for thread-safe process management
class Process_Manager : public ACE_Process_Manager
{
public:
	~Process_Manager() = default;
	static Process_Manager *instance();
	ACE_Recursive_Thread_Mutex &mutex();

private:
	ACE_Recursive_Thread_Mutex m_mutex;
};

// Process exit handler that registers to ACE_Process_Manager
// handle_exit() will be triggered when process exits
class ProcessExitHandler : public ACE_Event_Handler, public TimerHandler
{
public:
	ProcessExitHandler() = default;
	~ProcessExitHandler() = default;
	int handle_exit(ACE_Process *process) override;
	void terminate(pid_t pid);

private:
	bool onProcessExit(int exitCode, pid_t exitPid);
};

// Process Object supporting:
//  - cgroup resource limitation
//  - stdin/stdout/stderr pipe redirection
//  - auto kill on timeout
//  - timer-based kill
class AppProcess : public ProcessExitHandler
{
public:
	explicit AppProcess(std::weak_ptr<Application> owner);
	virtual ~AppProcess();

	// Get process ID
	virtual pid_t getpid() const;

	// Get process exit code
	virtual int returnValue() const;

	// Set process exit code and trigger cleanup
	virtual void onExit(int exitCode);

	// Timer callback for application exit event
	bool onTimerAppExit(int exitCode);

	// Check if process is running
	bool running() const;
	static bool running(pid_t pid);

	// Wait for process to exit with timeout
	pid_t wait(const ACE_Time_Value &tv, ACE_exitcode *status = nullptr);
	pid_t wait(ACE_exitcode *status = nullptr);

	// Get process unique identifiers
	const std::string &getuuid() const;
	const std::string &getkey() const;

	// Docker container ID management (for derived classes)
	virtual std::string containerId() const { return std::string(); }
	virtual void containerId(const std::string &) {}

	// Get process resource usage details
	// Returns: (success, memory_bytes, cpu_usage%, fd_count, pstree_string, leaf_pid)
	std::tuple<bool, uint64_t, float, uint64_t, std::string, pid_t> getProcessDetails(void *ptree = nullptr);

	// Attach an existing pid to AppProcess for management
	void attach(int pid, const std::string &stdoutFile = "");

	// Detach process to avoid destruction killing it
	void detach();

	// Kill the process group
	virtual void terminate();

	// Timer callback for termination
	bool onTimerTerminate();

	// Clean up OS resources (file handles, timers, etc.)
	void cleanResource();

	// Set cgroup resource limitation
	virtual void setCgroup(std::shared_ptr<ResourceLimitation> &limit);

	// Schedule process kill after timeout
	void delayKill(std::size_t timeoutSec, const std::string &from);

	// Register timer to check stdout file size
	void registerCheckStdoutTimer();

	// Timer callback to check and rotate stdout file
	bool onTimerCheckStdout();

	// Start process with specified configuration
	virtual int spawnProcess(std::string cmd, std::string user, std::string workDir,
							 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							 const std::string &stdoutFile = "", const nlohmann::json &stdinFileContent = EMPTY_STR_JSON,
							 int maxStdoutSize = APP_STD_OUT_MAX_FILE_SIZE);

	// Spawn process with ACE_Process_Options
	virtual pid_t spawn(ACE_Process_Options &options);

	// Get stdout content from specified position
	virtual const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false);

	// Get/set process start error message
	const std::string startError() const;
	void startError(const std::string &err);

private:
	// Validate command file existence and execution permission
	int validateCommand(const std::string &cmd);

	// Prepare environment variables with built-in AppMesh variables
	void prepareEnvironment(std::map<std::string, std::string> &envMap);

protected:
	const std::weak_ptr<Application> m_owner; // Application owner pointer

private:
	std::atomic_long m_timerTerminateId;   // Timer ID for delayed kill
	std::atomic_long m_timerCheckStdoutId; // Timer ID for stdout check
	off_t m_stdOutMaxSize;				   // Maximum stdout file size
	mutable std::recursive_mutex m_processMutex;

	AtomicHandleGuard m_stdinHandler;  // stdin file descriptor
	AtomicHandleGuard m_stdoutHandler; // stdout file descriptor
	std::string m_stdinFileName;
	std::string m_stdoutFileName;
	mutable std::recursive_mutex m_outFileMutex;
#if defined(_WIN32)
	SharedHandle m_job; // Windows job object handle
#endif

	// CPU usage calculation
	mutable std::recursive_mutex m_cpuMutex;
	uint64_t m_lastProcCpuTime; // Last process CPU time
	uint64_t m_lastSysCpuTime;	// Last system CPU time

	std::unique_ptr<LinuxCgroup> m_cgroup; // cgroup controller
	const std::string m_uuid;			   // Process unique UUID
	const std::string m_key;			   // Process access key
	std::atomic<pid_t> m_pid;			   // Process ID
	std::atomic<int> m_returnValue;		   // Process exit code

	boost::atomic_shared_ptr<std::string> m_startError; // Process start error message
};
