// src/daemon/process/AppProcess.h
#pragma once

#include <map>
#include <memory>
#include <string>
#include <tuple>

#include <boost/smart_ptr/atomic_shared_ptr.hpp>

#include "../../common/AtomicHandleGuard.hpp"
#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "AttachProcess.h"
#include "ProcessManager.h"
#if defined(_WIN32)
#include "../../common/os/jobobject.hpp"
#endif

class LinuxCgroup;
class ResourceLimitation;
class Application;
class StdoutStrategy;

// Process Object supporting:
//  - cgroup resource limitation
//  - stdin/stdout/stderr pipe redirection
//  - auto kill on timeout
//  - stdout dispatch via StdoutStrategy (pump or timer)
class AppProcess : public TimerHandler
{
public:
	explicit AppProcess(std::weak_ptr<Application> owner);
	virtual ~AppProcess();

	long stdoutDispatchedBytes() const;

	virtual pid_t getpid() const;
	virtual int returnValue() const;
	virtual void onExit(int exitCode);
	bool onTimerAppExit(int exitCode);

	bool running() const;
	static bool running(pid_t pid);

	pid_t wait(const ACE_Time_Value &tv, ACE_exitcode *status = nullptr);
	pid_t wait(ACE_exitcode *status = nullptr);

	const std::string &getuuid() const;
	const std::string &getkey() const;

	virtual std::string containerId() const { return std::string(); }
	virtual void containerId(const std::string &) {}

	std::tuple<bool, uint64_t, float, uint64_t, std::string, pid_t> getProcessDetails(void *ptree = nullptr);

	void attach(int pid, const std::string &stdoutFile = "");
	// Recovered (attached) processes are not our children — no SIGCHLD; Application::refresh
	// polls and synthesizes the exit. Set ONLY by Application::attach (Docker must not opt in).
	void markRecovered() { m_recovered.store(true); }
	bool isRecovered() const { return m_recovered.load(); }
	void detach();
	virtual void terminate();
	bool onTimerTerminate();
	void cleanResource();
	virtual void setCgroup(std::shared_ptr<ResourceLimitation> &limit);
	void delayKill(std::size_t timeoutSec, const std::string &from);
	void registerCheckStdoutTimer();
	bool onTimerCheckStdout();

	virtual int spawnProcess(std::string cmd, std::string user, std::string workDir,
							 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							 const std::string &stdoutFile = "", const nlohmann::json &stdinFileContent = EMPTY_STR_JSON,
							 int maxStdoutSize = APP_STD_OUT_MAX_FILE_SIZE);

	virtual pid_t spawn(ACE_Process_Options &options);

	virtual const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false);

	const std::string startError() const;
	void startError(const std::string &err);

private:
	int validateCommand(const std::string &cmd);
	void prepareEnvironment(std::map<std::string, std::string> &envMap);

	// Per-process bridge registered as exit_notify_ with ACE_Process_Manager.
	class ExitAdapter;

protected:
	const std::weak_ptr<Application> m_owner;

private:
	std::atomic_long m_timerTerminateId;
	std::atomic_long m_timerCheckStdoutId;
	off_t m_stdOutMaxSize;
	mutable std::recursive_mutex m_processMutex;

	AtomicHandleGuard m_stdinHandler;
	AtomicHandleGuard m_stdoutHandler;
	std::string m_stdinFileName;
	std::string m_stdoutFileName;
	// shared_ptr so the mutex outlives whichever (AppProcess or StdoutPump) destructs first.
	mutable std::shared_ptr<std::recursive_mutex> m_outFileMutex;
#if defined(_WIN32)
	SharedHandle m_job;
#endif

	mutable std::recursive_mutex m_cpuMutex;
	uint64_t m_lastProcCpuTime;
	uint64_t m_lastSysCpuTime;

	std::unique_ptr<LinuxCgroup> m_cgroup;
	const std::string m_uuid;
	const std::string m_key;
	std::atomic<pid_t> m_pid;
	std::atomic<int> m_returnValue;
	// BUG fix: CAS guard prevents double onExit when terminate() races with natural exit.
	std::atomic<bool> m_exitFired{false};
	// True once we deliberately kill this process; marks its exit as not-natural (no restart).
	std::atomic<bool> m_terminating{false};
	// True for a daemon-restart recovered (attached) process; enables tick-side exit polling.
	std::atomic<bool> m_recovered{false};

	boost::atomic_shared_ptr<std::string> m_startError;

	std::unique_ptr<StdoutStrategy> m_stdoutStrategy;
};
