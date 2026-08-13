// src/daemon/process/AppProcess.h
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>
#include <utility>

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

struct ProcessStartResult
{
	bool accepted = false;
	pid_t pid = ACE_INVALID_PID;
	std::string error;
};

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

	// Lifecycle
	ProcessStartResult start(std::string cmd, std::string user, std::string workDir,
							 std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							 const std::string &stdoutFile = "", const nlohmann::json &stdinFileContent = EMPTY_STR_JSON,
							 int maxStdoutSize = APP_STD_OUT_MAX_FILE_SIZE);
	void terminate();
	void scheduleTermination(std::size_t timeoutSec, const std::string &from);
	bool running() const;
	// Wait for AppMesh finalization (stdout drained and Application exit state committed),
	// not for OS reaping. Returns the run's native PID, 0 on timeout, or
	// ACE_INVALID_PID when a finalized backend run never exposed a native PID.
	pid_t wait(const ACE_Time_Value &tv, ACE_exitcode *status = nullptr);

	// Identity and result
	virtual pid_t getpid() const;
	virtual int returnValue() const;
	const std::string &getuuid() const;
	const std::string &getkey() const;
	const std::string startError() const;
	virtual std::string containerId() const { return std::string(); }

	// Output and process metrics
	virtual const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE, bool readLine = false);
	std::tuple<bool, uint64_t, float, uint64_t, std::string, pid_t> getProcessDetails(
		void *ptree = nullptr, bool includeTreeString = true, bool metricsSample = false);

protected:
	// Backend contract
	virtual pid_t startImpl(std::string cmd, std::string user, std::string workDir,
							std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							const std::string &stdoutFile, const nlohmann::json &stdinFileContent,
							int maxStdoutSize);
	virtual void terminateImpl();

	// Backend state publication
	void attach(int pid, const std::string &stdoutFile = "");
	void detach();
	// Container backends may prove that creation/start succeeded after the host PID
	// has already disappeared. Preserve that accepted start, then report its exit.
	void reportEarlyExit(int exitCode);
	void setStartError(const std::string &error);

private:
	static constexpr int FORCED_TERMINATION_EXIT_CODE = 9;
	friend class Application;

	// Application integration
	void markRecovered();
	bool isRecovered() const;
	void startStdoutMonitoring();
	bool blocksStart() const;
	bool isFinalized() const noexcept;
	bool canReportExit() const noexcept;
	pid_t lastPid() const;

	// Start/exit coordination
	void resolveStart(bool accepted, pid_t pid);
	bool isStartAccepted() const;
	void onExit(int exitCode);
	void enqueueExitFinalization(int exitCode);
	void finalizeExit(int exitCode);

	// Native process and resource helpers
	int validateCommand(const std::string &cmd);
	void prepareEnvironment(std::map<std::string, std::string> &envMap);
	pid_t spawn(ACE_Process_Options &options, const std::shared_ptr<ResourceLimitation> &limit = nullptr);
	void setCgroup(const std::shared_ptr<ResourceLimitation> &limit);
	long cleanupResources();
	bool onTimerTerminate();
	bool onTimerCheckStdout();
	static bool running(pid_t pid);
	static bool sameProcessRunning(pid_t pid, std::uint64_t expectedStart);

	// Per-process bridge registered with ACE_Process_Manager.
	class ExitAdapter;

	// Ownership and timers
	const std::weak_ptr<Application> m_owner;
	std::atomic_long m_timerTerminateId;
	std::atomic_long m_timerCheckStdoutId;
	off_t m_stdOutMaxSize;
	mutable std::mutex m_processMutex;

	// Redirected I/O
	AtomicHandleGuard m_stdinHandler;
	AtomicHandleGuard m_stdoutHandler;
	std::string m_stdinFileName;
	std::string m_stdoutFileName;
	// shared_ptr so the mutex outlives whichever (AppProcess or StdoutPump) destructs first.
	mutable std::shared_ptr<std::mutex> m_outFileMutex;
#if defined(_WIN32)
	SharedHandle m_job;
#endif

	// Metrics sampling
	mutable std::mutex m_cpuMutex;
	uint64_t m_lastProcCpuTime;
	std::chrono::steady_clock::time_point m_lastCpuSampleTime;
	uint64_t m_lastMetricProcCpuTime;
	std::chrono::steady_clock::time_point m_lastMetricCpuSampleTime;

	// Native resources and identity
	std::unique_ptr<LinuxCgroup> m_cgroup;
	const std::string m_uuid;
	const std::string m_key;
	std::atomic<pid_t> m_pid;
	std::atomic<int> m_returnValue;

	// Start/exit coordination
	struct Lifecycle;
	std::unique_ptr<Lifecycle> m_lifecycle;

	// Runtime stdout delivery
	std::unique_ptr<StdoutStrategy> m_stdoutStrategy;
};
