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
#include <vector>

#include "../../common/AtomicHandleGuard.hpp"
#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "../../common/os/process.h"
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
	pid_t pid = INVALID_PID;
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
							 const std::string &stdoutFile = "", const Json::Value &stdinFileContent = EMPTY_STR_JSON,
							 int maxStdoutSize = APP_STD_OUT_MAX_FILE_SIZE);
	void terminate();
	void scheduleTermination(std::size_t timeoutSec, const std::string &from);
	bool running() const;
	// Wait for AppMesh finalization (stdout drained and Application exit state committed),
	// not for OS reaping. Returns the run's native PID, 0 on timeout, or
	// INVALID_PID when a finalized backend run never exposed a native PID.
	// A zero timeout polls.
	pid_t wait(std::chrono::milliseconds timeout, int *status = nullptr);

	// Identity and result
	virtual pid_t getpid() const;
	virtual int returnValue() const;
	const std::string &getUuid() const;
	const std::string &getKey() const;
	const std::string startError() const;
	virtual std::string containerId() const { return std::string(); }

	// Output and process metrics
	virtual const std::string getOutputMsg(long *position = nullptr, int maxSize = APP_STD_OUT_VIEW_DEFAULT_SIZE,
										   bool readLine = false);
	std::tuple<bool, uint64_t, float, uint64_t, std::string, pid_t>
	getProcessDetails(void *ptree = nullptr, bool includeTreeString = true, bool metricsSample = false);

protected:
	// Backend contract
	virtual pid_t startImpl(std::string cmd, std::string user, std::string workDir,
							std::map<std::string, std::string> envMap, std::shared_ptr<ResourceLimitation> limit,
							const std::string &stdoutFile, const Json::Value &stdinFileContent, int maxStdoutSize);
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
	bool isFinalized() const noexcept;
	bool canReportExit() const noexcept;
	pid_t lastPid() const;
	// Polled-exit report for runs without a child exit callback; container exit
	// codes need a blocking backend inspect and are fetched off the caller's thread.
	void reportPolledExitAsync();

	// Start/exit coordination
	void resolveStart(bool accepted, pid_t pid);
	bool isStartAccepted() const;
	void onExit(int exitCode);
	// Runs on the ProcessService thread: stdout teardown and application
	// callbacks may block safely outside the exit-observation context.
	void finalizeExit() noexcept;

	// Native process and resource helpers
	int validateCommand(const std::vector<std::string> &argv);
	void prepareEnvironment(std::map<std::string, std::string> &envMap);
	long cleanupResources();
	bool onTimerTerminate();
	bool onTimerCheckStdout();
	static bool running(pid_t pid);
	static bool sameProcessRunning(pid_t pid, std::uint64_t expectedStart);

	// Ownership and timers
	const std::weak_ptr<Application> m_owner;
	// Ownerless runs (health checks, docker CLI helpers) log start/exit at debug.
	const bool m_internal;
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
	std::atomic<pid_t> m_lastPid; // startImpl() writes without m_processMutex
	std::uint64_t m_processStartToken;
	bool m_recovered;
	std::atomic<int> m_returnValue;

	// Start/exit coordination
	struct Lifecycle;
	std::unique_ptr<Lifecycle> m_lifecycle;

	// Runtime stdout delivery
	std::unique_ptr<StdoutStrategy> m_stdoutStrategy;
};
