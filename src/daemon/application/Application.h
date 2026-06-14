// src/daemon/application/Application.h
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>

#include <boost/smart_ptr/shared_ptr.hpp>
#include <boost/thread/recursive_mutex.hpp>
#include <boost/thread/synchronized_value.hpp>
#include <nlohmann/json.hpp>

#include "../../common/TimerHandler.h"
#include "../rest/HttpRequest.h"
#include "AppBehavior.h"
#include "AppUtils.h"

class AppTimer;
class User;
class CounterMetric;
class GaugeMetric;
class PrometheusRest;
class AppProcess;
class DailyLimitation;
class ResourceLimitation;
class TaskRequest;

// Recursive mutex is REQUIRED: terminate() under a synchronize() scope re-enters via
// onExitUpdate() -> m_process.get() (e.g. disabling an exited app); plain mutex would self-deadlock.
using AppMeshProcess = boost::synchronized_value<std::shared_ptr<AppProcess>, boost::recursive_mutex>;

// An Application defines and manages a process job
class Application : public TimerHandler, public AppBehavior
{
public:
	Application();
	virtual ~Application();

	// Getters
	const std::string &getName() const;
	pid_t getpid() const;
	int health() const;
	const std::string &healthCheckCmd() const;
	const std::shared_ptr<User> &getOwner() const;
	int getOwnerPermission() const;
	STATUS getStatus() const;
	bool isPersistAble() const;
	bool isEnabled() const;

	// Setters
	void health(bool health);
	void setUnPersistable();
	void nextLaunchTime(const std::chrono::system_clock::time_point &time);

	// Availability check
	bool available(const std::chrono::system_clock::time_point &now = std::chrono::system_clock::now());
	bool attach(int pid);

	// JSON serialization
	static void FromJson(const std::shared_ptr<Application> &app, const nlohmann::json &obj) noexcept(false);
	virtual nlohmann::json AsJson(bool returnRuntimeInfo, void *ptree = nullptr);
	virtual void save();
	virtual void remove();
	virtual void dump();
	virtual std::string getYamlPath();

	// Operations
	void execute(void *ptree = nullptr);
	void enable();
	void disable();
	void destroy();

	// Behavior
	void scheduleNext(std::chrono::system_clock::time_point startFrom = std::chrono::system_clock::now());
	void regSuicideTimer(int timeoutSeconds);
	bool onTimerAppRemove();
	void handleError();
	// triggerLifecycle: inline immediate restart; currently always false (restart is tick-driven).
	// naturalExit: latch for restart (vs. deliberate kill). reporter: latch only if it's the current m_process.
	void onExitUpdate(int code, bool triggerLifecycle = false, bool naturalExit = false, const AppProcess *reporter = nullptr);
	void terminate(std::shared_ptr<AppProcess> &process);

	// Run operations
	std::string runAsync(int timeoutSeconds) noexcept(false);
	std::string runSync(int timeoutSeconds, std::shared_ptr<HttpRequest> asyncHttpRequest) noexcept(false);
	std::tuple<std::string, bool, int> getOutput(long &position, long maxSize, const std::string &processUuid = "", int index = 0, size_t timeout = 0);

	// Task operations
	void sendTask(std::shared_ptr<HttpRequest> asyncHttpRequest);
	bool deleteTask();
	void fetchTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest);
	void replyTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest);
	std::tuple<int, std::string> taskStatus();

	// Prometheus metrics
	void initMetrics();
	void initMetrics(std::shared_ptr<Application> fromApp);

protected:
	// Error handling
	void setLastError(const std::string &error) noexcept(false);
	const std::string getLastError() const noexcept(false);
	void setInvalidError() noexcept(false);

	// Process management
	std::shared_ptr<AppProcess> allocProcess(bool monitorProcess, const std::string &dockerImage, const std::string &appName);
	bool onTimerSpawn(std::uint64_t gen);
	void refresh();
	void collectMetrics(void *ptree = nullptr); // Prometheus process-stat sampling; runs outside m_lifecycleMutex
	void healthCheck();

	std::string runApp(int timeoutSeconds) noexcept(false);
	const std::string getExecUser() const;
	const std::string &getCmdLine() const;
	std::map<std::string, std::string> getMergedEnvMap() const;

	// Single convergence point for the lifecycle state machine. Triggered by the periodic
	// tick (execute) and by a process-exit upcall (onExitUpdate, for immediate restart).
	void driveLifecycle(const std::chrono::system_clock::time_point &now);
	void handleUnavailable(const std::chrono::system_clock::time_point &now);
	// Terminate the running process (if any) and return next-start ownership to the tick.
	bool forceStop();
	void handleScheduling(const std::chrono::system_clock::time_point &now);
	// Crash-loop backoff delay for the next restart (see RestartBackoff); 0 for periodic/cron.
	std::chrono::seconds restartDelay();
	// The single place a spawn timer is armed; binds a fresh m_spawnGen as the authorization.
	void armSpawn(const std::chrono::system_clock::time_point &when);
	bool consumePendingExit(); // test-and-clear the exit latch; true => caller should run handleError()

protected:
	std::shared_ptr<AppTimer> m_timer;
	bool m_persistAble;

	std::string m_name;
	std::string m_commandLine;
	std::string m_description;
	std::shared_ptr<User> m_owner; // TODO: when user is removed, need remove associated app, otherwise, app invoke will fail
	int m_ownerPermission;
	std::string m_workdir;
	std::string m_stdoutFile;
	nlohmann::json m_metadata;
	bool m_shellApp;
	bool m_sessionLogin;
	int m_stdoutCacheNum;
	std::shared_ptr<ShellAppFileGen> m_shellAppFile;
	std::shared_ptr<LogFileQueue> m_stdoutFileQueue;

	std::chrono::system_clock::time_point m_startTime;
	std::chrono::system_clock::time_point m_endTime;

	// Short running
	std::string m_startIntervalValue;
	int m_startInterval;
	std::string m_bufferTimeValue;
	int m_bufferTime;
	bool m_startIntervalValueIsCronExpr;
	std::shared_ptr<AppProcess> m_bufferProcess;

	// Spawn authorization: every arm/cancel bumps it, onTimerSpawn runs only with the current
	// value. Avoids the register-fires-before-store id race and any m_lifecycleMutex coupling.
	std::atomic<std::uint64_t> m_spawnGen{0};
	// For best-effort cancelTimer() only; correctness is via m_spawnGen, stale cancel is harmless.
	std::atomic_long m_nextStartTimerId;

	std::chrono::system_clock::time_point m_regTime;
	std::string m_healthCheckCmd;
	const std::string m_appId;
	unsigned int m_version;

	std::atomic_long m_timerRemoveId;
	std::shared_ptr<DailyLimitation> m_dailyLimit;
	std::shared_ptr<ResourceLimitation> m_resourceLimit;
	std::map<std::string, std::string> m_envMap;
	std::map<std::string, std::string> m_secEnvMap;
	std::string m_dockerImage;

	// Runtime dynamic variables
	AppMeshProcess m_process;
	std::atomic_bool m_health;
	std::atomic<STATUS> m_status;
	std::atomic_bool m_destroying{false}; // First entry to destroy() wins; rest are no-ops.
	mutable std::mutex m_saveMutex; // Serialise concurrent save() on same app yaml.

	// Schedule intent: true when no one owns the next start (initial, force-stop, failed arm);
	// cleared by armSpawn(). handleScheduling triggers off this.
	std::atomic_bool m_needsSchedule;

	// ---- Consolidated runtime run-state (struct + lock + accessors, keep together) ----
	// Guarded by m_runMutex so readers see a consistent snapshot.
	// Lock order: m_process -> m_runMutex; never hold m_runMutex across timer/m_process ops.
	struct RunState
	{
		pid_t pid = 0;      // real default (ACE_INVALID_PID) set in Application ctor
		int returnCode = 0; // real default (INVALID_RETURN_CODE) set in Application ctor
		boost::shared_ptr<std::chrono::system_clock::time_point> startTime; // null = not started
		boost::shared_ptr<std::chrono::system_clock::time_point> exitTime;  // null = not exited
		boost::shared_ptr<std::chrono::system_clock::time_point> nextLaunch; // next planned launch (display data); null = none
		bool exitPending = false; // an exit was recorded and not yet handled by driveLifecycle
	};
	mutable std::mutex m_runMutex;
	RunState m_run; // guarded by m_runMutex

	template <typename Fn>
	void updateRunState(Fn &&fn) // grouped mutation under the run lock
	{
		std::lock_guard<std::mutex> guard(m_runMutex);
		fn(m_run);
	}
	RunState loadRunState() const // consistent copy for readers
	{
		std::lock_guard<std::mutex> guard(m_runMutex);
		return m_run;
	}
	// ------------------------------------------------------------------------------------

	// Serializes driveLifecycle() across its trigger threads (periodic tick + the
	// exit-driven call). Lock order: m_lifecycleMutex -> m_process -> m_runMutex.
	std::mutex m_lifecycleMutex;

	// Crash-loop restart backoff; only touched from handleError (under m_lifecycleMutex).
	RestartBackoff m_restartBackoff;

	// Error message
	boost::synchronized_value<std::string> m_lastError;

	// Task request (application level)
	TaskRequest m_task;

	// Prometheus metrics
	std::shared_ptr<CounterMetric> m_metricStartCount;
	std::shared_ptr<GaugeMetric> m_metricMemory;
	std::shared_ptr<GaugeMetric> m_metricCpu;
	std::shared_ptr<GaugeMetric> m_metricAppPid;
	std::shared_ptr<GaugeMetric> m_metricFileDesc;
	// Always-on start counter reported by AsJson (independent of Prometheus). shared_ptr so an
	// updated app inherits the prior object's count (see initMetrics). atomic, not a prometheus
	// type, to keep this off the Prometheus dependency when metrics are disabled.
	std::shared_ptr<std::atomic<unsigned long long>> m_starts;
};
