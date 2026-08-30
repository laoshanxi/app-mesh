// src/daemon/application/Application.h
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <tuple>
#include <vector>

#include <boost/smart_ptr/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/synchronized_value.hpp>
#include <nlohmann/json.hpp>

#include "../../common/TimerHandler.h"
#include "../rest/HttpRequest.h"
#include "AppBehavior.h"
#include "AppUtils.h"

class AppTimer;
class CounterMetric;
class GaugeMetric;
class AppProcess;
class DailyLimitation;
class ResourceLimitation;
class TaskRequest;

using AppMeshProcess = boost::synchronized_value<std::shared_ptr<AppProcess>, boost::mutex>;

// An Application defines and manages a process job
class Application : public TimerHandler, public AppBehavior
{
public:
	Application();
	virtual ~Application();

	// Identity and state
	const std::string &getName() const;
	pid_t getpid() const;
	int health() const;
	const std::string &healthCheckCmd() const;
	const std::string &getOwnerPrincipalId() const;
	int getOwnerPermission() const;
	STATUS getStatus() const;
	bool isPersistAble() const;
	bool isManaged() const;
	bool isOneShot() const;
	bool isEnabled() const;
	bool isSystemProtected() const;
	int startupPhase() const;
	const std::vector<std::string> &dependencies() const;
	void health(bool health);
	void setUnPersistable();

	// Persistence and representation
	static void FromJson(const std::shared_ptr<Application> &app, const nlohmann::json &obj) noexcept(false);
	virtual nlohmann::json AsJson(bool returnRuntimeInfo, void *ptree = nullptr);
	virtual void save();
	virtual void remove();
	virtual void dump();
	virtual std::string getYamlPath();

	// Managed lifecycle
	bool available(const std::chrono::system_clock::time_point &now = std::chrono::system_clock::now());
	bool attach(int pid);
	void execute(void *ptree = nullptr, bool refreshMetrics = false);
	void enable();
	void disable();
	void destroy();
	void scheduleRemoval(int timeoutSeconds);

	// On-demand runs and output
	std::string runAsync(int timeoutSeconds) noexcept(false);
	std::string runSync(int timeoutSeconds, std::shared_ptr<HttpRequest> asyncHttpRequest) noexcept(false);
	std::tuple<std::string, bool, int> getOutput(long &position, long maxSize, const std::string &processUuid = "", int index = 0, size_t timeout = 0);

	// Worker task channel
	void sendTask(std::shared_ptr<HttpRequest> asyncHttpRequest);
	bool deleteTask();
	void fetchTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest);
	void replyTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest);
	std::tuple<int, std::string> taskStatus();
	/// Proves possession of the current managed process key and returns the
	/// daemon-assigned process UUID.  The key itself is never promoted to an
	/// authorization identity.
	std::string currentProcessUuidForKey(const std::string &processKey);
	bool isCurrentProcessUuid(const std::string &processUuid);

	// Prometheus metrics
	void initMetrics();
	void initMetrics(std::shared_ptr<Application> fromApp);
	void clearMetrics();

private:
	friend class AppProcess;
	friend class HttpRequestOutputView;

	using RunCompletionCallback = std::function<void()>;
	using RunCompletionSubscription = std::uint64_t;
	static constexpr RunCompletionSubscription INVALID_RUN_COMPLETION_SUBSCRIPTION = 0;

	// Lifecycle convergence (scheduler thread)
	void maintainRuntime(const std::chrono::system_clock::time_point &now);
	void stopUnavailableRun(const std::chrono::system_clock::time_point &now);
	bool stopCurrentRun();
	void stopAllProcesses();
	bool onTimerRemoval();
	void collectMetrics(void *ptree, bool refreshMetrics); // Uses the scheduler's shared process snapshot.
	void healthCheck();
	void applyExitPolicy();

	// Run creation and process callbacks
	std::string startRun(bool onDemand, int timeoutSeconds, const std::shared_ptr<HttpRequest> &completionRequest = nullptr,
						 std::uint64_t lifecycleGeneration = 0);
	std::shared_ptr<AppProcess> createProcess(const std::string &dockerImage, const std::string &appName);
	void terminate(std::shared_ptr<AppProcess> process);
	void onStartAccepted(const std::string &runId, pid_t pid);
	void recordStartFailure(const std::string &runId, const std::string &error, bool onDemand);
	// Natural exits latch restart only when reporter is the current run.
	void recordProcessExit(int code, bool naturalExit, AppProcess *reporter, long stdoutDispatchedBytes);
	void completeRun(const std::string &runId);

	// Completion observers
	RunCompletionSubscription subscribeRunCompletion(const std::string &processUuid, RunCompletionCallback callback);
	void unsubscribeRunCompletion(RunCompletionSubscription subscription);

	// Scheduling policy
	std::chrono::seconds restartDelay();
	void scheduleNext(std::chrono::system_clock::time_point startFrom = std::chrono::system_clock::now());
	void scheduleStartAt(const std::chrono::system_clock::time_point &when);
	std::uint64_t consumeScheduledStart(const std::chrono::system_clock::time_point &now);
	bool isRecurring() const;

	// Effective launch configuration
	const std::string getExecUser() const;
	const std::string &getCmdLine() const;
	std::map<std::string, std::string> getMergedEnvMap() const;

	// Error state
	void setLastError(const std::string &error) noexcept(false);
	const std::string getLastError() const noexcept(false);
	void setUnavailableError() noexcept(false);

	enum class Kind
	{
		Managed,
		OneShot,
		SystemAgent,
		System
	};

	// Definition and ownership
	std::shared_ptr<AppTimer> m_timer;
	Kind m_kind;

	std::string m_name;
	std::string m_commandLine;
	std::string m_description;
	std::string m_ownerPrincipalId;
	std::string m_executionUser;
	int m_startupPhase;
	int m_ownerPermission;
	std::string m_workdir;
	std::string m_stdoutFile;
	nlohmann::json m_metadata;
	bool m_shellApp;
	bool m_sessionLogin;
	int m_stdoutCacheNum;
	std::shared_ptr<ShellAppFileGen> m_shellAppFile;
	std::shared_ptr<LogFileQueue> m_stdoutFileQueue;

	// Availability window and scheduling
	std::chrono::system_clock::time_point m_startTime;
	std::chrono::system_clock::time_point m_endTime;
	std::string m_startIntervalValue;
	int m_startInterval;
	std::string m_bufferTimeValue;
	int m_bufferTime;
	enum class ScheduleKind
	{
		Continuous,
		Interval,
		Cron
	};
	ScheduleKind m_scheduleKind;
	std::shared_ptr<AppProcess> m_bufferProcess;

	// Runtime configuration
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

	// Runtime state
	AppMeshProcess m_process;
	std::atomic_bool m_health;
	std::atomic<STATUS> m_status;
	mutable std::mutex m_saveMutex; // Serialise concurrent save() on same app yaml.

	// Runtime lifecycle details are intentionally hidden from Application's interface.
	// The definition owns the run snapshot, completion registry, backoff, and their locks.
	struct Runtime;
	std::unique_ptr<Runtime> m_runtime;

	boost::synchronized_value<std::string> m_lastError;
	TaskRequest m_task;

	// Metrics shared by replacement Application instances
	struct MetricsState
	{
		std::mutex mutex;
		const Application *owner = nullptr; // Identity only; never dereferenced.
		std::shared_ptr<CounterMetric> startCount;
		std::shared_ptr<CounterMetric> collectionError;
		std::shared_ptr<GaugeMetric> memory;
		std::shared_ptr<GaugeMetric> cpu;
		std::shared_ptr<GaugeMetric> appPid;
		std::shared_ptr<GaugeMetric> fileDesc;
		std::shared_ptr<GaugeMetric> enabled;
		std::shared_ptr<GaugeMetric> running;
		std::shared_ptr<GaugeMetric> healthy;
		unsigned long long starts = 0;
	};
	std::shared_ptr<MetricsState> m_metrics;
	static void resetMetricHandles(MetricsState &metrics);
};
