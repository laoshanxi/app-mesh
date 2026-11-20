// src/daemon/application/Application.h
#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <vector>

#include <boost/smart_ptr/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/thread/synchronized_value.hpp>
#include <json/json.h>

#include "../../common/TimerHandler.h"
#include "../../common/os/models.h" // pid_t
#include "../rest/HttpRequest.h"
#include "AppBehavior.h"
#include "AppUtils.h"

class AppTimer;
class CounterMetric;
class GaugeMetric;
class AppProcess;
class DailyLimitation;
class HMACVerifier;
class ResourceLimitation;
class TaskRequest;

using AppMeshProcess = boost::synchronized_value<std::shared_ptr<AppProcess>, boost::mutex>;

// An Application defines and manages a process job
class Application : public TimerHandler, public AppBehavior
{
public:
	static constexpr int DEFAULT_STARTUP_PHASE = 100;

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
	/// Base application name this on-demand run instance was spawned from
	/// (empty for unnamed/new-app runs); the engine-injected run_base marker.
	const std::string &runBaseApp() const { return m_runBaseApp; }
	/// True for cron and interval schedules (point-in-time runs).
	bool isRecurring() const;
	// stop_grace_period in seconds; 0 when unset. Container backends apply
	// their own default when the owner did not configure one.
	int stopGraceSeconds() const { return m_bufferTime; }
	/// True when the app runs as a container (docker_image set).
	bool isContainerized() const { return !m_dockerImage.empty(); }
	/// Health verdict straight from the container: the image HEALTHCHECK status
	/// Docker already maintains (read, never re-executed) when the image
	/// defines one — an explicit health_check_cmd is then bypassed to avoid
	/// duplicate probing; otherwise health_check_cmd executes inside the
	/// container. nullopt when this app has no container-health semantics
	/// (native apps, or a container app with neither an image HEALTHCHECK nor
	/// health_check_cmd) or when the container channel failed.
	std::optional<int> probeContainerHealth();
	bool isEnabled() const;
	bool isSystemProtected() const;
	int startupPhase() const;
	const std::vector<std::string> &dependsOn() const;
	// Dependency names not yet satisfied at the last scheduler pass (runtime info).
	const std::vector<std::string> waitingFor() const;
	void health(bool health);
	void setUnPersistable();

	// Persistence and representation
	static void FromJson(const std::shared_ptr<Application> &app, const Json::Value &obj) noexcept(false);
	virtual Json::Value AsJson(bool returnRuntimeInfo, void *ptree = nullptr);
	virtual void save();
	virtual void remove();
	/// A same-name replacement writes the same stdout paths; destruction must not delete them.
	void releaseStdoutFiles();

	virtual void dump();
	virtual std::string getYamlPath();

	// Managed lifecycle
	bool available(const std::chrono::system_clock::time_point &now = std::chrono::system_clock::now());
	bool attach(int pid);
	void execute(void *ptree = nullptr, bool refreshMetrics = false);
	void enable();
	/// Flips the status to DISABLED and suspends scheduling; callers stop the runs.
	void disable();
	/// Stops the current and buffer runs; idempotent.
	void stopAllProcesses();
	void destroy();
	void scheduleRemoval(int timeoutSeconds);

	// On-demand runs and output
	std::string runAsync(int timeoutSeconds) noexcept(false);
	std::string runSync(int timeoutSeconds, std::shared_ptr<HttpRequest> asyncHttpRequest) noexcept(false);
	std::tuple<std::string, bool, int> getOutput(long &position, long maxSize, const std::string &processUuid = "",
												 int index = 0, size_t timeout = 0);

	// Worker task channel
	void sendTask(std::shared_ptr<HttpRequest> asyncHttpRequest);
	bool deleteTask();
	void fetchTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest);
	void replyTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest);
	// Worker incremental result: delivered when the in-flight caller streams.
	void partialTask(const std::string &processKey, const std::string &payload, bool &delivered);
	std::tuple<int, std::string> taskStatus();

	// Interactive stdin (apps registered with "stdin": "pipe"): injects bytes
	// into the running process; `closePipe` sends EOF. Returns bytes written.
	long writeStdin(const std::vector<std::uint8_t> &data, bool closePipe, const std::string &processUuid = "");
	bool isStdinPipe() const { return m_stdinPipe; }

	// Current process identity and managed process proof
	bool isCurrentProcessUuid(const std::string &processUuid);
	/// Proves the caller holds the current process pre-shared key by verifying
	/// its per-request HMAC signature, and returns the process UUID.
	std::string currentProcessUuidForProof(const std::string &message, const std::string &hmacSignature);
	/// Verifies a per-request HMAC signature against the current process pre-shared key.
	bool verifyProcessProof(const std::string &message, const std::string &hmacSignature);
	/// Signs a message with the current process pre-shared key; empty when no proof exists.
	std::string signProcessProof(const std::string &message);

	// A container die event pushed by the agent: reports the exit like the scheduler poll.
	void reportContainerEvent(const std::string &containerId);
	/// Blocks until the spawned process has read its pre-shared key (startup fail-fast).
	bool waitProcessProofRead();

	// Prometheus metrics
	void initMetrics();
	void initMetrics(std::shared_ptr<Application> fromApp);
	void clearMetrics();

private:
	friend class AppProcess;
	friend class HttpRequestOutputView;

	/// Delete this application's YAML only when the file still carries its exact name.
	void removeOwnedYamlFile(const std::string &path);

	using RunCompletionCallback = std::function<void()>;
	using RunCompletionSubscription = std::uint64_t;
	static constexpr RunCompletionSubscription INVALID_RUN_COMPLETION_SUBSCRIPTION = 0;

	// Lifecycle convergence (scheduler thread)
	void maintainRuntime(const std::chrono::system_clock::time_point &now);
	// Fills `unmet` with dependencies that are disabled, not running, or unhealthy.
	bool unmetDependencies(std::vector<std::string> &unmet) const;
	// Recomputes the gate, updates the waiting_for snapshot, logs transitions.
	bool refreshDependencyGate();
	void stopUnavailableRun(const std::chrono::system_clock::time_point &now);
	bool stopCurrentRun();
	bool onTimerRemoval();
	void collectMetrics(void *ptree, bool refreshMetrics); // Uses the scheduler's shared process snapshot.
	void healthCheck();
	void applyExitPolicy();

	// Run creation and process callbacks
	std::string startRun(bool onDemand, int timeoutSeconds, const std::shared_ptr<HttpRequest> &completionRequest = nullptr,
						 std::uint64_t lifecycleGeneration = 0);
	std::shared_ptr<AppProcess> createProcess(const std::string &dockerImage, const std::string &appName);
	// Merge docker_ports/docker_volumes/docker_network into a copy of the app
	// metadata as the Docker create request body (PortBindings/Binds/NetworkMode).
	void compileDockerContainerFields(Json::Value &createBody) const;
	void terminate(std::shared_ptr<AppProcess> process);
	void onStartAccepted(const std::string &runId, pid_t pid);
	void recordStartFailure(const std::string &runId, const std::string &error, bool onDemand);
	// Natural exits latch restart only when reporter is the current run.
	void recordProcessExit(int code, bool naturalExit, AppProcess *reporter, long stdoutDispatchedBytes);
	void completeRun(const std::string &runId);

	// Managed process proof (Agent, Workflow): a per-spawn pre-shared key handed
	// over through shared memory on every start.
	bool usesProcessProof() const;
	std::shared_ptr<HMACVerifier> issueProcessProof(const std::string &execUser,
													std::map<std::string, std::string> &envMap) const;
	void activateProcessProof(const std::string &runId, const std::shared_ptr<HMACVerifier> &proof, bool startAccepted);

	// Completion observers
	RunCompletionSubscription subscribeRunCompletion(const std::string &processUuid, RunCompletionCallback callback);
	void unsubscribeRunCompletion(RunCompletionSubscription subscription);

	// Scheduling policy
	// bypassesSchedule: the restart ignores the timer's spacing (keepalive), so the
	// crash-loop backoff must throttle it even for recurring apps.
	std::chrono::seconds restartDelay(bool bypassesSchedule = false);
	void scheduleNext(std::chrono::system_clock::time_point startFrom = std::chrono::system_clock::now());
	void scheduleStartAt(const std::chrono::system_clock::time_point &when);
	std::uint64_t consumeScheduledStart(const std::chrono::system_clock::time_point &now);

	// Effective launch configuration
	const std::string getExecUser() const;
	const std::string &getCmdLine() const;
	std::map<std::string, std::string> getMergedEnvMap() const;
	// Target user of the sudo login wrapper, empty when the spawn needs no
	// environment passthrough (no session_login user switch or Docker app).
	std::string sudoLoginUser() const;

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
	// run_base marker: non-empty only for run instances copied from an existing
	// app (RestHandler::parseAndRegRunApp); never client-writable.
	std::string m_runBaseApp;
	std::string m_ownerPrincipalId;
	std::string m_executionUser;
	int m_startupPhase;
	std::vector<std::string> m_dependsOn;
	int m_ownerPermission;
	std::string m_workdir;
	std::string m_stdoutFile;
	Json::Value m_metadata;
	// "stdin": "pipe" — the daemon keeps the pipe write end open for writeStdin.
	bool m_stdinPipe{false};
	bool m_shellApp;
	bool m_sessionLogin;
	int m_stdoutCacheNum;
	std::shared_ptr<ShellAppFileGen> m_shellAppFile;
	std::shared_ptr<LogFileQueue> m_stdoutFileQueue;
	// stdout bytes the daemon pumped for the last exited run (-1 before any exit):
	// distinguishes "output never reached the daemon" from "lost after the pump".
	std::atomic<long> m_lastStdoutDispatchedBytes{-1};

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

	std::atomic_long m_timerRemoveId;
	std::shared_ptr<DailyLimitation> m_dailyLimit;
	std::shared_ptr<ResourceLimitation> m_resourceLimit;
	std::map<std::string, std::string> m_envMap;
	std::map<std::string, std::string> m_secEnvMap;
	std::string m_dockerImage;
	// First-class container wiring (docker run -p/-v/--network spelling),
	// compiled into the Docker create request body at launch.
	std::vector<std::string> m_dockerPorts;
	std::vector<std::string> m_dockerVolumes;
	std::string m_dockerNetwork;

	// Runtime state
	AppMeshProcess m_process;
	// Per-spawn pre-shared-key proof for managed system processes (Agent,
	// Workflow); replaced on every spawn, accessed under the m_process lock.
	std::shared_ptr<HMACVerifier> m_processProof;
	std::atomic_bool m_health;
	std::atomic<STATUS> m_status;
	mutable std::mutex m_saveMutex; // Serialise concurrent save() on same app yaml.

	// Runtime lifecycle details are intentionally hidden from Application's interface.
	// The definition owns the run snapshot, completion registry, backoff, and their locks.
	struct Runtime;
	std::unique_ptr<Runtime> m_runtime;

	boost::synchronized_value<std::string> m_lastError;
	// Unmet dependency names at the last scheduler pass (served by AsJson(true)).
	boost::synchronized_value<std::vector<std::string>> m_waitingFor;
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
