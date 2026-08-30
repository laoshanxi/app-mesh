// src/daemon/application/Application.cpp
#include "Application.h"

#include <limits>
#include <list>
#include <utility>

#include <boost/optional.hpp>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#include "../../common/DateTime.h"
#include "../../common/DurationParse.h"
#include "../../common/Utility.h"
#include "../../common/os/filesystem.h"
#include "../../common/os/linux.h"
#include "../../common/os/proc.h"
#include "../Configuration.h"
#include "../DailyLimitation.h"
#include "../ResourceLimitation.h"
#include "../process/AppProcess.h"
#if !defined(_WIN32)
#include "../process/DockerApiProcess.h"
#include "../process/DockerProcess.h"
#endif
#include "../rest/EventDispatcher.h"
#include "../rest/RestHandler.h"
#include "../security/HMACVerifier.h"
#include "../security/Security.h"
#include "../security/SecretProtector.h"
#include "AppTimer.h"

namespace
{
	constexpr int INVALID_RETURN_CODE = std::numeric_limits<int>::min();
	// Gap before a periodic app's next self-armed spawn: the current run already started this
	// second, so arm from the next second to avoid a same-second double computation.
	constexpr std::chrono::seconds PERIODIC_RESPAWN_GAP{1};
}

struct Application::Runtime
{
	struct CompletionSubscription
	{
		RunCompletionSubscription id;
		std::string runId;
		RunCompletionCallback callback;
	};

	struct Run
	{
		enum class Phase
		{
			Starting,
			Running,
			StopRequested,
			Finalizing,
			Completed
		};
		enum class ScheduleIntent
		{
			Dormant,
			NeedsPlan,
			Armed
		};

		std::string id;
		Phase phase = Phase::Completed;
		pid_t pid = ACE_INVALID_PID;
		int returnCode = INVALID_RETURN_CODE;
		boost::optional<std::chrono::system_clock::time_point> startTime;
		boost::optional<std::chrono::system_clock::time_point> exitTime;
		boost::optional<std::chrono::system_clock::time_point> nextLaunch;
		bool restartEvaluationPending = false;
		std::uint64_t lifecycleGeneration = 0;
		ScheduleIntent scheduleIntent = ScheduleIntent::NeedsPlan;
	};

	template <typename Fn>
	void update(Fn &&fn)
	{
		std::lock_guard<std::mutex> guard(runMutex);
		std::forward<Fn>(fn)(run);
	}

	Run load() const
	{
		std::lock_guard<std::mutex> guard(runMutex);
		return run;
	}

	void requireSchedulePlan()
	{
		update([](Run &state)
			   {
			state.nextLaunch.reset();
			state.scheduleIntent = Run::ScheduleIntent::NeedsPlan; });
	}

	void suspendSchedule()
	{
		update([](Run &state)
			   {
			state.nextLaunch.reset();
			state.restartEvaluationPending = false;
			state.scheduleIntent = Run::ScheduleIntent::Dormant; });
	}

	bool needsSchedulePlan() const
	{
		return load().scheduleIntent == Run::ScheduleIntent::NeedsPlan;
	}

	bool consumeRestartEvaluation()
	{
		bool consumed = false;
		update([&](Run &state)
			   {
			if (state.restartEvaluationPending)
			{
				state.restartEvaluationPending = false;
				consumed = true;
			} });
		return consumed;
	}

	// Lock order: Application::m_process -> runMutex -> Application::m_task.
	// lifecycleMutex precedes all of them. Callbacks run after every lock is released.
	mutable std::mutex runMutex;
	Run run;
	RunCompletionSubscription nextCompletionSubscription{1};
	std::list<CompletionSubscription> completionCallbacks;
	std::mutex lifecycleMutex;
	std::uint64_t lifecycleGeneration = 1;
	RestartBackoff restartBackoff;
};

Application::Application()
	: m_kind(Kind::Managed), m_startupPhase(100), m_ownerPermission(0), m_metadata(EMPTY_STR_JSON),
	  m_shellApp(false), m_sessionLogin(false), m_stdoutCacheNum(0),
	  m_startTime(AppTimer::TIME_UNSET), m_endTime(std::chrono::system_clock::time_point::max()),
	  m_startInterval(0), m_bufferTime(0), m_scheduleKind(ScheduleKind::Continuous),
	  m_regTime(std::chrono::system_clock::now()),
	  m_appId(Utility::shortID()), m_version(0), m_timerRemoveId(INVALID_TIMER_ID),
	  m_health(true),
	  m_status(STATUS::ENABLED), m_runtime(std::make_unique<Runtime>()),
	  m_metrics(std::make_shared<MetricsState>())
{
	const static char fname[] = "Application::Application() ";
	m_metrics->owner = this;
	LOG_DBG << fname << "Entered.";
}

Application::~Application()
{
	const static char fname[] = "Application::~Application() ";
	LOG_DBG << fname << "Entered. Application: " << m_name;
	// #include <boost/stacktrace.hpp>
	// std::cout << boost::stacktrace::stacktrace();
	Utility::removeFile(m_stdoutFile);
}

const std::string &Application::getName() const
{
	return m_name;
}

void Application::health(bool newHealth)
{
	bool oldHealth = m_health.exchange(newHealth);
	if (oldHealth != newHealth)
	{
		EventDispatcher::instance()->dispatch(m_name, AppEventType::HEALTH_CHANGE, {{"health", newHealth ? 0 : 1}, {"previous_health", oldHealth ? 0 : 1}});
	}
}

pid_t Application::getpid() const
{
	return m_runtime->load().pid;
}

int Application::health() const
{
	return 1 - m_health.load();
}

bool Application::isEnabled() const
{
	return (m_status.load() == STATUS::ENABLED);
}

bool Application::isSystemProtected() const
{
	return m_kind == Kind::System || m_kind == Kind::SystemAgent;
}

int Application::startupPhase() const { return m_startupPhase; }

const std::string &Application::healthCheckCmd() const
{
	return m_healthCheckCmd;
}

const std::string &Application::getOwnerPrincipalId() const
{
	return m_ownerPrincipalId;
}

int Application::getOwnerPermission() const
{
	return m_ownerPermission;
}

STATUS Application::getStatus() const
{
	return m_status.load();
}

bool Application::isPersistAble() const
{
	return m_kind == Kind::Managed;
}

bool Application::isManaged() const
{
	return m_kind != Kind::OneShot;
}

bool Application::isOneShot() const
{
	return m_kind == Kind::OneShot;
}

void Application::setUnPersistable()
{
	m_kind = (m_name == SEPARATE_AGENT_APP_NAME) ? Kind::SystemAgent : Kind::OneShot;
	if (m_kind == Kind::OneShot)
		m_runtime->suspendSchedule();
}

bool Application::isRecurring() const
{
	return m_scheduleKind != ScheduleKind::Continuous;
}

bool Application::available(const std::chrono::system_clock::time_point &now)
{
	// Check if expired
	if (m_endTime != AppTimer::TIME_UNSET &&
		m_endTime != std::chrono::system_clock::time_point::max() &&
		now >= m_endTime)
	{
		return false;
	}
	return isEnabled();
}

void Application::FromJson(const std::shared_ptr<Application> &app, const nlohmann::json &jsonObj)
{
	const static char fname[] = "Application::FromJson() ";
	app->m_name = normalizeAppName(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_name));

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_owner))
		throw std::invalid_argument(
			"legacy application owner cannot be mapped safely to an immutable OIDC Principal; "
			"provision the corresponding Dex Principal and replace owner with owner_principal_id");
	app->m_ownerPrincipalId = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_owner_principal_id));
	if (app->m_ownerPrincipalId.empty())
		throw std::invalid_argument("application owner_principal_id is required");
	app->m_executionUser = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_execution_user));
	if (GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_APP_system))
	{
		app->m_kind = Kind::System;
		if (app->m_ownerPrincipalId != AuthorizationStore::systemPrincipalId())
			throw std::invalid_argument("system application must be owned by system:appmesh");
	}
	const auto startupPhase = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_startup_phase);
	if (!startupPhase.empty())
	{
		static const std::map<std::string, int> phases = {
			{"auth-issuer", 20},
			{"ingress", 30}, {"normal", 100}};
		auto phase = phases.find(startupPhase);
		if (phase == phases.end())
			throw std::invalid_argument("invalid application startup_phase");
		app->m_startupPhase = phase->second;
	}
	app->m_ownerPermission = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_owner_permission);
	app->m_shellApp = GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_APP_shell_mode);
	app->m_sessionLogin = GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_APP_session_login);

	if (jsonObj.contains(JSON_KEY_APP_metadata))
	{
		app->m_metadata = jsonObj.at(JSON_KEY_APP_metadata);
		if (jsonObj.at(JSON_KEY_APP_metadata).is_string())
		{
			try
			{
				auto medataStr = jsonObj.at(JSON_KEY_APP_metadata).get<std::string>();
				app->m_metadata = nlohmann::json::parse(medataStr);
			}
			catch (...)
			{
				// Use text field if not JSON format
			}
		}
	}

	app->m_commandLine = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_command));
	app->m_description = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_description));

	// TODO: consider i18n and legal file name
	const static auto outputDir = (fs::path(Configuration::instance()->getWorkDir()) / "stdout");
	const auto fileName = Utility::stringFormat("appmesh.%s.out", app->m_name.c_str());
	app->m_stdoutFile = (outputDir / fileName).string();
	app->m_stdoutCacheNum = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_stdout_cache_num);
	app->m_stdoutFileQueue = std::make_shared<LogFileQueue>(app->m_stdoutFile, app->m_stdoutCacheNum);

	if (app->m_commandLine.length() >= MAX_COMMAND_LINE_LENGTH)
	{
		throw std::invalid_argument("command line length should less than 2048");
	}

	app->m_healthCheckCmd = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_health_check_cmd));
	if (app->m_healthCheckCmd.length() >= MAX_COMMAND_LINE_LENGTH)
	{
		throw std::invalid_argument("health check length should less than 2048");
	}

	app->m_workdir = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_working_dir));

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_status))
	{
		// Boolean is the documented wire form; numeric 1/0 stays accepted for
		// persisted YAML files and internal registrations.
		const auto &statusValue = jsonObj.at(JSON_KEY_APP_status);
		const int status = statusValue.is_boolean() ? (statusValue.get<bool>() ? 1 : 0) : statusValue.get<int>();
		app->m_status.store(static_cast<STATUS>(status));
	}

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_resource_limit))
	{
		app->m_resourceLimit = ResourceLimitation::FromJson(jsonObj.at(JSON_KEY_APP_resource_limit), app->m_name);
	}

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_env))
	{
		auto envs = jsonObj.at(JSON_KEY_APP_env);
		for (auto &env : envs.items())
		{
			app->m_envMap[env.key()] = env.value().get<std::string>();
		}
	}

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_sec_env))
	{
		bool fromRecover = HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_from_recover);
		auto envs = jsonObj.at(JSON_KEY_APP_sec_env);
		for (auto &env : envs.items())
		{
			if (fromRecover)
			{
				if (!env.value().is_string() ||
					!Utility::startWith(env.value().get<std::string>(), "sp1:"))
				{
					throw std::invalid_argument(
						"persisted sec_env uses legacy per-user encryption and cannot be migrated safely "
						"without the former credential material; re-register the secured value through "
						"an authenticated application update");
				}
				const std::string context = app->m_name + '\0' + env.key();
				try
				{
					app->m_secEnvMap[env.key()] = SecretProtector::instance().unprotect(
						env.value().get<std::string>(), context);
				}
				catch (const std::exception &)
				{
					throw std::invalid_argument(
						"persisted sec_env could not be authenticated; restore the original "
						"SecretProtector master key before starting App Mesh");
				}
			}
			else
			{
				// Do not need decrypt when register from UI/REST
				app->m_secEnvMap[env.key()] = env.value().get<std::string>();
			}
		}
	}

	app->m_dockerImage = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_docker_image);

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_pid))
	{
		app->attach(GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_pid));
	}

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_version))
	{
		SET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_version, app->m_version);
	}

	if (app->m_dockerImage.empty() && app->m_commandLine.empty())
	{
		throw std::invalid_argument("no command line provide");
	}

	if (!app->m_dockerImage.empty())
	{
		// Docker app does not support reserve more output backup files
		app->m_stdoutCacheNum = 0;
	}

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_time))
	{
		app->m_startTime = std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_time));
	}
	else if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds))
	{
		// For periodic run, set default startTime to now if not specified
		app->m_startTime = std::chrono::system_clock::now() + std::chrono::seconds(1);
	}

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_end_time))
	{
		app->m_endTime = std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_SHORT_APP_end_time));
	}

	if (app->m_endTime.time_since_epoch().count())
	{
		if (app->m_startTime > app->m_endTime)
		{
			throw std::invalid_argument("end_time should greater than the start_time");
		}
	}

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_daily_limitation))
	{
		app->m_dailyLimit = DailyLimitation::FromJson(jsonObj.at(JSON_KEY_APP_daily_limitation));
	}

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_REG_TIME))
	{
		app->m_regTime = std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_APP_REG_TIME));
	}

	// Init error handling
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_behavior))
	{
		app->behaviorInit(jsonObj.at(JSON_KEY_APP_behavior));
	}

	// Init m_timer
	DurationParse duration;
	app->m_bufferTimeValue = GET_JSON_STR_INT_TEXT(jsonObj, JSON_KEY_APP_retention);
	app->m_bufferTime = duration.parse(app->m_bufferTimeValue);

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds))
	{
		// Short running
		const bool cronSchedule = GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_SHORT_APP_cron_interval);
		app->m_startIntervalValue = GET_JSON_STR_INT_TEXT(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds);

		if (cronSchedule)
		{
			app->m_scheduleKind = ScheduleKind::Cron;
			app->m_timer = std::make_shared<AppTimerCron>(app->m_startTime, app->m_endTime, app->m_dailyLimit, app->m_startIntervalValue, app->m_startInterval);
			app->m_timer->nextTime(); // Validate cron expression
		}
		else
		{
			app->m_scheduleKind = ScheduleKind::Interval;
			app->m_startInterval = duration.parse(app->m_startIntervalValue);
			if (app->m_startInterval <= 0)
			{
				LOG_WAR << fname << "Invalid start interval <" << app->m_startIntervalValue << "> for application <" << app->m_name << ">, falling back to default";
				app->m_startInterval = DEFAULT_TOKEN_EXPIRE_SECONDS;
			}
			app->m_timer = std::make_shared<AppTimerPeriod>(app->m_startTime, app->m_endTime, app->m_dailyLimit, app->m_startInterval);
		}
	}
	else
	{
		// Long running
		app->m_scheduleKind = ScheduleKind::Continuous;
		app->m_timer = std::make_shared<AppTimer>(app->m_startTime, app->m_endTime, app->m_dailyLimit);
	}
}

void Application::collectMetrics(void *ptree, bool refreshMetrics)
{
	if (!refreshMetrics || !Configuration::instance()->prometheusEnabled())
	{
		return;
	}

	const auto process = m_process.get();
	const auto metrics = m_metrics;
	std::lock_guard<std::mutex> metricsGuard(metrics->mutex);
	if (metrics->owner != this)
		return;

	const bool processRunning = process && process->running();
	if (processRunning && ptree != nullptr && (metrics->memory || metrics->cpu || metrics->fileDesc))
	{
		auto usage = process->getProcessDetails(ptree, false, true);
		if (std::get<0>(usage))
		{
			if (metrics->memory)
				metrics->memory->metric().Set(std::get<1>(usage));
			// Convert percent to CPU cores.
			if (metrics->cpu)
				metrics->cpu->metric().Set(std::get<2>(usage) / 100.0);
			if (metrics->fileDesc)
				metrics->fileDesc->metric().Set(std::get<3>(usage));
		}
		else
		{
			if (metrics->memory)
				metrics->memory->metric().Set(0);
			if (metrics->cpu)
				metrics->cpu->metric().Set(0);
			if (metrics->fileDesc)
				metrics->fileDesc->metric().Set(0);
			if (metrics->collectionError)
				metrics->collectionError->metric().Increment();
		}
	}
	else if (!processRunning || ptree == nullptr)
	{
		if (metrics->memory)
			metrics->memory->metric().Set(0);
		if (metrics->cpu)
			metrics->cpu->metric().Set(0);
		if (metrics->fileDesc)
			metrics->fileDesc->metric().Set(0);
		if (processRunning && ptree == nullptr && metrics->collectionError)
			metrics->collectionError->metric().Increment();
	}
	const auto run = m_runtime->load();
	if (metrics->appPid)
	{
		metrics->appPid->metric().Set(processRunning && run.pid != ACE_INVALID_PID ? run.pid : 0);
	}
	if (metrics->enabled)
		metrics->enabled->metric().Set(getStatus() == STATUS::ENABLED ? 1 : 0);
	if (metrics->running)
		metrics->running->metric().Set(processRunning ? 1 : 0);
	if (metrics->healthy)
		metrics->healthy->metric().Set(processRunning && health() == 0 ? 1 : 0);
}

// Recovery entry (FromJson registration and main.cpp snapshot recovery); moving these calls
// up into the registration flow is deferred. Returns true when the recovered process is alive.
bool Application::attach(int pid)
{
	const static char fname[] = "Application::attach() ";

	if (pid <= 1)
	{
		return false;
	}

	// 1. Replace the current process with an attached (non-child) one
	std::shared_ptr<AppProcess> attached;
	std::shared_ptr<AppProcess> previous;
	{
		auto processLock = m_process.synchronize();
		// Idempotent: re-attaching the pid we already hold alive must not kill it.
		if ((*processLock) && (*processLock)->getpid() == pid && (*processLock)->running())
		{
			return true;
		}
		previous = std::move(*processLock);
		(*processLock) = createProcess(m_dockerImage, m_name);
		(*processLock)->attach(pid, m_stdoutFile);
		(*processLock)->markRecovered(); // not our child: maintainRuntime(now) detects its exit
		attached = (*processLock);
	}
	terminate(std::move(previous));

	// 2. Probe liveness (Windows: no probe -> treated as dead)
	const pid_t attachedPid = attached->getpid();
	auto procStartTime = std::chrono::system_clock::now();
	bool live = false;
#if !defined(_WIN32)
	if (auto stat = os::status(attachedPid))
	{
		live = attached->running();
		if (live)
			procStartTime = stat->get_starttime();
	}
#endif
	if (live)
	{
		TaskRequest::SupersededRequests supersededRequests;
		{
			auto processLock = m_process.synchronize();
			if (*processLock && (*processLock)->getuuid() == attached->getuuid())
				supersededRequests = m_task.activate(attached->getkey());
		}
		for (const auto &request : supersededRequests)
			if (request)
				request->interrupt();
		// A recovered process with a custom probe is not ready merely because
		// its PID exists. Keep dependents blocked until HealthCheckTask succeeds.
		health(m_healthCheckCmd.empty());
	}
	else
	{
		health(false);
	}

	// 3. Publish the recovered run-state and schedule intent before opening the
	// AppProcess start gate. A concurrent exit remains Observed until this state
	// and the task endpoint are ready, then finalizes against the correct run.
	{
		std::lock_guard<std::mutex> lifecycleGuard(m_runtime->lifecycleMutex);
		m_runtime->update([&](Runtime::Run &r)
						  {
			r.id = attached->getuuid();
			r.phase = live ? Runtime::Run::Phase::Running : Runtime::Run::Phase::Completed;
			r.pid = live ? attachedPid : ACE_INVALID_PID;
			r.startTime = procStartTime;
			r.returnCode = INVALID_RETURN_CODE;
			r.exitTime.reset();
			r.nextLaunch.reset();
			r.restartEvaluationPending = false;
			r.lifecycleGeneration = m_runtime->lifecycleGeneration;
			r.scheduleIntent = live ? Runtime::Run::ScheduleIntent::Dormant : Runtime::Run::ScheduleIntent::NeedsPlan; });
	}

	// A dead/reused recovery pid must not leave a pending process that blocks the
	// scheduler forever. Resolve the start only after identity and state publication.
	attached->resolveStart(live, live ? attachedPid : ACE_INVALID_PID);
	if (!live)
		attached->detach();

	LOG_INF << fname << "Attached pid <" << pid << "> to application <" << m_name
			<< ">, last start on <" << DateTime::formatLocalTime(procStartTime) << ">";

	// 4. Stdout follow-up, outside the m_process lock
	if (live && attached->running())
	{
		attached->startStdoutMonitoring();
	}
	return live;
}

void Application::stopUnavailableRun(const std::chrono::system_clock::time_point &now)
{
	const static char fname[] = "Application::stopUnavailableRun() ";

	const auto status = getStatus();
	if (status == STATUS::NOTAVAILABLE ||
		(status == STATUS::ENABLED && m_timer->isInDailyTimeRange(now)))
		return;
	if (!stopCurrentRun())
		return;

	LOG_INF << fname << "Application <" << m_name << "> stopped: "
			<< (status == STATUS::ENABLED ? "outside its valid time range" : "disabled")
			<< ", startTime <" << DateTime::formatLocalTime(m_startTime)
			<< ">, endTime <" << DateTime::formatLocalTime(m_endTime)
			<< ">, now <" << DateTime::formatLocalTime(now) << ">";
}

bool Application::stopCurrentRun()
{
	std::shared_ptr<AppProcess> process;
	{
		auto processLock = m_process.synchronize();
		if (!(*processLock) || !(*processLock)->running())
			return false;
		process = std::move(*processLock);
	}
	terminate(std::move(process));
	setUnavailableError();
	m_runtime->requireSchedulePlan();
	return true;
}

void Application::stopAllProcesses()
{
	std::shared_ptr<AppProcess> process;
	std::shared_ptr<AppProcess> bufferProcess;
	{
		auto processLock = m_process.synchronize();
		process = std::move(*processLock);
		bufferProcess = std::move(m_bufferProcess);
	}
	terminate(std::move(process));
	terminate(std::move(bufferProcess));
}

void Application::execute(void *ptree, bool refreshMetrics)
{
	// Periodic tick trigger.
	maintainRuntime(std::chrono::system_clock::now());
	// All applications in this scheduler pass reuse the same process snapshot.
	collectMetrics(ptree, refreshMetrics);
}

void Application::maintainRuntime(const std::chrono::system_clock::time_point &now)
{
	const auto needsPolledExitReport = [](const std::shared_ptr<AppProcess> &process)
	{
		if (!process || !process->canReportExit() || process->getpid() <= 1)
			return false;
		// Recovered processes and attached Docker containers have no child-process callback.
		// Docker image pulls do: their empty container ID keeps the exact callback authoritative.
		const bool lacksReactorExitCallback = process->isRecovered() || !process->containerId().empty();
		return lacksReactorExitCallback && !process->running();
	};

	std::shared_ptr<AppProcess> process;
	std::shared_ptr<AppProcess> bufferProcess;
	{
		auto lock = m_process.synchronize();
		if (m_bufferProcess)
		{
			if (m_bufferProcess->isFinalized())
				m_bufferProcess.reset();
			else
				bufferProcess = m_bufferProcess;
		}
		process = *lock;
	}

	if (needsPolledExitReport(bufferProcess))
	{
		const int exitCode = bufferProcess->isRecovered() ? 0 : bufferProcess->returnValue();
		bufferProcess->onExit(exitCode);
	}

	if (needsPolledExitReport(process))
	{
		// Docker inspection may block briefly, so obtain the exit code outside m_process.
		const int exitCode = process->isRecovered() ? 0 : process->returnValue();
		process->onExit(exitCode);
	}

	// Process inspection and termination may call Docker/OS backends. They own their
	// own synchronization and must never run while the scheduling decision is locked.
	stopUnavailableRun(now);
	healthCheck();
	const auto currentProcess = m_process.get();
	const bool processRunning = currentProcess && currentProcess->running();

	std::uint64_t lifecycleGeneration = 0;
	{
		// Serialize only schedule/restart decisions.
		std::lock_guard<std::mutex> lifecycleGuard(m_runtime->lifecycleMutex);
		if (m_runtime->needsSchedulePlan())
		{
			if (this->available(now))
				scheduleNext(now);
			else
				m_runtime->suspendSchedule();
		}
		if (isEnabled() && !processRunning && m_runtime->consumeRestartEvaluation())
			applyExitPolicy();
		lifecycleGeneration = consumeScheduledStart(now);
	}
	if (lifecycleGeneration != 0)
		startRun(false, 0, nullptr, lifecycleGeneration);
}

void Application::disable()
{
	const static char fname[] = "Application::disable() ";

	{
		// Status and schedule intent form one lifecycle decision. Keeping them under
		// the same lock prevents a concurrent enable from being overwritten by a
		// late suspendSchedule(). Process termination remains outside this lock.
		std::lock_guard<std::mutex> lifecycleGuard(m_runtime->lifecycleMutex);
		auto enabled = STATUS::ENABLED;
		if (!m_status.compare_exchange_strong(enabled, STATUS::DISABLED))
			return;
		++m_runtime->lifecycleGeneration;
		m_runtime->suspendSchedule();
	}

	LOG_INF << fname << "Application <" << m_name << "> disabled.";
	EventDispatcher::instance()->dispatch(m_name, AppEventType::STATUS_CHANGE, {{"status", "disabled"}, {"previous_status", "enabled"}});

	stopAllProcesses();
}

void Application::enable()
{
	{
		std::lock_guard<std::mutex> lifecycleGuard(m_runtime->lifecycleMutex);
		auto disabled = STATUS::DISABLED;
		if (!m_status.compare_exchange_strong(disabled, STATUS::ENABLED))
			return;
		++m_runtime->lifecycleGeneration;
		m_runtime->requireSchedulePlan();
	}
	EventDispatcher::instance()->dispatch(m_name, AppEventType::STATUS_CHANGE, {{"status", "enabled"}, {"previous_status", "disabled"}});
}

std::string Application::runAsync(int timeoutSeconds)
{
	const static char fname[] = "Application::runAsync() ";
	LOG_DBG << fname << "Entered.";

	return startRun(true, timeoutSeconds);
}

std::string Application::runSync(int timeoutSeconds, std::shared_ptr<HttpRequest> asyncHttpRequest)
{
	const static char fname[] = "Application::runSync() ";
	LOG_DBG << fname << "Entered.";

	return startRun(true, timeoutSeconds, asyncHttpRequest);
}

std::string Application::startRun(bool onDemand, int timeoutSeconds, const std::shared_ptr<HttpRequest> &completionRequest,
								  std::uint64_t lifecycleGeneration)
{
	const static char fname[] = "Application::startRun() ";
	if (onDemand && !isOneShot())
		throw std::invalid_argument("runApp is only for on-demand run apps");
	if (onDemand && !m_dockerImage.empty())
	{
		throw std::invalid_argument("Docker application does not support this API");
	}
	if (!onDemand && !isEnabled())
		return {};

	std::shared_ptr<AppProcess> process;
	std::shared_ptr<AppProcess> previous;
	std::shared_ptr<AppProcess> previousBuffer;
	bool bufferPrevious = false;
	RunCompletionSubscription completionSubscription = INVALID_RUN_COMPLETION_SUBSCRIPTION;
	std::string runId;
	std::unique_lock<std::mutex> lifecycleGuard;
	if (!onDemand)
	{
		lifecycleGuard = std::unique_lock<std::mutex>(m_runtime->lifecycleMutex);
		if (!isEnabled() || lifecycleGeneration == 0 || lifecycleGeneration != m_runtime->lifecycleGeneration)
			return {};
	}
	{
		auto processLock = m_process.synchronize();
		const auto currentRun = m_runtime->load();
		if (*processLock && currentRun.id == (*processLock)->getuuid() &&
			currentRun.phase == Runtime::Run::Phase::Starting)
		{
			if (onDemand)
				throw std::invalid_argument("application start is already in progress");
			return {};
		}

		process = createProcess(m_dockerImage, m_name);
		previous = std::move(*processLock);
		bufferPrevious = !onDemand && isRecurring() && m_bufferTime > 0 && previous && previous->running();
		if (bufferPrevious)
		{
			previousBuffer = std::move(m_bufferProcess);
			m_bufferProcess = previous;
		}
		*processLock = process;
		runId = process->getuuid();
		m_runtime->update([&](Runtime::Run &run)
						  {
			run.id = runId;
			run.phase = Runtime::Run::Phase::Starting;
			run.pid = ACE_INVALID_PID;
			run.startTime = std::chrono::system_clock::now();
			run.returnCode = INVALID_RETURN_CODE;
			run.exitTime.reset();
			run.restartEvaluationPending = false;
			run.lifecycleGeneration = onDemand ? 0 : lifecycleGeneration; });
	}
	if (lifecycleGuard.owns_lock())
		lifecycleGuard.unlock();

	// A new PID has not passed readiness yet. This closes the interval between
	// process publication and onStartAccepted(), during which a dependent App
	// could otherwise observe health left over from the previous run.
	health(false);

	if (previousBuffer)
		terminate(std::move(previousBuffer));
	if (bufferPrevious)
		previous->scheduleTermination(m_bufferTime, fname);
	else
		terminate(std::move(previous));

	if (completionRequest)
	{
		auto weakProcess = std::weak_ptr<AppProcess>(process);
		completionSubscription = subscribeRunCompletion(runId, [weakProcess, completionRequest]()
														{
			if (auto completed = weakProcess.lock())
			{
				long position = 0;
				std::map<std::string, std::string> headers;
				headers[HTTP_HEADER_KEY_exit_code] = std::to_string(completed->returnValue());
				const auto body = completed->getOutputMsg(&position);
				headers[HTTP_HEADER_KEY_output_pos] = std::to_string(position);
				completionRequest->reply(web::http::status_codes::OK, body, headers);
			} });
	}

	const auto execUser = (!onDemand && m_shellAppFile && m_shellAppFile->isUsingSudo()) ? std::string() : getExecUser();
	LOG_INF << fname << "Starting application <" << m_name << "> with user <" << execUser << ">";
	auto result = process->start(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit,
								 m_stdoutFile, m_metadata, APP_STD_OUT_MAX_FILE_SIZE);

	if (!result.accepted)
	{
		if (result.error.empty())
			result.error = "failed to start process";
		unsubscribeRunCompletion(completionSubscription);
		recordStartFailure(runId, result.error, onDemand);
	}
	else if (timeoutSeconds > 0)
	{
		process->scheduleTermination(timeoutSeconds, fname);
	}

	if (!result.accepted)
	{
		if (onDemand)
			throw std::invalid_argument(result.error.empty() ? "Start process failed" : result.error);
		return {};
	}
	if (!result.error.empty())
	{
		LOG_WAR << fname << "Application <" << m_name << "> started, but post-start setup reported: " << result.error;
	}

	if (!onDemand && isRecurring())
	{
		std::lock_guard<std::mutex> lifecycleGuard(m_runtime->lifecycleMutex);
		if (isEnabled() && lifecycleGeneration == m_runtime->lifecycleGeneration)
			scheduleNext(std::chrono::system_clock::now() + PERIODIC_RESPAWN_GAP);
	}
	process->startStdoutMonitoring();
	return process->getuuid();
}

void Application::onStartAccepted(const std::string &runId, pid_t pid)
{
	bool currentRun = false;
	TaskRequest::SupersededRequests supersededRequests;
	{
		auto processLock = m_process.synchronize();
		if (!(*processLock) || (*processLock)->getuuid() != runId)
			return;

		m_runtime->update([&](Runtime::Run &state)
						  {
			if (state.id != runId ||
				(state.phase != Runtime::Run::Phase::Starting && state.phase != Runtime::Run::Phase::StopRequested))
				return;
			// Bind the worker task endpoint before publishing Running, so SDK callers
			// cannot observe a runnable process whose key is not active yet.
			supersededRequests = m_task.activate((*processLock)->getkey());
			state.pid = pid;
			if (state.phase == Runtime::Run::Phase::Starting)
				state.phase = Runtime::Run::Phase::Running;
			currentRun = true; });
	}
	if (!currentRun)
		return;
	for (const auto &request : supersededRequests)
		if (request)
			request->interrupt();

	setLastError({});
	{
		const auto metrics = m_metrics;
		std::lock_guard<std::mutex> guard(metrics->mutex);
		++metrics->starts;
		if (metrics->owner == this && metrics->startCount)
			metrics->startCount->metric().Increment();
	}
	// Starting a process establishes liveness, not readiness. Applications with
	// a custom probe become healthy only after HealthCheckTask observes success.
	health(m_healthCheckCmd.empty());
	EventDispatcher::instance()->dispatch(m_name, AppEventType::PROCESS_START,
										  {{"pid", pid}, {"process_uuid", runId}});
}

void Application::recordStartFailure(const std::string &runId, const std::string &error, bool onDemand)
{
	const auto now = std::chrono::system_clock::now();
	bool currentRun = false;
	m_runtime->update([&](Runtime::Run &run)
					  {
		if (run.id != runId ||
			(run.phase != Runtime::Run::Phase::Starting && run.phase != Runtime::Run::Phase::StopRequested))
			return;
		run.pid = ACE_INVALID_PID;
		run.phase = Runtime::Run::Phase::Completed;
		run.exitTime = now;
		run.restartEvaluationPending = false;
		currentRun = true; });
	if (!currentRun)
		return;

	m_task.terminate();
	setLastError(error);
	health(false);
	LOG_WAR << "Application::recordStartFailure() application <" << m_name
			<< "> run <" << runId << "> failed to start: " << error;
	// Start rejection has no process-exit callback, so complete observers here.
	completeRun(runId);
	if (onDemand)
	{
		m_runtime->suspendSchedule();
		return;
	}

	std::lock_guard<std::mutex> lifecycleGuard(m_runtime->lifecycleMutex);
	const auto run = m_runtime->load();
	if (!isEnabled() || run.lifecycleGeneration != m_runtime->lifecycleGeneration)
		return;
	const auto retryDelay = isRecurring() ? PERIODIC_RESPAWN_GAP : restartDelay();
	scheduleNext(now + retryDelay);
}

void Application::sendTask(std::shared_ptr<HttpRequest> asyncHttpRequest)
{
	auto taskRequest = std::static_pointer_cast<HttpRequestWithTimeout>(asyncHttpRequest);
	m_task.sendTask(taskRequest);
}

bool Application::deleteTask()
{
	return m_task.deleteTask();
}

void Application::fetchTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest)
{
	std::shared_ptr<void> req = asyncHttpRequest; // TaskRequest takes shared_ptr<void>&
	m_task.fetchTask(processKey, req);
}

void Application::replyTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest)
{
	std::shared_ptr<void> req = asyncHttpRequest; // TaskRequest takes shared_ptr<void>&
	m_task.replyTask(processKey, req);
}

std::tuple<int, std::string> Application::taskStatus()
{
	return m_task.taskStatus();
}

std::string Application::currentProcessUuidForKey(const std::string &processKey)
{
	if (processKey.empty())
		return {};
	auto processLock = m_process.synchronize();
	if (!(*processLock) || !Utility::secureCompare((*processLock)->getkey(), processKey))
		return {};
	const auto run = m_runtime->load();
	if (run.id != (*processLock)->getuuid() ||
		(run.phase != Runtime::Run::Phase::Starting && run.phase != Runtime::Run::Phase::Running))
		return {};
	return (*processLock)->getuuid();
}

bool Application::isCurrentProcessUuid(const std::string &processUuid)
{
	if (processUuid.empty())
		return false;
	auto processLock = m_process.synchronize();
	if (!(*processLock) || !Utility::secureCompare((*processLock)->getuuid(), processUuid))
		return false;
	const auto run = m_runtime->load();
	return run.id == processUuid &&
		(run.phase == Runtime::Run::Phase::Starting || run.phase == Runtime::Run::Phase::Running);
}

const std::string Application::getExecUser() const
{
	if (m_kind == Kind::SystemAgent)
	{
		return "";
	}

#if defined(_WIN32)
	return "";
#else
	std::string executeUser = m_executionUser;
	if (executeUser.empty() && !Configuration::instance()->getDisableExecUser())
	{
		executeUser = Configuration::instance()->getDefaultExecUser();
	}

	if (executeUser.empty())
	{
		static const auto osUser = os::getUsernameByUid();
		executeUser = osUser;
	}
	return executeUser;
#endif
}

const std::string &Application::getCmdLine() const
{
	if (m_shellAppFile)
	{
		return m_shellAppFile->getShellStartCmd();
	}
	return m_commandLine;
}

void Application::healthCheck()
{
	if (m_healthCheckCmd.empty())
	{
		this->health(m_runtime->load().phase == Runtime::Run::Phase::Running);
	}
}

std::tuple<std::string, bool, int> Application::getOutput(long &position, long maxSize, const std::string &processUuid, int index, size_t timeout)
{
	const static char fname[] = "Application::getOutput() ";

	auto process = m_process.get();
	const bool matchesRun = process && (processUuid.empty() || process->getuuid() == processUuid);
	if (matchesRun && index == 0 && !process->isFinalized() && timeout > 0)
	{
		process->wait(ACE_Time_Value(static_cast<long>(timeout)));
	}

	bool finished = false;
	int exitCode = 0;

	if (process && index == 0)
	{
		if (!matchesRun)
		{
			throw NotFoundException("No corresponding process running or the given process uuid is wrong");
		}
		if (process->isFinalized())
		{
			exitCode = process->returnValue();
			finished = true;
			LOG_DBG << fname << "Process <" << process->getuuid() << "> finished with exit code <" << exitCode << ">";
		}
		auto output = process->getOutputMsg(&position, maxSize);
		return std::make_tuple(output, finished, exitCode);
	}

	// A caller asking for a specific run (process uuid, current index) while this app
	// hosts no run object would otherwise poll the stdout file forever without ever
	// receiving an exit status; fail fast instead so clients can distinguish "gone"
	// from "pending".
	if (!processUuid.empty() && index == 0)
	{
		throw NotFoundException("No corresponding process running or the given process uuid is wrong");
	}

	auto file = m_stdoutFileQueue->getFileName(index);
	return std::make_tuple(Utility::readFileCpp(file, &position, maxSize), finished, exitCode);
}

Application::RunCompletionSubscription Application::subscribeRunCompletion(
	const std::string &processUuid, RunCompletionCallback callback)
{
	if (!callback)
		return INVALID_RUN_COMPLETION_SUBSCRIPTION;

	std::lock_guard<std::mutex> guard(m_runtime->runMutex);
	const auto &run = m_runtime->run;
	if (run.id.empty() || (!processUuid.empty() && processUuid != run.id) ||
		run.phase == Runtime::Run::Phase::Completed)
	{
		return INVALID_RUN_COMPLETION_SUBSCRIPTION;
	}

	const auto subscription = m_runtime->nextCompletionSubscription++;
	m_runtime->completionCallbacks.push_back({subscription, run.id, std::move(callback)});
	return subscription;
}

void Application::unsubscribeRunCompletion(RunCompletionSubscription subscription)
{
	if (subscription == INVALID_RUN_COMPLETION_SUBSCRIPTION)
		return;
	RunCompletionCallback removedCallback;
	{
		std::lock_guard<std::mutex> guard(m_runtime->runMutex);
		for (auto it = m_runtime->completionCallbacks.begin(); it != m_runtime->completionCallbacks.end(); ++it)
		{
			if (it->id == subscription)
			{
				removedCallback = std::move(it->callback);
				m_runtime->completionCallbacks.erase(it);
				break;
			}
		}
	}
	// removedCallback and its captures are destroyed after runMutex is released.
}

void Application::initMetrics()
{
	const auto metrics = m_metrics;
	std::lock_guard<std::mutex> guard(metrics->mutex);
	if (metrics->startCount)
		return;
	resetMetricHandles(*metrics);
	metrics->owner = this;

	if (Configuration::instance()->prometheusEnabled())
	{
		// One-off names are unbounded; do not create Prometheus series for them.
		if (!isManaged())
			return;
		const std::map<std::string, std::string> labels = {{"application", getName()}};
		metrics->startCount = RESTHANDLER::instance()->createPromCounter(
			PROM_METRIC_NAME_appmesh_application_process_starts_total, PROM_METRIC_HELP_appmesh_application_process_starts_total, labels);
		metrics->startCount->metric().Increment(static_cast<double>(metrics->starts));
		// TODO: Add exit outcomes only when the lifecycle exposes one simple completion point.
		metrics->collectionError = RESTHANDLER::instance()->createPromCounter(
			PROM_METRIC_NAME_appmesh_application_metrics_collection_errors_total,
			PROM_METRIC_HELP_appmesh_application_metrics_collection_errors_total, labels);
		metrics->appPid = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_application_process_id, PROM_METRIC_HELP_appmesh_application_process_id, labels);
		metrics->memory = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_application_process_resident_memory_bytes, PROM_METRIC_HELP_appmesh_application_process_resident_memory_bytes, labels);
		metrics->cpu = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_application_process_cpu_usage_cores, PROM_METRIC_HELP_appmesh_application_process_cpu_usage_cores, labels);
		metrics->fileDesc = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_application_process_open_fds, PROM_METRIC_HELP_appmesh_application_process_open_fds, labels);
		metrics->enabled = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_application_enabled, PROM_METRIC_HELP_appmesh_application_enabled, labels);
		metrics->running = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_application_running, PROM_METRIC_HELP_appmesh_application_running, labels);
		metrics->healthy = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_application_healthy, PROM_METRIC_HELP_appmesh_application_healthy, labels);
	}
}

void Application::initMetrics(std::shared_ptr<Application> fromApp)
{
	if (!fromApp)
	{
		clearMetrics();
		return;
	}
	const auto registersApplicationMetrics = [](const Application &app)
	{ return app.isManaged(); };
	if (registersApplicationMetrics(*this) != registersApplicationMetrics(*fromApp))
	{
		fromApp->clearMetrics();
		initMetrics();
		return;
	}

	const auto inherited = fromApp->m_metrics;
	std::lock_guard<std::mutex> guard(inherited->mutex);
	inherited->owner = this;
	m_metrics = inherited;
}

void Application::clearMetrics()
{
	const auto metrics = m_metrics;
	std::lock_guard<std::mutex> guard(metrics->mutex);
	if (metrics->owner != this)
		return;
	metrics->owner = nullptr;
	resetMetricHandles(*metrics);
}

void Application::resetMetricHandles(MetricsState &metrics)
{
	metrics.startCount.reset();
	metrics.collectionError.reset();
	metrics.appPid.reset();
	metrics.memory.reset();
	metrics.cpu.reset();
	metrics.fileDesc.reset();
	metrics.enabled.reset();
	metrics.running.reset();
	metrics.healthy.reset();
}

nlohmann::json Application::AsJson(bool returnRuntimeInfo, void *ptree)
{
	const static char fname[] = "Application::AsJson() ";

	nlohmann::json result = nlohmann::json::object();

	LOG_DBG << fname << "Application: " << m_name;
	result[JSON_KEY_APP_name] = std::string(m_name);
	if (!m_ownerPrincipalId.empty())
	{
		result[JSON_KEY_APP_owner_principal_id] = m_ownerPrincipalId;
	}
	if (!m_executionUser.empty())
	{
		result[JSON_KEY_APP_execution_user] = m_executionUser;
	}
	if (m_kind == Kind::System)
		result[JSON_KEY_APP_system] = true;
	static const std::map<int, std::string> phaseNames = {
		{20, "auth-issuer"},
		{30, "ingress"}, {100, "normal"}};
	auto phaseName = phaseNames.find(m_startupPhase);
	if (phaseName != phaseNames.end() && m_startupPhase != 100)
		result[JSON_KEY_APP_startup_phase] = phaseName->second;
	if (m_ownerPermission)
	{
		result[JSON_KEY_APP_owner_permission] = (m_ownerPermission);
	}
	if (m_shellApp)
	{
		result[JSON_KEY_APP_shell_mode] = (m_shellApp);
	}
	if (m_sessionLogin)
	{
		result[JSON_KEY_APP_session_login] = (m_sessionLogin);
	}
	if (m_metadata != EMPTY_STR_JSON)
	{
		result[JSON_KEY_APP_metadata] = m_metadata;
	}
	if (!m_commandLine.empty())
	{
		result[(JSON_KEY_APP_command)] = std::string(m_commandLine);
	}
	if (!m_description.empty())
	{
		result[(JSON_KEY_APP_description)] = std::string(m_description);
	}
	if (m_stdoutCacheNum)
	{
		result[JSON_KEY_APP_stdout_cache_num] = (m_stdoutCacheNum);
	}
	if (!m_healthCheckCmd.empty())
	{
		result[(JSON_KEY_APP_health_check_cmd)] = std::string(m_healthCheckCmd);
	}
	if (!m_workdir.empty())
	{
		result[JSON_KEY_APP_working_dir] = std::string(m_workdir);
	}
	result[JSON_KEY_APP_status] = isEnabled();
	if (m_resourceLimit)
	{
		result[JSON_KEY_APP_resource_limit] = m_resourceLimit->AsJson();
	}
	if (m_envMap.size())
	{
		nlohmann::json envs = nlohmann::json::object();
		for (const auto &pair : m_envMap)
		{
			envs[pair.first] = std::string(pair.second);
		}
		result[JSON_KEY_APP_env] = std::move(envs);
	}
	if (m_secEnvMap.size() && !returnRuntimeInfo)
	{
		// Only include sec_env when saving to disk (not in API responses).
		nlohmann::json envs = nlohmann::json::object();
		for (const auto &pair : m_secEnvMap)
		{
			const std::string context = m_name + '\0' + pair.first;
			envs[pair.first] = SecretProtector::instance().protect(pair.second, context);
		}
		result[JSON_KEY_APP_sec_env] = std::move(envs);
	}
	if (!m_dockerImage.empty())
	{
		result[JSON_KEY_APP_docker_image] = std::string(m_dockerImage);
	}
	if (m_version)
	{
		result[JSON_KEY_APP_version] = (m_version);
	}
	if (m_startTime.time_since_epoch().count() && m_startTime != std::chrono::system_clock::time_point::min())
	{
		result[JSON_KEY_SHORT_APP_start_time] = (std::chrono::duration_cast<std::chrono::seconds>(m_startTime.time_since_epoch()).count());
	}
	if (m_endTime.time_since_epoch().count() && m_endTime != std::chrono::system_clock::time_point::max())
	{
		result[JSON_KEY_SHORT_APP_end_time] = (std::chrono::duration_cast<std::chrono::seconds>(m_endTime.time_since_epoch()).count());
	}
	if (m_dailyLimit)
	{
		result[JSON_KEY_APP_daily_limitation] = m_dailyLimit->AsJson();
	}
	result[JSON_KEY_APP_REG_TIME] = (std::chrono::duration_cast<std::chrono::seconds>(m_regTime.time_since_epoch()).count());
	result[JSON_KEY_APP_behavior] = this->behaviorAsJson();
	if (m_bufferTime)
	{
		result[JSON_KEY_APP_retention] = std::string(m_bufferTimeValue);
	}
	if (m_scheduleKind == ScheduleKind::Cron)
	{
		result[JSON_KEY_SHORT_APP_cron_interval] = true;
	}
	if (!m_startIntervalValue.empty())
	{
		result[JSON_KEY_SHORT_APP_start_interval_seconds] = std::string(m_startIntervalValue);
	}

	if (returnRuntimeInfo)
	{
		// Starts are published after the corresponding run state. Sample them first
		// so a response cannot combine a new count with the previous run's PID.
		unsigned long long starts = 0;
		{
			const auto metrics = m_metrics;
			std::lock_guard<std::mutex> guard(metrics->mutex);
			starts = metrics->starts;
		}
		auto run = m_runtime->load();
		auto process = m_process.get();
		if (run.returnCode != INVALID_RETURN_CODE)
		{
			result[JSON_KEY_APP_return] = run.returnCode;
		}
		if (process && process->running())
		{
			auto status = m_task.taskStatus();
			result[JSON_KEY_APP_task_id] = std::get<0>(status);
			result[JSON_KEY_APP_task_status] = std::get<1>(status);
			// Spawn races the run-state store: the process can be running before r.pid is
			// published (still ACE_INVALID_PID from the previous exit). Omit pid until valid.
			if (run.pid != ACE_INVALID_PID)
			{
				result[JSON_KEY_APP_pid] = run.pid;
				result[JSON_KEY_APP_pid_user] = os::getUsernameByUid(os::getProcessUid(run.pid));
			}

			auto usage = process->getProcessDetails(ptree);
			if (std::get<0>(usage))
			{
				result[JSON_KEY_APP_memory] = (std::get<1>(usage));
				result[JSON_KEY_APP_cpu] = (std::get<2>(usage));
				result[JSON_KEY_APP_open_fd] = (std::get<3>(usage));
				result[JSON_KEY_APP_pstree] = std::string(std::get<4>(usage));
				if (m_shellAppFile)
				{
					auto leafProcessUser = os::getUsernameByUid(os::getProcessUid(std::get<5>(usage)));
					if (!leafProcessUser.empty())
					{
						result[JSON_KEY_APP_pid_user] = leafProcessUser;
					}
				}
			}
		}
		auto startTime = run.startTime;
		if (startTime && std::chrono::time_point_cast<std::chrono::hours>(*startTime).time_since_epoch().count() > 24)
		{
			result[JSON_KEY_APP_last_start] = std::chrono::duration_cast<std::chrono::seconds>((*startTime).time_since_epoch()).count();
		}
		auto exitTime = run.exitTime;
		if (exitTime && std::chrono::time_point_cast<std::chrono::hours>(*exitTime).time_since_epoch().count() > 24)
		{
			result[JSON_KEY_APP_last_exit] = std::chrono::duration_cast<std::chrono::seconds>((*exitTime).time_since_epoch()).count();
		}
		const auto containerId = process ? process->containerId() : std::string();
		if (!containerId.empty())
		{
			result[JSON_KEY_APP_container_id] = containerId;
		}
		result[JSON_KEY_APP_health] = (this->health());
		if (m_stdoutFileQueue->size())
		{
			result[JSON_KEY_APP_stdout_cache_size] = (m_stdoutFileQueue->size());
		}
		auto err = getLastError();
		if (!err.empty())
		{
			result[JSON_KEY_APP_last_error] = std::string(err);
		}
		result[JSON_KEY_APP_starts] = static_cast<long long>(starts);
		auto nextLaunch = run.nextLaunch;
		if (nextLaunch)
		{
			result[JSON_KEY_SHORT_APP_next_start_time] = std::chrono::duration_cast<std::chrono::seconds>((*nextLaunch).time_since_epoch()).count();
		}
	}

	Utility::addExtraAppTimeReferStr(result);
	return result;
}

void Application::save()
{
	const static char fname[] = "Application::save() ";

	if (!this->isPersistAble())
		return;

	std::lock_guard<std::mutex> guard(m_saveMutex);
	const auto appPath = getYamlPath();
	uint16_t mode = 0644;
#if !defined(_WIN32)
	if (Utility::isFileExist(appPath))
	{
		const int existingMode = std::get<0>(os::fileStat(appPath));
		if (existingMode >= 0)
			mode = static_cast<uint16_t>(existingMode);
	}
#endif
	const auto content = Utility::jsonToYaml(AsJson(false)) + "\n";
	const auto tempPath = os::createTmpFile(appPath, content, mode);
	if (tempPath.empty())
	{
		LOG_ERR << fname << "Failed to create a temporary file for application <" << m_name << ">";
		throw std::invalid_argument("failed to save application, please check your app name or folder permission");
	}
	if (ACE_OS::rename(tempPath.c_str(), appPath.c_str()) != 0)
	{
		const auto error = last_error_msg();
		Utility::removeFile(tempPath);
		LOG_ERR << fname << "Failed to save application <" << m_name << "> to file <" << appPath << ">, error: " << error;
		throw std::invalid_argument("failed to save application, please check your app name or folder permission");
	}
	LOG_INF << fname << "Saved application <" << m_name << "> to file <" << appPath << ">";
}

std::string Application::getYamlPath()
{
	return (fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_APPLICATION_DIR / (getName() + ".yaml")).string();
}

void Application::remove()
{
	Utility::removeFile(getYamlPath());
	Utility::removeFile((fs::path(Utility::getHomeDir()) / APPMESH_APPLICATION_DIR / (getName() + ".yaml")).string());
}

void Application::dump()
{
	const static char fname[] = "Application::dump() ";

	LOG_DBG << fname << "m_name:" << m_name;
	LOG_DBG << fname << "m_commandLine:" << m_commandLine;
	LOG_DBG << fname << "m_description:" << m_description;
	LOG_DBG << fname << "m_metadata:" << m_metadata;
	LOG_DBG << fname << "m_shellApp:" << m_shellApp;
	LOG_DBG << fname << "m_sessionLogin:" << m_sessionLogin;
	LOG_DBG << fname << "behavior:" << behaviorAsJson();
	LOG_DBG << fname << "m_workdir:" << m_workdir;
	LOG_DBG << fname << "m_ownerPrincipalId:" << m_ownerPrincipalId;
	LOG_DBG << fname << "m_executionUser:" << m_executionUser;
	LOG_DBG << fname << "m_permission:" << m_ownerPermission;
	LOG_DBG << fname << "m_status:" << (int)m_status.load();
	const auto dumpPid = m_runtime->load().pid;
	if (dumpPid != ACE_INVALID_PID)
	{
		LOG_DBG << fname << "m_pid:" << dumpPid;
	}
	LOG_DBG << fname << "m_startTimeValue:" << DateTime::formatLocalTime(m_startTime);
	LOG_DBG << fname << "m_endTimeValue:" << DateTime::formatLocalTime(m_endTime);
	LOG_DBG << fname << "m_regTime:" << DateTime::formatLocalTime(m_regTime);
	LOG_DBG << fname << "m_dockerImage:" << m_dockerImage;
	LOG_DBG << fname << "m_stdoutFile:" << m_stdoutFile;
	{
		const auto metrics = m_metrics;
		std::lock_guard<std::mutex> guard(metrics->mutex);
		LOG_DBG << fname << "m_starts:" << metrics->starts;
	}
	LOG_DBG << fname << "m_version:" << m_version;
	LOG_DBG << fname << "m_lastError:" << getLastError();
	LOG_DBG << fname << "m_startInterval:" << m_startInterval;
	LOG_DBG << fname << "m_bufferTime:" << m_bufferTime;

	auto nextLaunchTime = m_runtime->load().nextLaunch;
	if (nextLaunchTime)
	{
		LOG_DBG << fname << "nextLaunch:" << DateTime::formatLocalTime(*nextLaunchTime);
	}
	if (m_dailyLimit)
	{
		m_dailyLimit->dump();
	}
	if (m_resourceLimit)
	{
		m_resourceLimit->dump();
	}
}

std::shared_ptr<AppProcess> Application::createProcess(const std::string &dockerImage, const std::string &appName)
{
	std::shared_ptr<AppProcess> process;
	const auto weakSelf = std::weak_ptr<Application>(std::dynamic_pointer_cast<Application>(shared_from_this()));
	m_stdoutFileQueue->enqueue();

	if ((m_shellApp || m_sessionLogin) && (m_shellAppFile == nullptr || !Utility::isFileExist(m_shellAppFile->getShellFileName())))
	{
		m_shellAppFile.reset();
		m_shellAppFile = std::make_shared<ShellAppFileGen>(appName, m_commandLine, getExecUser(), m_sessionLogin, m_workdir);
	}

	if (!dockerImage.empty())
	{
#if !defined(_WIN32)
		if (m_envMap.count(ENV_APPMESH_DOCKER_PARAMS) == 0)
		{
			process = std::make_shared<DockerApiProcess>(weakSelf, appName, dockerImage);
		}
		else
		{
			process = std::make_shared<DockerProcess>(weakSelf, appName, dockerImage);
		}
#else
		throw std::invalid_argument("Docker application does not support on Windows");
#endif
	}
	else
	{
		process = std::make_shared<AppProcess>(weakSelf);
	}
	return process;
}

void Application::destroy()
{
	const static char fname[] = "Application::destroy() ";

	LOG_DBG << fname << "suicide timer ID: " << m_timerRemoveId.load();
	this->disable(); // clears nextLaunch + sets DISABLED, so the tick won't start it
	{
		std::lock_guard<std::mutex> lifecycleGuard(m_runtime->lifecycleMutex);
		this->m_status.store(STATUS::NOTAVAILABLE);
		++m_runtime->lifecycleGeneration;
		m_runtime->suspendSchedule();
	}
	// disable() is a no-op when the app was already disabled; removal still stops every run.
	this->stopAllProcesses();
	this->cancelTimer(m_timerRemoveId);
}

bool Application::onTimerRemoval()
{
	const static char fname[] = "Application::onTimerRemoval() ";

	try
	{
		Configuration::instance()->removeApp(m_name, this);
	}
	catch (...)
	{
		LOG_CRT << fname << "FATAL: failed to remove application <" << m_name << ">";
	}
	return false;
}

void Application::recordProcessExit(int code, bool naturalExit, AppProcess *reporter, long stdoutDispatchedBytes)
{
	const auto runId = reporter->getuuid();
	const pid_t prevPid = reporter->lastPid();
	std::string exitError;
	if (code != 0 && naturalExit)
	{
		const auto error = reporter->startError();
		exitError = error.empty()
						? Utility::stringFormat("exited with return code: %d", code)
						: Utility::stringFormat("exited with return code: %d, msg: %s", code, error.c_str());
	}

	// Commit lifecycle state before best-effort output/event side effects.
	const auto now = std::chrono::system_clock::now();
	const bool dockerImagePull = !m_dockerImage.empty() && reporter->containerId().empty();
	bool currentRun = false;
	{
		std::lock_guard<std::mutex> lifecycleGuard(m_runtime->lifecycleMutex);
		const bool enabled = isEnabled();
		m_runtime->update([&](Runtime::Run &state)
						  {
			if (state.id != runId)
				return;
			const bool currentGeneration = state.lifecycleGeneration == m_runtime->lifecycleGeneration;
			// A successful Docker pull is an intermediate run: accepted containers always
			// publish their container ID before exit, while the pull process has none.
			const bool imagePullCompleted = naturalExit && enabled && currentGeneration && code == 0 && dockerImagePull;
			state.pid = ACE_INVALID_PID;
			state.phase = Runtime::Run::Phase::Finalizing;
			state.exitTime = now;
			state.returnCode = code;
			state.restartEvaluationPending = naturalExit && enabled && currentGeneration && !imagePullCompleted;
			if (imagePullCompleted)
			{
				state.nextLaunch = now;
				state.scheduleIntent = Runtime::Run::ScheduleIntent::Armed;
			}
			currentRun = true; });
	}
	if (currentRun)
	{
		if (!exitError.empty())
			setLastError(exitError);
		health(false);
		m_task.terminate();
	}

	EventDispatcher::instance()->flushStdout(m_name, reporter, stdoutDispatchedBytes);
	EventDispatcher::instance()->dispatch(m_name, AppEventType::PROCESS_EXIT,
										  {{"exit_code", code}, {"pid", prevPid}, {"last_error", currentRun ? getLastError() : exitError}});
}

void Application::completeRun(const std::string &runId)
{
	std::list<Runtime::CompletionSubscription> callbacks;
	{
		std::lock_guard<std::mutex> guard(m_runtime->runMutex);
		auto &run = m_runtime->run;
		if (run.id == runId && run.phase == Runtime::Run::Phase::Finalizing)
			run.phase = Runtime::Run::Phase::Completed;

		for (auto it = m_runtime->completionCallbacks.begin(); it != m_runtime->completionCallbacks.end();)
		{
			if (it->runId == runId)
			{
				auto current = it++;
				callbacks.splice(callbacks.end(), m_runtime->completionCallbacks, current);
			}
			else
			{
				++it;
			}
		}
	}

	for (auto &entry : callbacks)
	{
		try
		{
			entry.callback();
		}
		catch (...)
		{
			LOG_CRT << "Application::completeRun() FATAL: completion callback failed for run <" << runId << ">";
		}
	}
}

void Application::terminate(std::shared_ptr<AppProcess> p)
{
	if (p)
	{
		const auto runId = p->getuuid();
		m_runtime->update([&](Runtime::Run &run)
						  {
			if (run.id == runId && (run.phase == Runtime::Run::Phase::Starting || run.phase == Runtime::Run::Phase::Running))
				run.phase = Runtime::Run::Phase::StopRequested; });
		p->terminate();
	}

	m_task.terminate();
}

void Application::applyExitPolicy()
{
	const static char fname[] = "Application::applyExitPolicy() ";
	bool psk = false;

	switch (this->exitAction(m_runtime->load().returnCode))
	{
	case AppBehavior::Action::STANDBY:
		// do nothing
		break;
	case AppBehavior::Action::RESTART:
		if (m_kind == Kind::SystemAgent)
		{
			const auto shmName = HMACVerifierSingleton::instance()->writePSKToSHM();
			if (!shmName.empty())
			{
				m_envMap[ENV_PSK_SHM] = shmName;
				psk = true;
			}
		}

		// Restart after the crash-loop backoff delay (0 for a healthy run).
		this->scheduleNext(std::chrono::system_clock::now() + restartDelay());
		LOG_DBG << fname << "Next action for <" << m_name << "> is RESTART";

		if (psk)
		{
			// Async: we may BE the single timer-dispatch thread, which must stay free to fire
			// the spawn armed above; a blocking wait here would deadlock the PSK handshake.
			HMACVerifierSingleton::instance()->waitPSKReadAsync();
		}
		break;
	case AppBehavior::Action::KEEPALIVE:
		// Restart unconditionally (bypasses m_timer), still throttled by the crash-loop backoff.
		scheduleStartAt(std::chrono::system_clock::now() + restartDelay());
		LOG_DBG << fname << "Next action for <" << m_name << "> is KEEPALIVE";
		break;
	case AppBehavior::Action::REMOVE:
		m_runtime->suspendSchedule();
		this->scheduleRemoval(m_bufferTime);
		LOG_DBG << fname << "Next action for <" << m_name << "> is REMOVE";
		break;
	default:
		break;
	}
}

std::chrono::seconds Application::restartDelay()
{
	// Crash-loop backoff applies only to long-running apps. Periodic/cron runs are already
	// spaced by their own schedule (and are typically short), so adding backoff would skip
	// occurrences and wrongly penalize healthy short tasks.
	if (isRecurring())
	{
		return std::chrono::seconds(0);
	}

	auto run = m_runtime->load();
	const auto ranFor = (run.startTime && run.exitTime)
							? std::chrono::duration_cast<std::chrono::seconds>(*run.exitTime - *run.startTime)
							: std::chrono::seconds(0);
	return m_runtime->restartBackoff.onExit(ranFor);
}

void Application::scheduleStartAt(const std::chrono::system_clock::time_point &when)
{
	const static char fname[] = "Application::scheduleStartAt() ";

	// Record-only: no timer. The scheduler tick claims and starts it when `when`
	// is reached, keeping fork/exec off the shared timer thread.
	m_runtime->update([&](Runtime::Run &run)
					  {
		run.nextLaunch = when;
		run.scheduleIntent = Runtime::Run::ScheduleIntent::Armed; });
	LOG_DBG << fname << "Next start for <" << m_name << "> scheduled at " << DateTime::formatLocalTime(when);
}

std::uint64_t Application::consumeScheduledStart(const std::chrono::system_clock::time_point &now)
{
	if (!this->isEnabled())
	{
		m_runtime->suspendSchedule();
		return 0;
	}
	const auto next = m_runtime->load().nextLaunch;
	if (!next || now < *next)
		return 0;
	if (!m_timer->isInDailyTimeRange(now))
	{
		scheduleNext(now);
		return 0;
	}
	{
		auto processLock = m_process.synchronize();
		const auto &process = *processLock;
		if (process && !process->isFinalized())
		{
			const bool replaceRecurringRun =
				isRecurring() && process->isStartAccepted() && process->canReportExit() && process->running();
			if (!replaceRecurringRun)
				return 0;
		}
	}
	m_runtime->suspendSchedule();
	return m_runtime->lifecycleGeneration;
}

void Application::scheduleNext(std::chrono::system_clock::time_point startFrom)
{
	// Resolve the start-form's next occurrence; backoff spacing is already baked into startFrom.
	const auto next = m_timer->nextTime(startFrom);
	if (next == AppTimer::TIME_UNSET)
	{
		// The immutable start/end/daily schedule has no future occurrence.
		m_runtime->suspendSchedule();
		return;
	}
	scheduleStartAt(next);
}

void Application::scheduleRemoval(int timeoutSeconds)
{
	const static char fname[] = "Application::scheduleRemoval() ";

	LOG_DBG << fname << "Application <" << getName() << "> will be removed after <" << timeoutSeconds << "> seconds";
	this->registerTimer(m_timerRemoveId, 1000L * timeoutSeconds, 0, fname, std::bind(&Application::onTimerRemoval, this));
}

void Application::setLastError(const std::string &error)
{
	const static char fname[] = "Application::setLastError() ";

	auto lockedStr = m_lastError.synchronize();
	if (error != *lockedStr)
	{
		if (!error.empty())
		{
			*lockedStr = Utility::stringFormat("%s %s",
											   DateTime::formatLocalTime(std::chrono::system_clock::now()).c_str(), error.c_str());
			LOG_DBG << fname << "Last error for <" << getName() << ">: " << error;
		}
		else
		{
			*lockedStr = "";
		}
	}
}

const std::string Application::getLastError() const
{
	auto lockedStr = m_lastError.synchronize();
	return *lockedStr;
}

void Application::setUnavailableError()
{
	if (!this->isEnabled())
	{
		setLastError("not enabled");
	}
	else
	{
		setLastError("outside valid time range");
	}
}

std::map<std::string, std::string> Application::getMergedEnvMap() const
{
	auto envMap = m_envMap;
	for (const auto &pair : m_secEnvMap)
	{
		envMap[pair.first] = pair.second;
	}
	return envMap;
}
