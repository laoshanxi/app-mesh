// src/daemon/application/Application.cpp
#include <cassert>
#include <limits>

#include <boost/smart_ptr/make_shared.hpp>
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
#include "../process/MonitoredProcess.h"
#include "../rest/EventDispatcher.h"
#include "../rest/RestHandler.h"
#include "../security/HMACVerifier.h"
#include "../security/Security.h"
#include "../security/User.h"
#include "AppTimer.h"
#include "Application.h"

namespace
{
	constexpr int INVALID_RETURN_CODE = std::numeric_limits<int>::min();
	// Gap before a periodic app's next self-armed spawn: the current run already started this
	// second, so arm from the next second to avoid a same-second double computation.
	constexpr std::chrono::seconds PERIODIC_RESPAWN_GAP{1};
}

Application::Application()
	: m_persistAble(true), m_ownerPermission(0), m_metadata(EMPTY_STR_JSON),
	  m_shellApp(false), m_sessionLogin(false), m_stdoutCacheNum(0),
	  m_startTime(AppTimer::TIME_UNSET), m_endTime(std::chrono::system_clock::time_point::max()),
	  m_startInterval(0), m_bufferTime(0), m_startIntervalValueIsCronExpr(false),
	  m_regTime(std::chrono::system_clock::now()),
	  m_appId(Utility::shortID()), m_version(0), m_timerRemoveId(INVALID_TIMER_ID),
	  m_health(true),
	  m_status(STATUS::ENABLED), m_metrics(std::make_shared<MetricsState>())
{
	const static char fname[] = "Application::Application() ";
	m_run.pid = ACE_INVALID_PID;
	m_run.returnCode = INVALID_RETURN_CODE;
	m_metrics->owner = this;
	m_needsSchedule.store(true); // never scheduled yet
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
	return loadRunState().pid;
}

int Application::health() const
{
	return 1 - m_health.load();
}

bool Application::isEnabled() const
{
	return (m_status.load() == STATUS::ENABLED);
}

const std::string &Application::healthCheckCmd() const
{
	return m_healthCheckCmd;
}

const std::shared_ptr<User> &Application::getOwner() const
{
	return m_owner;
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
	return m_persistAble;
}

void Application::setUnPersistable()
{
	m_persistAble = false;
}

void Application::nextLaunchTime(const std::chrono::system_clock::time_point &time)
{
	auto value = (time == AppTimer::TIME_UNSET)
					 ? boost::shared_ptr<std::chrono::system_clock::time_point>()
					 : boost::make_shared<std::chrono::system_clock::time_point>(time);
	updateRunState([&](RunState &r) { r.nextLaunch = value; });
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

	auto ownerStr = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_owner));
	if (!ownerStr.empty())
	{
		app->m_owner = Security::instance()->getUserInfo(ownerStr);
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
		app->m_status.store(static_cast<STATUS>(GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_status)));
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
			if (fromRecover && app->m_owner)
			{
				app->m_secEnvMap[env.key()] = app->m_owner->decrypt(env.value().get<std::string>());
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
		app->m_startIntervalValueIsCronExpr = GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_SHORT_APP_cron_interval);
		app->m_startIntervalValue = GET_JSON_STR_INT_TEXT(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds);

		if (app->m_startIntervalValueIsCronExpr)
		{
			app->m_timer = std::make_shared<AppTimerCron>(app->m_startTime, app->m_endTime, app->m_dailyLimit, app->m_startIntervalValue, app->m_startInterval);
			app->m_timer->nextTime(); // Validate cron expression
		}
		else
		{
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
		app->m_timer = std::make_shared<AppTimer>(app->m_startTime, app->m_endTime, app->m_dailyLimit);
	}
}

void Application::refresh()
{
	std::shared_ptr<AppProcess> exitedProcess;
	{
		auto lock = m_process.synchronize();
		if (m_bufferProcess && !m_bufferProcess->running())
		{
			m_bufferProcess.reset();
		}
		const auto process = *lock;
		const pid_t pid = process ? process->getpid() : ACE_INVALID_PID;
		// Recovered and Docker processes are attached, so no reactor exit callback is available.
		const bool lacksReactorExitCallback = process && (process->isRecovered() || !m_dockerImage.empty());
		// Another exit path may already have claimed the process.
		const bool isExitUnclaimed = process && process->m_exitPhase.load(std::memory_order_acquire) == AppProcess::ExitPhase::Active;
		// A valid PID excludes a Docker start that failed before host-PID attachment.
		const bool hasValidPid = pid > 1;
		if (lacksReactorExitCallback && isExitUnclaimed && hasValidPid && !AppProcess::running(pid))
		{
			// Potentially blocking Docker inspection runs after releasing the process gate.
			// TODO: Docker event subscription could replace this host-PID polling path.
			exitedProcess = process;
		}
	}

	if (exitedProcess)
	{
		// A recovered PID is not our child, so its real exit status cannot be obtained.
		const int exitCode = exitedProcess->isRecovered() ? 0 : exitedProcess->returnValue();
		exitedProcess->onExit(exitCode);
	}

	// Health check
	healthCheck();
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
	const auto run = loadRunState();
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
	{
		auto processLock = m_process.synchronize();
		// Idempotent: re-attaching the pid we already hold alive must not kill it.
		if ((*processLock) && (*processLock)->getpid() == pid && (*processLock)->running())
		{
			return true;
		}
		this->terminate(*processLock);
		(*processLock) = allocProcess(false, m_dockerImage, m_name);
		(*processLock)->attach(pid, m_stdoutFile);
		(*processLock)->markRecovered(); // not our child: refresh() polls for its exit
		attached = (*processLock);
	}

	// 2. Probe liveness (Windows: no probe -> treated as dead)
	const pid_t attachedPid = attached->getpid();
	auto procStartTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
	bool live = false;
#if !defined(_WIN32)
	if (auto stat = os::status(attachedPid))
	{
		live = true;
		procStartTime = boost::make_shared<std::chrono::system_clock::time_point>(stat->get_starttime());
	}
#endif

	// 3. Publish the recovered run-state as one consistent snapshot
	updateRunState([&](RunState &r) {
		r.pid = attachedPid;
		r.startTime = procStartTime;
		r.returnCode = INVALID_RETURN_CODE;
		r.exitTime = nullptr;
		r.exitPending = false;
	});
	if (live)
	{
		// Already running: suppress (re)scheduling so we don't restart what we attached to.
		nextLaunchTime(*procStartTime);
		m_needsSchedule.store(false);
	} // dead: intent stays true, the tick starts it normally

	LOG_INF << fname << "Attached pid <" << pid << "> to application <" << m_name
			<< ">, last start on <" << DateTime::formatLocalTime(*procStartTime) << ">";

	// 4. Stdout follow-up, outside the m_process lock
	if (live && attached->running())
	{
		attached->registerCheckStdoutTimer();
	}
	return live;
}

void Application::handleUnavailable(const std::chrono::system_clock::time_point &now)
{
	const static char fname[] = "Application::handleUnavailable() ";

	if (this->available(now))
	{
		// Running outside the daily time range: stop until the range re-opens.
		if (!m_timer->isInDailyTimeRange(now) && forceStop())
		{
			LOG_INF << fname << "Application <" << m_name << "> stopped: outside its daily time range, startTime <"
					<< DateTime::formatLocalTime(m_startTime) << ">, endTime <" << DateTime::formatLocalTime(m_endTime)
					<< ">, now <" << DateTime::formatLocalTime(now) << ">";
		}
	}
	else if (getStatus() != STATUS::NOTAVAILABLE) // NOTAVAILABLE: runApp temp apps and destroying
	{
		if (forceStop())
		{
			LOG_INF << fname << "Application <" << m_name << "> stopped: no longer available";
		}
	}
}

bool Application::forceStop()
{
	auto processLock = m_process.synchronize();
	if (!(*processLock) || !(*processLock)->running())
	{
		return false;
	}
	terminate(*processLock);
	setInvalidError();
	nextLaunchTime(AppTimer::TIME_UNSET);
	m_needsSchedule.store(true); // (re)schedule when eligible again
	return true;
}

void Application::handleScheduling(const std::chrono::system_clock::time_point &now)
{
	// (re)schedule when the intent flag is set (first run, or after a force-stop). Periodic
	// apps self-arm their next run in spawnNow, cron apps re-arm via handleError's RESTART,
	// so no fabricated "previous run" is needed here.
	if (this->available(now) && m_needsSchedule.load())
	{
		scheduleNext(now);
	}
}

bool Application::consumePendingExit()
{
	if (getStatus() != STATUS::ENABLED)
	{
		return false; // disabled apps do not auto-handle exits
	}

	auto process = m_process.get();
	if (process && process->running())
	{
		// Defensive: a new run may have started between the exit and this check.
		return false;
	}

	// Test-and-clear the latch: handleError() runs exactly once per genuine exit.
	bool consumed = false;
	updateRunState([&](RunState &r) {
		if (r.exitPending)
		{
			r.exitPending = false;
			consumed = true;
		}
	});
	return consumed;
}

void Application::execute(void *ptree, bool refreshMetrics)
{
	// Periodic tick trigger.
	driveLifecycle(std::chrono::system_clock::now());
	// All applications in this scheduler pass reuse the same process snapshot.
	collectMetrics(ptree, refreshMetrics);
}

void Application::driveLifecycle(const std::chrono::system_clock::time_point &now)
{
	// Serialize driveLifecycle for this app (tick vs. exit-driven). Lock order:
	// m_lifecycleMutex -> m_process -> m_runMutex. Timer-queue ops below are safe under it
	// because timer upcalls release the queue lock before invoking handlers.
	std::lock_guard<std::mutex> lifecycleGuard(m_lifecycleMutex);

	// [1] Terminates running processes when the app is unavailable or outside its daily time range
	handleUnavailable(now);

	// [2] First-time / post-stop scheduling.
	handleScheduling(now);

	// [3] Refresh application state (health check + buffer-process cleanup)
	refresh();

	// [4] Apply the exit behavior exactly once per genuine exit (latch test-and-clear).
	if (consumePendingExit())
	{
		handleError();
	}

	// [5] Start the process if its scheduled launch is now due (on this scheduler thread,
	//     not the shared timer thread). Runs last so a just-scheduled "due now" starts here.
	spawnIfDue(now);
}

void Application::spawnNow()
{
	const static char fname[] = "Application::spawnNow() ";

	// Runs on the scheduler-tick thread (via spawnIfDue), never the shared timer thread.
	std::shared_ptr<AppProcess> checkProcStdoutFile;
	pid_t spawnedPid = 0;
	std::string processUuid;
	if (!this->isEnabled())
	{
		// Skipped while disabled: restore the intent so a later enable() re-arms via the tick.
		m_needsSchedule.store(true);
	}
	else
	{
		try
		{
			auto processLock = m_process.synchronize();

			// 1. Clean old process
			if ((*processLock) && (*processLock)->running())
			{
				if (m_bufferTime > 0)
				{
					// Give some time for buffer process
					m_bufferProcess = (*processLock);
					m_bufferProcess->delayKill(m_bufferTime, __FUNCTION__);
				}
				else
				{
					// Direct kill old process
					terminate(*processLock);
				}
			}

			// 2. Start new process
			(*processLock).reset();
			(*processLock) = allocProcess(false, m_dockerImage, m_name);

			// Publish a clean Running state so no stale return/exitTime is observable for the new run.
			updateRunState([&](RunState &r) {
				r.startTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
				r.returnCode = INVALID_RETURN_CODE;
				r.exitTime = nullptr;
				r.exitPending = false;
			});
			const auto execUser = (m_shellAppFile && m_shellAppFile->isUsingSudo()) ? std::string() : getExecUser();
			LOG_INF << fname << "Starting application <" << m_name << "> with user <" << execUser << ">";

			const pid_t newPid = (*processLock)->spawnProcess(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata, APP_STD_OUT_MAX_FILE_SIZE);
			updateRunState([&](RunState &r) { r.pid = newPid; });
			if (newPid > 0)
			{
				checkProcStdoutFile = (*processLock);
				spawnedPid = newPid;
				processUuid = (*processLock)->getuuid();
			}
			else
			{
				// Spawn failed: no process and no exit upcall, so restore the intent for a tick retry.
				m_needsSchedule.store(true);
			}

			// 3. Post process
			setLastError((*processLock)->startError());
		}
		catch (...)
		{
			m_needsSchedule.store(true);
			throw;
		}
	}

	// Dispatch event outside m_process lock to avoid blocking other threads
	if (spawnedPid > 0)
	{
		EventDispatcher::instance()->dispatch(m_name, AppEventType::PROCESS_START, {{"pid", spawnedPid}, {"process_uuid", processUuid}});
	}

	// 4. Record the next periodic occurrence (the tick spawns it when due).
	// Cron schedules carry m_startInterval == 0, so check the cron flag too (cf. restartDelay()).
	if (this->isEnabled() && (m_startInterval > 0 || m_startIntervalValueIsCronExpr))
	{
		this->scheduleNext(std::chrono::system_clock::now() + PERIODIC_RESPAWN_GAP);
	}

	// 5. registerCheckStdoutTimer() outside the m_process lock
	if (checkProcStdoutFile)
	{
		checkProcStdoutFile->registerCheckStdoutTimer();
	}
}

void Application::disable()
{
	const static char fname[] = "Application::disable() ";

	auto enabled = STATUS::ENABLED;
	if (!m_status.compare_exchange_strong(enabled, STATUS::DISABLED))
		return;

	LOG_INF << fname << "Application <" << m_name << "> disabled.";
	EventDispatcher::instance()->dispatch(m_name, AppEventType::STATUS_CHANGE, {{"status", "disabled"}, {"previous_status", "enabled"}});

	terminate(*m_process.synchronize());
	// Clear the scheduled launch so the tick won't start it; status=DISABLED also gates spawnIfDue.
	nextLaunchTime(AppTimer::TIME_UNSET);
	m_needsSchedule.store(true); // so a later enable() reschedules (gated by available())
}

void Application::enable()
{
	auto disabled = STATUS::DISABLED;
	if (m_status.compare_exchange_strong(disabled, STATUS::ENABLED))
	{
		EventDispatcher::instance()->dispatch(m_name, AppEventType::STATUS_CHANGE, {{"status", "enabled"}, {"previous_status", "disabled"}});
	}
}

std::string Application::runAsync(int timeoutSeconds)
{
	const static char fname[] = "Application::runAsync() ";
	LOG_DBG << fname << "Entered.";

	// Guard before terminate(): must not destroy the existing process and then throw.
	if (m_status.load() == STATUS::ENABLED)
	{
		throw std::invalid_argument("runApp is only for on-demand run apps, not an enabled application");
	}

	auto processLock = m_process.synchronize();
	terminate(*processLock);
	(*processLock) = allocProcess(false, m_dockerImage, m_name);
	return runApp(timeoutSeconds);
}

std::string Application::runSync(int timeoutSeconds, std::shared_ptr<HttpRequest> asyncHttpRequest)
{
	const static char fname[] = "Application::runSync() ";
	LOG_DBG << fname << "Entered.";

	// Guard before terminate(): must not destroy the existing process and then throw.
	if (m_status.load() == STATUS::ENABLED)
	{
		throw std::invalid_argument("runApp is only for on-demand run apps, not an enabled application");
	}

	auto processLock = m_process.synchronize();
	terminate(*processLock);
	(*processLock) = allocProcess(true, m_dockerImage, m_name);
	auto monitorProc = std::dynamic_pointer_cast<MonitoredProcess>(*processLock);
	if (monitorProc)
	{
		monitorProc->setAsyncHttpRequest(asyncHttpRequest);
	}
	else
	{
		LOG_WAR << fname << "Process for application <" << m_name << "> is not a MonitoredProcess, async output is unavailable";
	}

	return runApp(timeoutSeconds);
}

std::string Application::runApp(int timeoutSeconds)
{
	const static char fname[] = "Application::runApp() ";
	LOG_DBG << fname << "Entered.";

	auto processLock = m_process.synchronize();
	if (!m_dockerImage.empty())
	{
		throw std::invalid_argument("Docker application does not support this API");
	}
	// Run-on-demand only: parseAndRegRunApp registers these apps as NOTAVAILABLE. Guard always-on
	// (not a debug assert) so an ENABLED/managed app can never be hijacked into a one-off run.
	if (m_status.load() == STATUS::ENABLED)
	{
		throw std::invalid_argument("runApp is only for on-demand run apps, not an enabled application");
	}

	const auto execUser = getExecUser();
	LOG_INF << fname << "Running application <" << m_name << "> with timeout <" << timeoutSeconds << "> seconds";

	// New run begins: publish a clean Running state (see spawnNow for rationale).
	updateRunState([&](RunState &r) {
		r.startTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
		r.returnCode = INVALID_RETURN_CODE;
		r.exitTime = nullptr;
		r.exitPending = false;
	});
	const pid_t newPid = (*processLock)->spawnProcess(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata, APP_STD_OUT_MAX_FILE_SIZE);
	updateRunState([&](RunState &r) { r.pid = newPid; });
	setLastError((*processLock)->startError());

	if (newPid > 0)
	{
		this->health(true);
		if (timeoutSeconds > 0)
		{
			(*processLock)->delayKill(timeoutSeconds, fname);
		}
	}
	else
	{
		throw std::invalid_argument("Start process failed");
	}

	return (*processLock)->getuuid();
}

void Application::sendTask(std::shared_ptr<HttpRequest> asyncHttpRequest)
{
	auto processLock = m_process.synchronize();
	if (*processLock == nullptr)
	{
		throw std::invalid_argument("No process running");
	}

	auto taskRequest = std::static_pointer_cast<HttpRequestWithTimeout>(asyncHttpRequest);
	m_task.sendTask(taskRequest);
}

bool Application::deleteTask()
{
	auto processLock = m_process.synchronize();
	return m_task.deleteTask();
}

void Application::fetchTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest)
{
	auto processLock = m_process.synchronize();
	if (*processLock == nullptr || !(*processLock)->running())
	{
		throw std::invalid_argument("Illegal request");
	}
	if (processKey != (*processLock)->getkey())
	{
		throw std::runtime_error("Process key mismatch");
	}
	std::shared_ptr<void> req = asyncHttpRequest; // TaskRequest takes shared_ptr<void>&
	m_task.fetchTask(req);
}

void Application::replyTask(const std::string &processKey, std::shared_ptr<HttpRequest> asyncHttpRequest)
{
	auto processLock = m_process.synchronize();
	if (*processLock == nullptr || !(*processLock)->running())
	{
		throw std::invalid_argument("Illegal request");
	}
	if (processKey != (*processLock)->getkey())
	{
		throw std::runtime_error("Process key mismatch");
	}
	std::shared_ptr<void> req = asyncHttpRequest; // TaskRequest takes shared_ptr<void>&
	m_task.replyTask(req);
}

std::tuple<int, std::string> Application::taskStatus()
{
	auto processLock = m_process.synchronize();
	return m_task.taskStatus();
}

const std::string Application::getExecUser() const
{
	if (m_name == SEPARATE_AGENT_APP_NAME)
	{
		return "";
	}

#if defined(_WIN32)
	return "";
#else
	std::string executeUser;
	if (m_owner)
	{
		executeUser = m_owner->getExecUserOverride();
	}
	else if (!Configuration::instance()->getDisableExecUser())
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
		auto run = loadRunState();
		auto health = (run.pid > 0) || (run.returnCode == 0); // returnCode==0 already excludes INVALID_RETURN_CODE
		this->health(health);
	}
}

std::tuple<std::string, bool, int> Application::getOutput(long &position, long maxSize, const std::string &processUuid, int index, size_t timeout)
{
	const static char fname[] = "Application::getOutput() ";

	auto process = m_process.get();
	if (process && index == 0 && process->getuuid() == processUuid && process->running() && timeout > 0)
	{
		process->wait(ACE_Time_Value(timeout));
	}

	bool finished = false;
	int exitCode = 0;

	if (process && index == 0)
	{
		if (!processUuid.empty() && process->getuuid() != processUuid)
		{
			throw NotFoundException("No corresponding process running or the given process uuid is wrong");
		}
		if (process->getuuid() == processUuid)
		{
			if (!process->running())
			{
				exitCode = process->returnValue();
				finished = true;
				LOG_DBG << fname << "Process <" << processUuid << "> finished with exit code <" << exitCode << ">";
			}
		}
		auto output = process->getOutputMsg(&position, maxSize);
		return std::make_tuple(output, finished, exitCode);
	}

	auto file = m_stdoutFileQueue->getFileName(index);
	return std::make_tuple(Utility::readFileCpp(file, &position, maxSize), finished, exitCode);
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
		if (!m_persistAble && getName() != SEPARATE_AGENT_APP_NAME)
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
	const auto registersApplicationMetrics = [](const Application &app) {
		return app.m_persistAble || app.getName() == SEPARATE_AGENT_APP_NAME;
	};
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
	if (m_owner)
	{
		result[JSON_KEY_APP_owner] = std::string(m_owner->getName());
	}
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
	result[JSON_KEY_APP_status] = (int)m_status.load();
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
		auto owner = getOwner();
		if (!owner)
		{
			// Refuse to persist sec_env without an owner — we would have to write
			// plaintext to disk, which silently leaks secrets.
			throw std::invalid_argument("cannot persist sec_env for application <" + m_name + "> without an owner");
		}
		nlohmann::json envs = nlohmann::json::object();
		for (const auto &pair : m_secEnvMap)
		{
			envs[pair.first] = owner->encrypt(pair.second);
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
	if (m_startIntervalValueIsCronExpr)
	{
		result[JSON_KEY_SHORT_APP_cron_interval] = (m_startIntervalValueIsCronExpr);
	}
	if (!m_startIntervalValue.empty())
	{
		result[JSON_KEY_SHORT_APP_start_interval_seconds] = std::string(m_startIntervalValue);
	}

	if (returnRuntimeInfo)
	{
		auto run = loadRunState();
		auto process = m_process.get();
		if (run.returnCode != INVALID_RETURN_CODE)
		{
			result[JSON_KEY_APP_return] = run.returnCode;
		}
		if (process && process->running())
		{
			{
				auto processLock = m_process.synchronize();
				auto status = m_task.taskStatus();
				result[JSON_KEY_APP_task_id] = std::get<0>(status);
				result[JSON_KEY_APP_task_status] = std::get<1>(status);
			}
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
		if (process && !process->containerId().empty())
		{
			result[JSON_KEY_APP_container_id] = std::string((process->containerId()));
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
		const auto metrics = m_metrics;
		std::lock_guard<std::mutex> guard(metrics->mutex);
		result[JSON_KEY_APP_starts] = static_cast<long long>(metrics->starts);
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
	if (m_owner)
	{
		LOG_DBG << fname << "m_owner:" << m_owner->getName();
	}
	LOG_DBG << fname << "m_permission:" << m_ownerPermission;
	LOG_DBG << fname << "m_status:" << (int)m_status.load();
	const auto dumpPid = loadRunState().pid;
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

	auto nextLaunchTime = loadRunState().nextLaunch;
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

std::shared_ptr<AppProcess> Application::allocProcess(bool monitorProcess, const std::string &dockerImage, const std::string &appName)
{
	std::shared_ptr<AppProcess> process;
	const auto weakSelf = std::weak_ptr<Application>(std::dynamic_pointer_cast<Application>(shared_from_this()));
	m_stdoutFileQueue->enqueue();
	// Single increment site keeps JSON (m_starts) and Prometheus counters consistent;
	// attach/recovery intentionally counts as a start (long-standing JSON behavior).
	{
		const auto metrics = m_metrics;
		std::lock_guard<std::mutex> guard(metrics->mutex);
		++metrics->starts;
		if (metrics->owner == this && metrics->startCount)
			metrics->startCount->metric().Increment();
	}

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
		if (monitorProcess)
		{
			process = std::make_shared<MonitoredProcess>(weakSelf);
		}
		else
		{
			process = std::make_shared<AppProcess>(weakSelf);
		}
	}
	return process;
}

void Application::destroy()
{
	const static char fname[] = "Application::destroy() ";

	LOG_DBG << fname << "suicide timer ID: " << m_timerRemoveId.load();
	this->disable(); // clears nextLaunch + sets DISABLED, so the tick won't start it
	this->m_status.store(STATUS::NOTAVAILABLE);
	this->cancelTimer(m_timerRemoveId);
}

bool Application::onTimerAppRemove()
{
	const static char fname[] = "Application::onTimerAppRemove() ";
	clearTimerId(m_timerRemoveId);

	try
	{
		Configuration::instance()->removeApp(m_name, this);
	}
	catch (...)
	{
		LOG_ERR << fname << "Error occurred while removing application <" << m_name << ">.";
	}
	return false;
}

void Application::onExitUpdate(int code, bool naturalExit, AppProcess *reporter)
{
	auto process = m_process.get();
	const bool stillRunning = (process != nullptr && process->running());
	const auto run = loadRunState();
	// A deliberate terminate resets m_process before this timer runs; match its last PID.
	const bool isCurrentProcess = reporter == process.get() ||
		(process == nullptr && reporter->lastPid() == run.pid);
	const pid_t prevPid = reporter->lastPid();
	if (code != 0 && isCurrentProcess)
	{
		const auto error = reporter->startError();
		setLastError(Utility::stringFormat("exited with return code: %d, msg: %s", code, error.c_str()));
	}

	// Commit lifecycle state before best-effort output/event side effects.
	if (isCurrentProcess)
	{
		updateRunState([&](RunState &state) {
			if (!stillRunning)
				state.pid = ACE_INVALID_PID;
			state.exitTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
			state.returnCode = code;
			state.exitPending = naturalExit && !stillRunning;
		});
	}

	const long dispatchedPos = reporter->stdoutDispatchedBytes();
	EventDispatcher::instance()->flushStdout(m_name, reporter, dispatchedPos);
	EventDispatcher::instance()->dispatch(m_name, AppEventType::PROCESS_EXIT,
		{{"exit_code", code}, {"pid", prevPid}, {"last_error", getLastError()}});
}

void Application::terminate(std::shared_ptr<AppProcess> &p)
{
	if (p)
	{
		p->terminate();
		// Docker implementations detach without calling AppProcess::onExit; the CAS
		// guard makes this a no-op when the base implementation already reported it.
		if (p->lastPid() > 1)
			p->onExit(9);
	}

	m_task.terminate();
	p.reset();
}

void Application::handleError()
{
	const static char fname[] = "Application::handleError() ";
	bool psk = false;

	switch (this->exitAction(loadRunState().returnCode))
	{
	case AppBehavior::Action::STANDBY:
		// do nothing
		break;
	case AppBehavior::Action::RESTART:
		if (m_name == SEPARATE_AGENT_APP_NAME)
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
		scheduleSpawnAt(std::chrono::system_clock::now() + restartDelay());
		LOG_DBG << fname << "Next action for <" << m_name << "> is KEEPALIVE";
		break;
	case AppBehavior::Action::REMOVE:
		this->regSuicideTimer(m_bufferTime);
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
	if (m_startInterval > 0 || m_startIntervalValueIsCronExpr)
	{
		return std::chrono::seconds(0);
	}

	auto run = loadRunState();
	const auto ranFor = (run.startTime && run.exitTime)
							? std::chrono::duration_cast<std::chrono::seconds>(*run.exitTime - *run.startTime)
							: std::chrono::seconds(0);
	return m_restartBackoff.onExit(ranFor);
}

void Application::scheduleSpawnAt(const std::chrono::system_clock::time_point &when)
{
	const static char fname[] = "Application::scheduleSpawnAt() ";

	// Record-only: no timer. The scheduler tick (spawnIfDue) starts the process when `when`
	// is reached, on its own thread — keeping fork/exec off the shared timer thread.
	nextLaunchTime(when);
	m_needsSchedule.store(false);
	LOG_DBG << fname << "Next start for <" << m_name << "> scheduled at " << DateTime::formatLocalTime(when);
}

void Application::spawnIfDue(const std::chrono::system_clock::time_point &now)
{
	if (!this->isEnabled())
	{
		return;
	}
	const auto next = loadRunState().nextLaunch;
	if (!next || now < *next)
	{
		return; // nothing scheduled, or not due yet
	}
	auto processLock = m_process.synchronize();
	const auto &process = *processLock;
	if (process && process->blocksStart())
	{
		return; // active, or its exit event/stdout is still being finalized
	}
	nextLaunchTime(AppTimer::TIME_UNSET); // consume the due launch (periodic re-arms in spawnNow)
	spawnNow(); // m_process uses a recursive mutex; keep the gate and replacement atomic.
}

void Application::scheduleNext(std::chrono::system_clock::time_point startFrom)
{
	// Resolve the start-form's next occurrence; backoff spacing is already baked into startFrom.
	const auto next = m_timer->nextTime(startFrom);
	if (next == AppTimer::TIME_UNSET)
	{
		nextLaunchTime(next);
		m_needsSchedule.store(true); // no valid next time: a later tick retries
		return;
	}
	scheduleSpawnAt(next);
}

void Application::regSuicideTimer(int timeoutSeconds)
{
	const static char fname[] = "Application::regSuicideTimer() ";

	this->cancelTimer(m_timerRemoveId);
	LOG_DBG << fname << "Application <" << getName() << "> will be removed after <" << timeoutSeconds << "> seconds";
	m_timerRemoveId.store(this->registerTimer(1000L * timeoutSeconds, 0, fname, std::bind(&Application::onTimerAppRemove, this)));
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

void Application::setInvalidError()
{
	if (!this->isEnabled())
	{
		setLastError("not enabled");
	}
	else
	{
		setLastError("not in daily time range");
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
