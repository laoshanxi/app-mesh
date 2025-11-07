#include <algorithm>
#include <assert.h>
#include <limits>

#include <boost/smart_ptr/make_shared.hpp>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#include "../../common/DateTime.h"
#include "../../common/DurationParse.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.h"
#include "../../common/os/proc.h"
#include "../Configuration.h"
#include "../DailyLimitation.h"
#include "../ResourceCollection.h"
#include "../ResourceLimitation.h"
#include "../process/AppProcess.h"
#if !defined(_WIN32)
#include "../process/DockerApiProcess.h"
#include "../process/DockerProcess.h"
#endif
#include "../process/MonitoredProcess.h"
#include "../rest/RestHandler.h"
#include "../security/HMACVerifier.h"
#include "../security/Security.h"
#include "../security/User.h"
#include "AppTimer.h"
#include "Application.h"

namespace
{
	constexpr int INVALID_RETURN_CODE = std::numeric_limits<int>::min();
}

Application::Application()
	: m_persistAble(true), m_ownerPermission(0), m_metadata(EMPTY_STR_JSON),
	  m_shellApp(false), m_sessionLogin(false), m_stdoutCacheNum(0), m_stdoutCacheSize(0),
	  m_startTime(AppTimer::EPOCH_ZERO_TIME), m_endTime(std::chrono::system_clock::time_point::max()),
	  m_startInterval(0), m_bufferTime(0), m_startIntervalValueIsCronExpr(false),
	  m_nextStartTimerId(INVALID_TIMER_ID), m_regTime(std::chrono::system_clock::now()),
	  m_appId(Utility::shortID()), m_version(0), m_timerRemoveId(INVALID_TIMER_ID),
	  m_pid(ACE_INVALID_PID), m_return(INVALID_RETURN_CODE), m_health(true),
	  m_status(STATUS::ENABLED), m_starts(std::make_shared<prometheus::Counter>())
{
	const static char fname[] = "Application::Application() ";
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

bool Application::operator==(const std::shared_ptr<Application> &app)
{
	if (app->m_dailyLimit && !app->m_dailyLimit->operator==(this->m_dailyLimit))
		return false;
	if (this->m_dailyLimit && !this->m_dailyLimit->operator==(app->m_dailyLimit))
		return false;

	if (app->m_resourceLimit && !app->m_resourceLimit->operator==(this->m_resourceLimit))
		return false;
	if (this->m_resourceLimit && !this->m_resourceLimit->operator==(app->m_resourceLimit))
		return false;

	return (this->m_name == app->m_name &&
			this->m_shellApp == app->m_shellApp &&
			this->m_sessionLogin == app->m_sessionLogin &&
			this->m_commandLine == app->m_commandLine &&
			this->m_owner == app->m_owner &&
			this->m_ownerPermission == app->m_ownerPermission &&
			this->m_dockerImage == app->m_dockerImage &&
			this->m_version == app->m_version &&
			this->m_workdir == app->m_workdir &&
			this->m_stdoutFile == app->m_stdoutFile &&
			this->m_healthCheckCmd == app->m_healthCheckCmd &&
			this->m_startTime == app->m_startTime &&
			this->m_endTime == app->m_endTime &&
			this->m_startIntervalValue == app->m_startIntervalValue &&
			this->m_bufferTimeValue == app->m_bufferTimeValue &&
			this->m_startIntervalValueIsCronExpr == app->m_startIntervalValueIsCronExpr &&
			this->m_status.load() == app->m_status.load());
}

const std::string &Application::getName() const
{
	return m_name;
}

void Application::health(bool health)
{
	m_health.store(health);
}

pid_t Application::getpid() const
{
	return m_pid.load();
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
	if (time == AppTimer::EPOCH_ZERO_TIME)
	{
		m_nextLaunchTime.store(nullptr);
	}
	else
	{
		m_nextLaunchTime.store(boost::make_shared<std::chrono::system_clock::time_point>(time));
	}
}

bool Application::available(const std::chrono::system_clock::time_point &now)
{
	// Check if expired
	if (m_endTime != AppTimer::EPOCH_ZERO_TIME &&
		m_endTime != std::chrono::system_clock::time_point::max() &&
		now >= m_endTime)
	{
		return false;
	}
	return isEnabled();
}

void Application::FromJson(const std::shared_ptr<Application> &app, const nlohmann::json &jsonObj)
{
	app->m_name = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_name));

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
	app->m_stdoutCacheSize = app->m_stdoutFileQueue->size();

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
		app->m_stdoutCacheSize = 0;
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
			assert(app->m_startInterval > 0);
			app->m_timer = std::make_shared<AppTimerPeriod>(app->m_startTime, app->m_endTime, app->m_dailyLimit, app->m_startInterval);
		}
	}
	else
	{
		// Long running
		app->m_timer = std::make_shared<AppTimer>(app->m_startTime, app->m_endTime, app->m_dailyLimit);
	}
}

void Application::refresh(void *ptree)
{
	{
		auto lock = m_process.synchronize();
		if (m_bufferProcess && !m_bufferProcess->running())
		{
			m_bufferProcess.reset();
		}
	}

	// Health check
	healthCheck();

	// Prometheus
	if (Configuration::instance()->prometheusEnabled() && RESTHANDLER::instance()->collected())
	{
		auto process = m_process.get();
		if (m_metricMemory && process)
		{
			auto usage = process->getProcessDetails(ptree);
			m_metricMemory->metric().Set(std::get<1>(usage));
			m_metricCpu->metric().Set(std::get<2>(usage));
			if (m_metricFileDesc)
			{
				m_metricFileDesc->metric().Set(std::get<3>(usage));
			}
		}
		if (m_metricAppPid)
		{
			m_metricAppPid->metric().Set(m_pid.load());
		}
	}
}

bool Application::attach(int pid)
{
	const static char fname[] = "Application::attach() ";

	std::shared_ptr<AppProcess> checkProcStdoutFile;
	if (pid > 1)
	{
		auto processLock = m_process.synchronize();
		this->terminate(*processLock);
		(*processLock) = allocProcess(false, m_dockerImage, m_name);
		(*processLock)->attach(pid, m_stdoutFile);
		m_pid.store((*processLock)->getpid());

		auto procStartTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
#if defined(_WIN32)
		// TODO: For Windows, implement process status check
#else
		auto stat = os::status(m_pid.load());
		if (stat)
		{
			// Recover m_nextLaunchTime to avoid restart
			procStartTime = boost::make_shared<std::chrono::system_clock::time_point>(stat->get_starttime());
			nextLaunchTime(stat->get_starttime());
		}
#endif
		m_procStartTime.store(procStartTime);
		LOG_INF << fname << "Attached pid <" << pid << "> to application " << m_name
				<< ", last start on: " << DateTime::formatLocalTime(*procStartTime);
		if ((*processLock)->running())
		{
			checkProcStdoutFile = (*processLock);
		}
	}

	// registerCheckStdoutTimer() outside of m_appMutex
	if (checkProcStdoutFile)
	{
		checkProcStdoutFile->registerCheckStdoutTimer();
	}
	return true;
}

void Application::handleUnavailable(const std::chrono::system_clock::time_point &now)
{
	const static char fname[] = "Application::handleUnavailable() ";

	// [1]: An Application can only be <available> or <not available>
	if (this->available(now))
	{
		// [1.1]: Check if current time is within the application's daily time range
		auto inDailyRange = m_timer->isInDailyTimeRange(now);
		auto processLock = m_process.synchronize();
		if ((*processLock) && (*processLock)->running() && !inDailyRange)
		{
			// Terminate running process if it's outside the valid time range
			LOG_INF << fname << "Application <" << m_name << "> is not in start time, startTime: "
					<< DateTime::formatLocalTime(m_startTime) << " endTime: " << DateTime::formatLocalTime(m_endTime)
					<< " now: " << DateTime::formatLocalTime(now);
			terminate(*processLock);
			setInvalidError();
			nextLaunchTime(AppTimer::EPOCH_ZERO_TIME);
		}
	}
	else if (getStatus() != STATUS::NOTAVIALABLE) // Ignore NOTAVIALABLE status, which is used for runApp and destroying
	{
		// [1.3]: Terminate process for <not available> application
		auto processLock = m_process.synchronize();
		if ((*processLock) && (*processLock)->running())
		{
			LOG_INF << fname << "Application <" << m_name << "> is not available";
			terminate(*processLock);
			setInvalidError();
			nextLaunchTime(AppTimer::EPOCH_ZERO_TIME);
		}
	}
}

boost::shared_ptr<std::chrono::system_clock::time_point> Application::handleScheduling(const std::chrono::system_clock::time_point &now)
{
	if (this->available(now))
	{
		// [1.2]: If not scheduled yet, set flag to trigger the first run for a normal application
		auto doSchedule = (m_nextLaunchTime.load() == nullptr);

		if (doSchedule)
		{
			// Trigger first run (without holding app lock)
			auto scheduleTime = scheduleNext(now);

			// For periodic applications, simulate a previous run so error handling logic can work
			if (m_startInterval && scheduleTime && m_return.load() == INVALID_RETURN_CODE &&
				m_procExitTime.load() == nullptr && m_procStartTime.load() == nullptr)
			{
				m_return.store(0); // Simulate a successful return code for periodic run
				m_procExitTime.store(boost::make_shared<std::chrono::system_clock::time_point>(now));
				m_procStartTime.store(boost::make_shared<std::chrono::system_clock::time_point>(now - std::chrono::hours(1)));
				scheduleTime.reset();
			}

			return scheduleTime;
		}
	}
	return nullptr;
}

bool Application::hasExited(const std::chrono::system_clock::time_point &now) const
{
	if (getStatus() != STATUS::ENABLED)
	{
		return false;
	}

	auto process = m_process.get();
	if (process && process->running())
	{
		return false; // Still running
	}

	if (m_return.load() == INVALID_RETURN_CODE)
	{
		return false; // No return code yet
	}

	auto exitTime = m_procExitTime.load();
	auto startTime = m_procStartTime.load();
	if (!exitTime || !startTime)
	{
		return false; // Not start or not exit yet
	}

	// Note: m_procExitTime and m_procStartTime may not be set in a guaranteed order due to asynchronous execution.
	//   - m_procExitTime is set in Application::onExitUpdate (by terminate).
	//   - m_procStartTime is set in Application::onTimerSpawn (by scheduleNext).
	//   - so: m_procStartTime might delay small time, add 1 second buffer to check
	return (now > (*startTime + std::chrono::seconds(1)));
}

void Application::execute(void *ptree)
{
	auto now = std::chrono::system_clock::now();

	// Terminates running processes when the app is unavailable or outside its daily time range
	handleUnavailable(now);

	// Manages first-time scheduling and initializes state for periodic apps
	auto scheduleTime = handleScheduling(now);

	// Refresh application state (health checks, metrics, cleanup)
	refresh(ptree);

	// Handle error if process exited
	if (scheduleTime == nullptr && hasExited(now))
	{
		handleError();
	}
}

bool Application::onTimerSpawn()
{
	const static char fname[] = "Application::onTimerSpawn() ";

	m_nextStartTimerIdEvent.wait();
	auto timerId = m_nextStartTimerId.exchange(INVALID_TIMER_ID);
	if (!IS_VALID_TIMER_ID(timerId))
	{
		LOG_WAR << fname << "Application <" << m_name << "> not available anymore, skip spawn.";
		return false;
	}

	std::shared_ptr<AppProcess> checkProcStdoutFile;
	if (this->isEnabled())
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

		m_procStartTime.store(boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now()));
		const auto execUser = (m_shellAppFile && m_shellAppFile->isUsingSudo()) ? std::string() : getExecUser();
		LOG_INF << fname << "Starting application <" << m_name << "> with user: " << execUser;

		m_pid.store((*processLock)->spawnProcess(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata, APP_STD_OUT_MAX_FILE_SIZE));
		if (m_pid.load() > 0)
		{
			checkProcStdoutFile = (*processLock);
		}

		// 3. Post process
		setLastError((*processLock)->startError());
		if (m_metricStartCount)
		{
			m_metricStartCount->metric().Increment();
		}
	}

	// 4. Schedule next run for period run (if next have not scheduled)
	if (this->isEnabled() && m_startInterval > 0 && m_nextStartTimerId.load() == INVALID_TIMER_ID)
	{
		// Note: timer lock can hold app lock, app lock should not hold timer lock
		// Make sure next run start from next second (while current start already begin)
		this->scheduleNext(std::chrono::system_clock::now() + std::chrono::seconds(1));
	}

	// 5. registerCheckStdoutTimer() outside of m_appMutex
	if (checkProcStdoutFile)
	{
		checkProcStdoutFile->registerCheckStdoutTimer();
	}

	return false;
}

void Application::disable()
{
	const static char fname[] = "Application::disable() ";

	this->cancelTimer(m_nextStartTimerId);

	auto enabled = STATUS::ENABLED;
	if (m_status.compare_exchange_strong(enabled, STATUS::DISABLED))
	{
		LOG_INF << fname << "Application <" << m_name << "> disabled.";
	}

	terminate(*m_process.synchronize());
	nextLaunchTime(AppTimer::EPOCH_ZERO_TIME);
	save();
}

void Application::enable()
{
	auto disabled = STATUS::DISABLED;
	m_status.compare_exchange_strong(disabled, STATUS::ENABLED);
	save();
}

std::string Application::runAsyncrize(int timeoutSeconds)
{
	const static char fname[] = "Application::runAsyncrize() ";
	LOG_DBG << fname << "Entered.";

	auto processLock = m_process.synchronize();
	(*processLock).reset();
	(*processLock) = allocProcess(false, m_dockerImage, m_name);
	return runApp(timeoutSeconds);
}

std::string Application::runSyncrize(int timeoutSeconds, std::shared_ptr<void> asyncHttpRequest)
{
	const static char fname[] = "Application::runSyncrize() ";
	LOG_DBG << fname << "Entered.";

	auto processLock = m_process.synchronize();
	(*processLock).reset();
	(*processLock) = allocProcess(true, m_dockerImage, m_name);
	auto monitorProc = std::dynamic_pointer_cast<MonitoredProcess>(*processLock);
	assert(monitorProc != nullptr);
	monitorProc->setAsyncHttpRequest(asyncHttpRequest);

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
	assert(m_status.load() != STATUS::ENABLED);

	const auto execUser = getExecUser();
	LOG_INF << fname << "Running application <" << m_name << "> with timeout <" << timeoutSeconds << "> seconds";

	m_procStartTime.store(boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now()));
	m_pid.store((*processLock)->spawnProcess(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata, APP_STD_OUT_MAX_FILE_SIZE));

	setLastError((*processLock)->startError());
	if (m_metricStartCount)
	{
		m_metricStartCount->metric().Increment();
	}

	if (m_pid.load() > 0)
	{
		m_health.store(true);
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

void Application::sendTask(std::shared_ptr<void> asyncHttpRequest)
{
	auto processLock = m_process.synchronize();
	if (*processLock == nullptr)
	{
		throw std::invalid_argument("No process running");
	}

	// TODO: if previous one not finished, discard current? restart process? pending in queue?
	auto taskRequest = std::static_pointer_cast<HttpRequestWithTimeout>(asyncHttpRequest);
	m_task.sendTask(taskRequest);
}

bool Application::deleteTask()
{
	auto processLock = m_process.synchronize();
	return m_task.deleteTask();
}

void Application::fetchTask(const std::string &processKey, std::shared_ptr<void> asyncHttpRequest)
{
	auto processLock = m_process.synchronize();
	if (*processLock == nullptr || !(*processLock)->running())
	{
		throw std::invalid_argument("Illegal request");
	}
	if (processKey != (*processLock)->getkey())
	{
		throw std::invalid_argument("Process key mismatch");
	}
	m_task.fetchTask(asyncHttpRequest);
}

void Application::replyTask(const std::string &processKey, std::shared_ptr<void> asyncHttpRequest)
{
	auto processLock = m_process.synchronize();
	if (*processLock == nullptr || !(*processLock)->running())
	{
		throw std::invalid_argument("Illegal request");
	}
	if (processKey != (*processLock)->getkey())
	{
		throw std::invalid_argument("Process key mismatch");
	}
	m_task.replyTask(asyncHttpRequest);
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
		auto health = (getpid() > 0) || (m_return.load() != INVALID_RETURN_CODE && m_return.load() == 0);
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
				LOG_DBG << fname << "process:" << processUuid << " finished with exit code: " << exitCode;
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
	auto lock = m_process.synchronize();

	m_metricStartCount.reset();
	m_metricAppPid.reset();
	m_metricMemory.reset();
	m_metricCpu.reset();
	m_metricFileDesc.reset();

	if (Configuration::instance()->prometheusEnabled())
	{
		// Use uuid in label here to avoid same name app use the same metric cause issue
		m_metricStartCount = RESTHANDLER::instance()->createPromCounter(
			PROM_METRIC_NAME_appmesh_prom_process_start_count, PROM_METRIC_HELP_appmesh_prom_process_start_count,
			{{"application", getName()}, {"id", m_appId}});
		m_metricAppPid = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_prom_process_id_gauge, PROM_METRIC_HELP_appmesh_prom_process_start_count,
			{{"application", getName()}, {"id", m_appId}});
		m_metricMemory = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_prom_process_memory_gauge, PROM_METRIC_HELP_appmesh_prom_process_memory_gauge,
			{{"application", getName()}, {"id", m_appId}});
		m_metricCpu = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_prom_process_cpu_gauge, PROM_METRIC_HELP_appmesh_prom_process_cpu_gauge,
			{{"application", getName()}, {"id", m_appId}});
		m_metricFileDesc = RESTHANDLER::instance()->createPromGauge(
			PROM_METRIC_NAME_appmesh_prom_process_file_descriptors, PROM_METRIC_HELP_appmesh_prom_process_file_descriptors,
			{{"application", getName()}, {"id", m_appId}});
	}
}

void Application::initMetrics(std::shared_ptr<Application> fromApp)
{
	auto lock = m_process.synchronize();

	m_metricStartCount.reset();
	m_metricAppPid.reset();
	m_metricMemory.reset();
	m_metricCpu.reset();
	m_metricFileDesc.reset();

	if (fromApp)
	{
		m_metricStartCount = fromApp->m_metricStartCount;
		m_metricAppPid = fromApp->m_metricAppPid;
		m_metricMemory = fromApp->m_metricMemory;
		m_metricCpu = fromApp->m_metricCpu;
		m_metricFileDesc = fromApp->m_metricFileDesc;
		m_starts = fromApp->m_starts;
	}
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
	if (!m_commandLine.empty())
	{
		result[(JSON_KEY_APP_command)] = std::string(m_commandLine);
	}
	if (!m_description.empty())
	{
		result[(JSON_KEY_APP_description)] = std::string(m_description);
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
	if (m_stdoutCacheNum)
	{
		result[JSON_KEY_APP_stdout_cache_num] = (m_stdoutCacheNum);
	}
	if (m_metadata != EMPTY_STR_JSON)
	{
		result[JSON_KEY_APP_metadata] = m_metadata;
	}

	if (returnRuntimeInfo)
	{
		if (m_return.load() != INVALID_RETURN_CODE)
		{
			result[JSON_KEY_APP_return] = m_return.load();
		}
		auto process = m_process.get();
		if (process && process->running())
		{
			{
				auto processLock = m_process.synchronize();
				auto status = m_task.taskStatus();
				result[JSON_KEY_APP_task_id] = std::get<0>(status);
				result[JSON_KEY_APP_task_status] = std::get<1>(status);
			}
			result[JSON_KEY_APP_pid] = m_pid.load();
			result[JSON_KEY_APP_pid_user] = os::getUsernameByUid(os::getProcessUid(m_pid.load()));

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
		auto startTime = m_procStartTime.load();
		if (startTime && std::chrono::time_point_cast<std::chrono::hours>(*startTime).time_since_epoch().count() > 24)
		{
			result[JSON_KEY_APP_last_start] = std::chrono::duration_cast<std::chrono::seconds>((*startTime).time_since_epoch()).count();
		}
		auto exitTime = m_procExitTime.load();
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
	}

	if (m_dailyLimit)
	{
		result[JSON_KEY_APP_daily_limitation] = m_dailyLimit->AsJson();
	}
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

	if (m_secEnvMap.size())
	{
		nlohmann::json envs = nlohmann::json::object();
		auto owner = getOwner();
		for (const auto &pair : m_secEnvMap)
		{
			auto encryptedEnvValue = owner ? owner->encrypt(pair.second) : pair.second;
			envs[pair.first] = std::move(encryptedEnvValue);
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
	result[JSON_KEY_APP_REG_TIME] = (std::chrono::duration_cast<std::chrono::seconds>(m_regTime.time_since_epoch()).count());

	if (returnRuntimeInfo)
	{
		auto err = getLastError();
		if (!err.empty())
		{
			result[JSON_KEY_APP_last_error] = std::string(err);
		}
		result[JSON_KEY_APP_starts] = static_cast<long long>(m_starts->Value());
	}

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

	auto nextLaunchTime = m_nextLaunchTime.load();
	if (returnRuntimeInfo && nextLaunchTime)
	{
		result[JSON_KEY_SHORT_APP_next_start_time] = std::chrono::duration_cast<std::chrono::seconds>((*nextLaunchTime).time_since_epoch()).count();
	}

	Utility::addExtraAppTimeReferStr(result);
	return result;
}

void Application::save()
{
	const static char fname[] = "Application::save() ";

	if (this->isPersistAble())
	{
		const auto appPath = getYamlPath();
		LOG_DBG << fname << appPath;
		std::ofstream ofs(appPath, ios::trunc);
		ofs << std::setw(4) << Utility::jsonToYaml(AsJson(false)) << std::endl;
		if (ofs.fail())
		{
			throw std::invalid_argument("failed to save application, please check your app name or folder permission");
		}
		LOG_INF << fname << "Saved file: " << appPath;
	}
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
	if (m_pid.load() != ACE_INVALID_PID)
	{
		LOG_DBG << fname << "m_pid:" << m_pid.load();
	}
	LOG_DBG << fname << "m_startTimeValue:" << DateTime::formatLocalTime(m_startTime);
	LOG_DBG << fname << "m_endTimeValue:" << DateTime::formatLocalTime(m_endTime);
	LOG_DBG << fname << "m_regTime:" << DateTime::formatLocalTime(m_regTime);
	LOG_DBG << fname << "m_dockerImage:" << m_dockerImage;
	LOG_DBG << fname << "m_stdoutFile:" << m_stdoutFile;
	LOG_DBG << fname << "m_starts:" << m_starts->Value();
	LOG_DBG << fname << "m_version:" << m_version;
	LOG_DBG << fname << "m_lastError:" << getLastError();
	LOG_DBG << fname << "m_startInterval:" << m_startInterval;
	LOG_DBG << fname << "m_bufferTime:" << m_bufferTime;

	auto nextLaunchTime = m_nextLaunchTime.load();
	if (nextLaunchTime)
	{
		LOG_DBG << fname << "m_nextLaunchTime:" << DateTime::formatLocalTime(*nextLaunchTime);
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
	m_stdoutFileQueue->enqueue();
	m_starts->Increment();

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
			process.reset(new DockerApiProcess(appName, dockerImage));
		}
		else
		{
			process.reset(new DockerProcess(appName, dockerImage));
		}
#else
		throw std::invalid_argument("Docker application does not support on Windows");
#endif
	}
	else
	{
		auto weakSelf = std::weak_ptr<Application>(std::dynamic_pointer_cast<Application>(weak_from_this().lock()));

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

	LOG_DBG << fname << "suicide timer ID: " << m_timerRemoveId.load() << " nextStartTimerId: " << m_nextStartTimerId.load();
	this->disable();
	this->m_status.store(STATUS::NOTAVIALABLE);
	this->cancelTimer(m_timerRemoveId);
	this->cancelTimer(m_nextStartTimerId);
}

bool Application::onTimerAppRemove()
{
	const static char fname[] = "Application::onTimerAppRemove() ";
	CLEAR_TIMER_ID(m_timerRemoveId);

	try
	{
		Configuration::instance()->removeApp(m_name);
	}
	catch (...)
	{
		LOG_ERR << fname << "Error occurred while removing application <" << m_name << ">.";
	}
	return false;
}

void Application::onExitUpdate(int code)
{
	auto process = m_process.get();
	if (process == nullptr || !process->running())
	{
		m_pid.store(ACE_INVALID_PID);
	}
	m_procExitTime.store(boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now()));
	m_return.store(code);

	if (code != 0 && process)
	{
		setLastError(Utility::stringFormat("exited with return code: %d, msg: %s", code, process->startError().c_str()));
	}
	// immediate error handling (compared with Application::execute)
	// this->registerTimer(0, 0, std::bind(&Application::handleError, this), fname);
}

void Application::terminate(std::shared_ptr<AppProcess> &p)
{
	if (p)
	{
		p->terminate();
	}

	m_task.terminate();

	// Update exit information
	onExitUpdate(9);

	p.reset();
}

void Application::handleError()
{
	const static char fname[] = "Application::handleError() ";
	bool psk = false;

	switch (this->exitAction(m_return.load()))
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

		// do restart
		this->scheduleNext();
		LOG_DBG << fname << "Next action for <" << m_name << "> is RESTART";

		if (psk)
		{
			HMACVerifierSingleton::instance()->waitPSKRead();
		}
		break;
	case AppBehavior::Action::KEEPALIVE:
		// keep alive always, used for period run
		nextLaunchTime(std::chrono::system_clock::now());
		m_nextStartTimerIdEvent.reset();
		m_nextStartTimerId.store(this->registerTimer(0, 0, std::bind(&Application::onTimerSpawn, this), fname));
		m_nextStartTimerIdEvent.signal();
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

boost::shared_ptr<std::chrono::system_clock::time_point> Application::scheduleNext(std::chrono::system_clock::time_point startFrom)
{
	const static char fname[] = "Application::scheduleNext() ";

	auto next = m_timer->nextTime(startFrom);

	// Avoid frequency issue
	auto startTime = m_procStartTime.load();
	auto distanceSeconds = std::abs(std::chrono::duration_cast<std::chrono::seconds>(
										next - (startTime ? *startTime : AppTimer::EPOCH_ZERO_TIME))
										.count());
	if (distanceSeconds < 1)
	{
		next += std::chrono::milliseconds(500); // add 0.5s buffer if target start is now
	}

	// 1. update m_nextLaunchTime before register timer, spawn will check m_nextLaunchTime
	nextLaunchTime(next);

	if (next != AppTimer::EPOCH_ZERO_TIME)
	{
		// 2. register timer
		auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(next - std::chrono::system_clock::now()).count();
		m_nextStartTimerIdEvent.reset();
		m_nextStartTimerId.store(this->registerTimer(delay, 0, std::bind(&Application::onTimerSpawn, this), fname));
		m_nextStartTimerIdEvent.signal();
		LOG_DBG << fname << "Next start for <" << m_name << "> is " << DateTime::formatLocalTime(next)
				<< " start timer ID <" << m_nextStartTimerId.load() << ">";
	}

	return m_nextLaunchTime.load();
}

void Application::regSuicideTimer(int timeoutSeconds)
{
	const static char fname[] = "Application::regSuicideTimer() ";

	this->cancelTimer(m_timerRemoveId);
	LOG_DBG << fname << "Application <" << getName() << "> will be removed after <" << timeoutSeconds << "> seconds";
	m_timerRemoveId.store(this->registerTimer(1000L * timeoutSeconds, 0, std::bind(&Application::onTimerAppRemove, this), fname));
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
	std::map<std::string, std::string> envMap;
	std::merge(m_envMap.begin(), m_envMap.end(),
			   m_secEnvMap.begin(), m_secEnvMap.end(),
			   std::inserter(envMap, envMap.begin()));
	return envMap;
}
