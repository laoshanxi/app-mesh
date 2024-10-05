#include <algorithm>
#include <assert.h>
#include <limits>

#include <boost/smart_ptr/make_shared.hpp>
#include <prometheus/counter.h>
#include <prometheus/gauge.h>

#include "../../common/DateTime.h"
#include "../../common/DurationParse.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.hpp"
#include "../../common/os/process.hpp"
#include "../Configuration.h"
#include "../DailyLimitation.h"
#include "../ResourceCollection.h"
#include "../ResourceLimitation.h"
#include "../process/AppProcess.h"
#include "../process/DockerApiProcess.h"
#include "../process/DockerProcess.h"
#include "../process/MonitoredProcess.h"
#include "../rest/RestHandler.h"
#include "../security/HMACVerifier.h"
#include "../security/Security.h"
#include "../security/User.h"
#include "AppTimer.h"
#include "Application.h"

constexpr int INVALID_RETURN_CODE = std::numeric_limits<int>::min();

Application::Application()
	: m_persistAble(true), m_ownerPermission(0), m_metadata(EMPTY_STR_JSON),
	  m_shellApp(false), m_sessionLogin(false), m_stdoutCacheNum(0), m_stdoutCacheSize(0),
	  m_startTime(AppTimer::EPOCH_ZERO_TIME), m_endTime(std::chrono::system_clock::time_point::max()),
	  m_startInterval(0), m_bufferTime(0), m_startIntervalValueIsCronExpr(false),
	  m_nextStartTimerId(INVALID_TIMER_ID), m_regTime(std::chrono::system_clock::now()), m_appId(Utility::createUUID()),
	  m_version(0), m_timerRemoveId(INVALID_TIMER_ID),
	  m_pid(ACE_INVALID_PID), m_return(INVALID_RETURN_CODE), m_health(true), m_status(STATUS::ENABLED), m_starts(std::make_shared<prometheus::Counter>())
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
}

bool Application::operator==(const std::shared_ptr<Application> &app)
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);

	if (app->m_dailyLimit != nullptr && !app->m_dailyLimit->operator==(this->m_dailyLimit))
		return false;
	if (this->m_dailyLimit != nullptr && !this->m_dailyLimit->operator==(app->m_dailyLimit))
		return false;

	if (app->m_resourceLimit != nullptr && !app->m_resourceLimit->operator==(this->m_resourceLimit))
		return false;
	if (this->m_resourceLimit != nullptr && !this->m_resourceLimit->operator==(app->m_resourceLimit))
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
			this->m_status == app->m_status);
}

const std::string &Application::getName() const
{
	return m_name;
}

void Application::health(bool health)
{
	m_health = health; // health: 0-health, 1-unhealthy
}

pid_t Application::getpid() const
{
	return m_pid.load();
}

int Application::health() const
{
	return 1 - m_health;
}

bool Application::isEnabled() const
{
	return (m_status == STATUS::ENABLED);
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

bool Application::isCloudApp() const
{
	return (m_metadata == CLOUD_STR_JSON);
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

bool Application::available(const std::chrono::system_clock::time_point &now)
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// check expired
	if (m_endTime != AppTimer::EPOCH_ZERO_TIME && m_endTime != std::chrono::system_clock::time_point::max() && now >= m_endTime)
	{
		return false;
	}
	// check enable
	return isEnabled();
}

void Application::FromJson(const std::shared_ptr<Application> &app, const nlohmann::json &jsonObj)
{
	app->m_name = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_name));
	auto ownerStr = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_owner));
	if (ownerStr.length())
		app->m_owner = Security::instance()->getUserInfo(ownerStr);
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
				// try to load as JSON
				app->m_metadata = nlohmann::json::parse(medataStr);
			}
			catch (...)
			{
				// use text field in case of not JSON format
			}
		}
	}

	app->m_commandLine = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_command));
	app->m_description = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_description));
	// TODO: consider i18n and  legal file name
	const static auto outputDir = (fs::path(Configuration::instance()->getWorkDir()) / "stdout");
	const auto fileName = Utility::stringFormat("appmesh.%s.out", app->m_name.c_str());
	app->m_stdoutFile = (outputDir / fileName).string();
	app->m_stdoutCacheNum = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_stdout_cache_num);
	app->m_stdoutFileQueue = std::make_shared<LogFileQueue>(app->m_stdoutFile, app->m_stdoutCacheNum);
	app->m_stdoutCacheSize = app->m_stdoutFileQueue->size();
	if (app->m_commandLine.length() >= MAX_COMMAND_LINE_LENGTH)
		throw std::invalid_argument("command line length should less than 2048");
	app->m_healthCheckCmd = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_health_check_cmd));
	if (app->m_healthCheckCmd.length() >= MAX_COMMAND_LINE_LENGTH)
		throw std::invalid_argument("health check length should less than 2048");
	app->m_workdir = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_working_dir));
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_status))
	{
		app->m_status = static_cast<STATUS> GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_status);
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
			app->m_envMap[(env.key())] = (env.value().get<std::string>());
		}
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_sec_env))
	{
		bool fromRecover = HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_from_recover);
		auto envs = jsonObj.at(JSON_KEY_APP_sec_env);
		for (auto &env : envs.items())
		{
			// from register, env was not encrypted
			if (fromRecover && app->m_owner != nullptr)
			{
				app->m_secEnvMap[(env.key())] = app->m_owner->decrypt((env.value().get<std::string>()));
			}
			else
			{
				app->m_secEnvMap[(env.key())] = (env.value().get<std::string>());
			}
		}
	}

	app->m_dockerImage = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_docker_image);
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_pid))
		app->attach(GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_pid));
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_version))
		SET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_version, app->m_version);
	if (app->m_dockerImage.length() == 0 && app->m_commandLine.length() == 0)
		throw std::invalid_argument("no command line provide");
	if (app->m_dockerImage.length()) // docker app does not support reserve more output backup files
	{
		app->m_stdoutCacheNum = 0;
		app->m_stdoutCacheSize = 0;
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_time))
	{
		app->m_startTime = std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_time));
	}
	else if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds))
	{
		// for periodic run, set default startTime to now if not specified
		app->m_startTime = std::chrono::system_clock::now() + std::chrono::seconds(1);
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_end_time))
	{
		app->m_endTime = std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_SHORT_APP_end_time));
	}
	if (app->m_endTime.time_since_epoch().count())
	{
		if (app->m_startTime > app->m_endTime)
			throw std::invalid_argument("end_time should greater than the start_time");
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_daily_limitation))
	{
		app->m_dailyLimit = DailyLimitation::FromJson(jsonObj.at(JSON_KEY_APP_daily_limitation));
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_REG_TIME))
	{
		app->m_regTime = std::chrono::system_clock::from_time_t(GET_JSON_INT64_VALUE(jsonObj, JSON_KEY_APP_REG_TIME));
	}

	// init error handling
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_behavior))
	{
		app->behaviorInit(jsonObj.at(JSON_KEY_APP_behavior));
	}

	// init m_timer
	DurationParse duration;
	app->m_bufferTimeValue = GET_JSON_STR_INT_TEXT(jsonObj, JSON_KEY_APP_retention);
	app->m_bufferTime = duration.parse(app->m_bufferTimeValue);
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds))
	{
		// short running
		app->m_startIntervalValueIsCronExpr = GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_SHORT_APP_cron_interval);
		app->m_startIntervalValue = GET_JSON_STR_INT_TEXT(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds);
		if (app->m_startIntervalValueIsCronExpr)
		{
			app->m_timer = std::make_shared<AppTimerCron>(app->m_startTime, app->m_endTime, app->m_dailyLimit, app->m_startIntervalValue, app->m_startInterval);
			app->m_timer->nextTime(); // test to validate cron expression
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
		// long running
		app->m_timer = std::make_shared<AppTimer>(app->m_startTime, app->m_endTime, app->m_dailyLimit);
	}
}

void Application::refresh(void *ptree)
{

	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		if (m_bufferProcess && !m_bufferProcess->running())
			m_bufferProcess = nullptr;
	}

	// health check
	healthCheck();

	// 4. Prometheus
	if (Configuration::instance()->prometheusEnabled() && RESTHANDLER::instance()->collected())
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		if (m_metricMemory && m_process)
		{
			auto usage = m_process->getProcessDetails(ptree);
			m_metricMemory->metric().Set(std::get<1>(usage));
			m_metricCpu->metric().Set(std::get<2>(usage));
			if (m_metricFileDesc)
				m_metricFileDesc->metric().Set(std::get<3>(usage));
		}
		if (m_metricAppPid)
			m_metricAppPid->metric().Set(m_pid.load());
	}
}

bool Application::attach(int pid)
{
	const static char fname[] = "Application::attach() ";

	std::shared_ptr<AppProcess> checkProcStdoutFile;
	if (pid > 1)
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		this->terminate(m_process);
		m_process = allocProcess(false, m_dockerImage, m_name);
		m_process->attach(pid, m_stdoutFile);
		m_pid = m_process->getpid();
		m_procStartTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
		auto stat = os::status(m_pid.load());
		if (stat)
		{
			// recover m_nextLaunchTime to avoid restart
			m_procStartTime = boost::make_shared<std::chrono::system_clock::time_point>(stat->get_starttime());
			m_nextLaunchTime = m_procStartTime;
		}
		LOG_INF << fname << "attached pid <" << pid << "> to application " << m_name << ", last start on: " << DateTime::formatLocalTime(*m_procStartTime);
		if (m_process->running())
			checkProcStdoutFile = m_process;
	}
	// registerCheckStdoutTimer() outside of m_appMutex
	if (checkProcStdoutFile)
		checkProcStdoutFile->registerCheckStdoutTimer();
	return true;
}

void Application::execute(void *ptree)
{
	const static char fname[] = "Application::execute() ";
	auto now = std::chrono::system_clock::now();
	bool scheduleNextRun = false; // the first time to start the event chain
	if (this->available(now))
	{
		auto inDailyRange = m_timer->isInDailyTimeRange(now);
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		if (m_process && m_process->running() && !inDailyRange)
		{
			// check run status and kill for invalid runs
			LOG_INF << fname << DateTime::formatLocalTime(now) << " Application <" << m_name << "> was not in start time, startTime:" << DateTime::formatLocalTime(m_startTime) << " endTime:" << DateTime::formatLocalTime(m_endTime);
			terminate(m_process);
			setInvalidError();
			m_nextLaunchTime.reset();
		}
		scheduleNextRun = (m_nextLaunchTime == nullptr);
	}
	else if (getStatus() != STATUS::NOTAVIALABLE)
	{
		// not available
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		if (m_process && m_process->running())
		{
			LOG_INF << fname << "Application <" << m_name << "> was not available";
			terminate(m_process);
			setInvalidError();
			m_nextLaunchTime.reset();
		}
	}

	boost::shared_ptr<std::chrono::system_clock::time_point> nextRunTime;
	if (scheduleNextRun)
	{
		// trigger first run without app lock
		nextRunTime = scheduleNext(now);
	}

	refresh(ptree);
	if (m_return != INVALID_RETURN_CODE && m_procExitTime && m_procStartTime && *m_procExitTime > *m_procStartTime && nextRunTime == nullptr && getStatus() == STATUS::ENABLED)
	{
		// error handling
		handleError();
	}
}

bool Application::onTimerSpawn()
{
	const static char fname[] = "Application::onTimerSpawn() ";

	auto timerId = m_nextStartTimerId.exchange(INVALID_TIMER_ID);
	if (!IS_VALID_TIMER_ID(timerId))
	{
		LOG_WAR << fname << "application <" << m_name << "> not avialable any more, skip spawn.";
		return false;
	}

	std::shared_ptr<AppProcess> checkProcStdoutFile;
	if (this->isEnabled())
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);

		// 1. clean old process
		if (m_process && m_process->running())
		{
			if (m_bufferTime > 0)
			{
				// give some time for buffer process
				m_bufferProcess = m_process;
				m_bufferProcess->delayKill(m_bufferTime, __FUNCTION__);
			}
			else
			{
				// direct kill old process
				terminate(m_process);
			}
		}

		// 2. start new process
		const auto execUser = getExecUser();
		LOG_INF << fname << "Starting application <" << m_name << "> with user: " << execUser;
		m_process.reset();
		m_process = allocProcess(false, m_dockerImage, m_name);
		m_procStartTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
		bool sudoSwitchUser = (m_shellAppFile != nullptr && Utility::startWith(m_shellAppFile->getShellStartCmd(), "/usr/bin/sudo"));
		m_pid = m_process->spawnProcess(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata, APP_STD_OUT_MAX_FILE_SIZE, sudoSwitchUser);
		if (m_pid.load() > 0)
			checkProcStdoutFile = m_process;

		// 3. post process
		setLastError(m_process->startError());
		if (m_metricStartCount)
			m_metricStartCount->metric().Increment();
	}

	// 4. schedule next run for period run
	if (this->isEnabled() && m_startInterval > 0)
	{
		// note: timer lock can hold app lock, app lock should not hold timer lock
		this->scheduleNext();
	}

	// 5. registerCheckStdoutTimer() outside of m_appMutex
	if (checkProcStdoutFile)
		checkProcStdoutFile->registerCheckStdoutTimer();

	return false;
}

void Application::disable()
{
	const static char fname[] = "Application::disable() ";

	// clean old timer
	this->cancelTimer(m_nextStartTimerId);

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	auto enabled = STATUS::ENABLED;
	if (m_status.compare_exchange_strong(enabled, STATUS::DISABLED))
	{
		LOG_INF << fname << "Application <" << m_name << "> disabled.";
	}
	// kill process
	terminate(m_process);
	m_nextLaunchTime.reset();
	setInvalidError();

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

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	m_process.reset(); // m_process->terminate();
	m_process = allocProcess(false, m_dockerImage, m_name);
	return runApp(timeoutSeconds);
}

std::string Application::runSyncrize(int timeoutSeconds, void *asyncHttpRequest)
{
	const static char fname[] = "Application::runSyncrize() ";
	LOG_DBG << fname << "Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	m_process.reset(); // m_process->terminate();
	m_process = allocProcess(true, m_dockerImage, m_name);
	auto monitorProc = std::dynamic_pointer_cast<MonitoredProcess>(m_process);
	assert(monitorProc != nullptr);
	monitorProc->setAsyncHttpRequest(asyncHttpRequest);

	return runApp(timeoutSeconds);
}

std::string Application::runApp(int timeoutSeconds)
{
	const static char fname[] = "Application::runApp() ";
	LOG_DBG << fname << "Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (m_dockerImage.length())
	{
		throw std::invalid_argument("Docker application does not support this API");
	}
	assert(m_status != STATUS::ENABLED);

	const auto execUser = getExecUser();
	LOG_INF << fname << "Running application <" << m_name << "> with timeout <" << timeoutSeconds << "> seconds";
	m_procStartTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
	bool sudoSwitchUser = (m_shellAppFile != nullptr && Utility::startWith(m_shellAppFile->getShellStartCmd(), "/usr/bin/sudo"));
	m_pid = m_process->spawnProcess(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata, APP_STD_OUT_MAX_FILE_SIZE, sudoSwitchUser);
	// TODO: run app does not call registerCheckStdoutTimer() for now
	setLastError(m_process->startError());
	if (m_metricStartCount)
		m_metricStartCount->metric().Increment();

	if (m_pid.load() > 0)
	{
		m_health = true;
		if (timeoutSeconds > 0)
			m_process->delayKill(timeoutSeconds, fname);
	}
	else
	{
		throw std::invalid_argument("Start process failed");
	}

	return m_process->getuuid();
}

const std::string Application::getExecUser() const
{
	std::string executeUser;
	if (m_owner)
	{
		// get correct execute user when Application has user info
		executeUser = m_owner->getExecUserOverride();
	}
	else if (!Configuration::instance()->getDisableExecUser())
	{
		// get default execute user when Application have no user info
		executeUser = Configuration::instance()->getDefaultExecUser();
	}
	if (executeUser.empty())
		executeUser = Utility::getOsUserName();
	return executeUser;
}

const std::string &Application::getCmdLine() const
{
	if (m_shellAppFile != nullptr)
		return m_shellAppFile->getShellStartCmd();
	return m_commandLine;
}

void Application::healthCheck()
{
	if (m_healthCheckCmd.empty())
	{
		auto health = (getpid() > 0) || (m_return != INVALID_RETURN_CODE && 0 == m_return.load());
		this->health(health);
	}
}

std::tuple<std::string, bool, int> Application::getOutput(long &position, long maxSize, const std::string &processUuid, int index, size_t timeout)
{
	const static char fname[] = "Application::getOutput() ";

	std::shared_ptr<AppProcess> process;
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		process = m_process;
	}
	if (process != nullptr && index == 0 && process->getuuid() == processUuid && process->running() && timeout > 0)
	{
		// TODO: timeout > 0 already now work, will remove related code in future.
		process->wait(ACE_Time_Value(timeout));
	}

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	bool finished = false;
	int exitCode = 0;
	if (m_process && index == 0)
	{
		if (processUuid.length() && m_process->getuuid() != processUuid)
		{
			throw NotFoundException("No corresponding process running or the given process uuid is wrong");
		}
		if (m_process->getuuid() == processUuid)
		{
			if (!m_process->running())
			{
				exitCode = m_process->returnValue();
				finished = true;
				LOG_DBG << fname << "process:" << processUuid << " finished with exit code: " << exitCode;
			}
		}
		auto output = m_process->getOutputMsg(&position, maxSize);
		return std::make_tuple(output, finished, exitCode);
	}
	auto file = m_stdoutFileQueue->getFileName(index);
	return std::make_tuple(Utility::readFileCpp(file, &position, maxSize), finished, exitCode);
}

void Application::initMetrics()
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// must clean first, otherwise the duplicate one will create
	m_metricStartCount = nullptr;
	m_metricAppPid = nullptr;
	m_metricMemory = nullptr;
	m_metricCpu = nullptr;
	m_metricFileDesc = nullptr;

	// update
	if (Configuration::instance()->prometheusEnabled())
	{
		// use uuid in label here to avoid same name app use the same metric cause issue
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
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// must clean first, otherwise the duplicate one will create
	m_metricStartCount = nullptr;
	m_metricAppPid = nullptr;
	m_metricMemory = nullptr;
	m_metricCpu = nullptr;
	m_metricFileDesc = nullptr;

	// update
	if (fromApp)
	{
		// use uuid in label here to avoid same name app use the same metric cause issue
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

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	LOG_DBG << fname << "application:" << m_name;
	result[JSON_KEY_APP_name] = std::string(m_name);
	if (m_owner)
		result[JSON_KEY_APP_owner] = std::string(m_owner->getName());
	if (m_ownerPermission)
		result[JSON_KEY_APP_owner_permission] = (m_ownerPermission);
	if (m_shellApp)
		result[JSON_KEY_APP_shell_mode] = (m_shellApp);
	if (m_sessionLogin)
		result[JSON_KEY_APP_session_login] = (m_sessionLogin);
	if (m_commandLine.length())
		result[(JSON_KEY_APP_command)] = std::string(m_commandLine);
	if (m_description.length())
		result[(JSON_KEY_APP_description)] = std::string(m_description);
	if (m_healthCheckCmd.length())
		result[(JSON_KEY_APP_health_check_cmd)] = std::string(m_healthCheckCmd);
	if (m_workdir.length())
		result[JSON_KEY_APP_working_dir] = std::string(m_workdir);
	result[JSON_KEY_APP_status] = (int)m_status.load();
	if (m_stdoutCacheNum)
		result[JSON_KEY_APP_stdout_cache_num] = (m_stdoutCacheNum);
	if (m_metadata != EMPTY_STR_JSON)
		result[JSON_KEY_APP_metadata] = m_metadata;
	if (returnRuntimeInfo)
	{
		if (m_return != INVALID_RETURN_CODE)
			result[JSON_KEY_APP_return] = m_return.load();
		if (m_process && m_process->running())
		{
			result[JSON_KEY_APP_pid] = m_pid.load();
			auto usage = m_process->getProcessDetails(ptree);
			if (std::get<0>(usage))
			{
				result[JSON_KEY_APP_memory] = (std::get<1>(usage));
				result[JSON_KEY_APP_cpu] = (std::get<2>(usage));
				result[JSON_KEY_APP_open_fd] = (std::get<3>(usage));
				result[JSON_KEY_APP_pstree] = std::string(std::get<4>(usage));
			}
		}
		if (m_procStartTime && std::chrono::time_point_cast<std::chrono::hours>(*m_procStartTime).time_since_epoch().count() > 24) // avoid print 1970-01-01 08:00:00
			result[JSON_KEY_APP_last_start] = std::chrono::duration_cast<std::chrono::seconds>((*m_procStartTime).time_since_epoch()).count();
		if (m_procExitTime && std::chrono::time_point_cast<std::chrono::hours>(*m_procExitTime).time_since_epoch().count() > 24)
			result[JSON_KEY_APP_last_exit] = std::chrono::duration_cast<std::chrono::seconds>((*m_procExitTime).time_since_epoch()).count();
		if (m_process && !m_process->containerId().empty())
		{
			result[JSON_KEY_APP_container_id] = std::string((m_process->containerId()));
		}
		result[JSON_KEY_APP_health] = (this->health());
		if (m_stdoutFileQueue->size())
			result[JSON_KEY_APP_stdout_cache_size] = (m_stdoutFileQueue->size());
		// result[JSON_KEY_APP_id] = std::string(m_appId);
	}
	if (m_dailyLimit != nullptr)
	{
		result[JSON_KEY_APP_daily_limitation] = m_dailyLimit->AsJson();
	}
	if (m_resourceLimit != nullptr)
	{
		result[JSON_KEY_APP_resource_limit] = m_resourceLimit->AsJson();
	}
	if (m_envMap.size())
	{
		nlohmann::json envs = nlohmann::json::object();
		std::for_each(m_envMap.begin(), m_envMap.end(), [&envs](const std::pair<std::string, std::string> &pair)
					  { envs[(pair.first)] = std::string(pair.second); });
		result[JSON_KEY_APP_env] = std::move(envs);
	}
	if (m_secEnvMap.size())
	{
		nlohmann::json envs = nlohmann::json::object();
		auto owner = getOwner();
		std::for_each(m_secEnvMap.begin(), m_secEnvMap.end(), [&envs, &owner](const std::pair<std::string, std::string> &pair)
					  {
						  auto encryptedEnvValue = owner ? owner->encrypt(pair.second) : pair.second;
						  envs[(pair.first)] = std::move(encryptedEnvValue); });
		result[JSON_KEY_APP_sec_env] = std::move(envs);
	}
	if (m_dockerImage.length())
		result[JSON_KEY_APP_docker_image] = std::string(m_dockerImage);
	if (m_version)
		result[JSON_KEY_APP_version] = (m_version);

	if (m_startTime.time_since_epoch().count())
		result[JSON_KEY_SHORT_APP_start_time] = (std::chrono::duration_cast<std::chrono::seconds>(m_startTime.time_since_epoch()).count());
	if (m_endTime.time_since_epoch().count() && m_endTime != std::chrono::system_clock::time_point::max())
		result[JSON_KEY_SHORT_APP_end_time] = (std::chrono::duration_cast<std::chrono::seconds>(m_endTime.time_since_epoch()).count());
	result[JSON_KEY_APP_REG_TIME] = (std::chrono::duration_cast<std::chrono::seconds>(m_regTime.time_since_epoch()).count());
	if (returnRuntimeInfo)
	{
		auto err = getLastError();
		if (err.length())
			result[JSON_KEY_APP_last_error] = std::string(err);
		result[JSON_KEY_APP_starts] = static_cast<long long>(m_starts->Value());
	}

	result[JSON_KEY_APP_behavior] = this->behaviorAsJson();
	if (m_bufferTime)
		result[JSON_KEY_APP_retention] = std::string(m_bufferTimeValue);
	if (m_startIntervalValueIsCronExpr)
		result[JSON_KEY_SHORT_APP_cron_interval] = (m_startIntervalValueIsCronExpr);
	if (m_startIntervalValue.length())
	{
		result[JSON_KEY_SHORT_APP_start_interval_seconds] = std::string(m_startIntervalValue);
	}
	if (returnRuntimeInfo && m_nextLaunchTime)
	{
		result[JSON_KEY_SHORT_APP_next_start_time] = std::chrono::duration_cast<std::chrono::seconds>((*m_nextLaunchTime).time_since_epoch()).count();
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
		LOG_INF << fname << "saved file: " << appPath;
	}
}

std::string Application::getYamlPath()
{
	return (fs::path(Utility::getParentDir()) / APPMESH_WORK_DIR / APPMESH_APPLICATION_DIR / (getName() + ".yaml")).string();
}

void Application::remove()
{
	Utility::removeFile(getYamlPath());
	Utility::removeFile((fs::path(Utility::getParentDir()) / APPMESH_APPLICATION_DIR / (getName() + ".yaml")).string());
}

void Application::dump()
{
	const static char fname[] = "Application::dump() ";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);

	LOG_DBG << fname << "m_name:" << m_name;
	LOG_DBG << fname << "m_commandLine:" << m_commandLine;
	LOG_DBG << fname << "m_description:" << m_description;
	LOG_DBG << fname << "m_metadata:" << m_metadata;
	LOG_DBG << fname << "m_shellApp:" << m_shellApp;
	LOG_DBG << fname << "m_sessionLogin:" << m_sessionLogin;
	LOG_DBG << fname << "behavior:" << behaviorAsJson();
	LOG_DBG << fname << "m_workdir:" << m_workdir;
	if (m_owner)
		LOG_DBG << fname << "m_owner:" << m_owner->getName();
	LOG_DBG << fname << "m_permission:" << m_ownerPermission;
	LOG_DBG << fname << "m_status:" << (int)m_status.load();
	if (m_pid.load() != ACE_INVALID_PID)
		LOG_DBG << fname << "m_pid:" << m_pid.load();
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
	if (m_nextLaunchTime)
		LOG_DBG << fname << "m_nextLaunchTime:" << DateTime::formatLocalTime(*m_nextLaunchTime);
	if (m_dailyLimit != nullptr)
		m_dailyLimit->dump();
	if (m_resourceLimit != nullptr)
		m_resourceLimit->dump();
}

std::shared_ptr<AppProcess> Application::allocProcess(bool monitorProcess, const std::string &dockerImage, const std::string &appName)
{
	std::shared_ptr<AppProcess> process;
	m_stdoutFileQueue->enqueue();
	m_starts->Increment();

	// prepare shell mode script
	if ((m_shellApp || m_sessionLogin) && (m_shellAppFile == nullptr || !Utility::isFileExist(m_shellAppFile->getShellFileName())))
	{
		m_shellAppFile = nullptr;
		m_shellAppFile = std::make_shared<ShellAppFileGen>(appName, m_commandLine, getExecUser(), m_sessionLogin, m_workdir);
	}

	// alloc process object
	if (dockerImage.length())
	{
		if (Configuration::instance()->getDockerProxyAddress().length() && m_envMap.count(ENV_APPMESH_DOCKER_PARAMS) == 0)
		{
			process.reset(new DockerApiProcess(appName, dockerImage));
		}
		else
		{
			process.reset(new DockerProcess(appName, dockerImage));
		}
	}
	else
	{
		if (monitorProcess)
		{
			process.reset(new MonitoredProcess(this));
		}
		else
		{
			process.reset(new AppProcess(this));
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
		LOG_ERR << fname;
	}
	return false;
}

void Application::onExitUpdate(int code)
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// update exit information
	if (m_process == nullptr || !m_process->running()) // avoid update pid when m_bufferProcess exit
		m_pid = ACE_INVALID_PID;
	m_procExitTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
	m_return.store(code);
	if (code != 0 && m_process)
		setLastError(Utility::stringFormat("exited with return code: %d, msg: %s", code, m_process->startError().c_str()));
	// this->registerTimer(0, 0, std::bind(&Application::handleError, this), fname);
	this->cancelTimer(m_timerRemoveId);
}

void Application::terminate(std::shared_ptr<AppProcess> &process)
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// terminate
	if (process)
		process->terminate();

	// update exit information
	if (m_process == nullptr || !m_process->running()) // avoid update pid when m_bufferProcess exit
		m_pid = ACE_INVALID_PID;
	m_return = 9;
	m_procExitTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
	process.reset();
}

void Application::handleError()
{
	const static char fname[] = "Application::handleError() ";
	bool psk = false;
	switch (this->exitAction(m_return.load()))
	{
	case AppBehavior::Action::STANDBY:
		// do nothing
		// LOG_DBG << fname << "next action for <" << m_name << "> is STANDBY";
		break;
	case AppBehavior::Action::RESTART:
		if (m_name == SEPARATE_AGENT_APP_NAME)
			psk = HMACVerifierSingleton::instance()->writePSKToSHM();

		// do restart
		this->scheduleNext();
		LOG_DBG << fname << "next action for <" << m_name << "> is RESTART";

		if (psk)
			HMACVerifierSingleton::instance()->waitPSKRead();
		break;
	case AppBehavior::Action::KEEPALIVE:
		// keep alive always, used for period run
		m_nextLaunchTime = boost::make_shared<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
		m_nextStartTimerId = this->registerTimer(10L, 0, std::bind(&Application::onTimerSpawn, this), fname);
		LOG_DBG << fname << "next action for <" << m_name << "> is KEEPALIVE";
		break;
	case AppBehavior::Action::REMOVE:
		this->regSuicideTimer(m_bufferTime);
		LOG_DBG << fname << "next action for <" << m_name << "> is REMOVE";
		break;
	default:
		break;
	}
}

boost::shared_ptr<std::chrono::system_clock::time_point> Application::scheduleNext(std::chrono::system_clock::time_point now)
{
	const static char fname[] = "Application::scheduleNext() ";

	auto next = m_timer->nextTime(now);
	if (next != AppTimer::EPOCH_ZERO_TIME)
	{
		// 1. update m_nextLaunchTime before register timer, spawn will check m_nextLaunchTime
		{
			std::lock_guard<std::recursive_mutex> guard(m_appMutex);
			m_nextLaunchTime = boost::make_shared<std::chrono::system_clock::time_point>(next);
			LOG_DBG << fname << "next start for <" << m_name << "> is " << DateTime::formatLocalTime(next);
		}
		// 2. register timer
		auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(next - std::chrono::system_clock::now()).count();
		m_nextStartTimerId = this->registerTimer(delay, 0, std::bind(&Application::onTimerSpawn, this), fname);
		LOG_DBG << fname << "next start timer ID <" << m_nextStartTimerId << ">";
	}
	else
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		m_nextLaunchTime.reset();
	}

	return m_nextLaunchTime;
}

void Application::regSuicideTimer(int timeoutSeconds)
{
	const static char fname[] = "Application::regSuicideTimer() ";

	this->cancelTimer(m_timerRemoveId);
	LOG_DBG << fname << "application <" << getName() << "> will be removed after <" << timeoutSeconds << "> seconds";
	m_timerRemoveId = this->registerTimer(1000L * timeoutSeconds, 0, std::bind(&Application::onTimerAppRemove, this), fname);
}

void Application::setLastError(const std::string &error)
{
	const static char fname[] = "Application::setLastError() ";

	if (error != m_lastError.get())
	{
		if (error.length())
		{
			m_lastError = Utility::stringFormat("%s %s", DateTime::formatLocalTime(std::chrono::system_clock::now()).c_str(), error.c_str());
			LOG_DBG << fname << "last error for <" << getName() << ">: " << error;
		}
		else
		{
			m_lastError = "";
		}
	}
}

const std::string Application::getLastError() const
{
	return m_lastError.get();
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
