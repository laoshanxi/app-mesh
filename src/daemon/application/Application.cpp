#include <algorithm>
#include <assert.h>

#include "../../common/DateTime.h"
#include "../../common/DurationParse.h"
#include "../../common/Utility.h"
#include "../../common/os/process.hpp"
#include "../../prom_exporter/counter.h"
#include "../../prom_exporter/gauge.h"
#include "../Configuration.h"
#include "../DailyLimitation.h"
#include "../ResourceCollection.h"
#include "../ResourceLimitation.h"
#include "../process/AppProcess.h"
#include "../process/DockerApiProcess.h"
#include "../process/DockerProcess.h"
#include "../process/MonitoredProcess.h"
#include "../rest/PrometheusRest.h"
#include "../security/Security.h"
#include "../security/User.h"
#include "AppTimer.h"
#include "Application.h"

ACE_Time_Value Application::m_waitTimeout = ACE_Time_Value(std::chrono::milliseconds(20));

Application::Application()
	: m_persistAble(true), m_status(STATUS::ENABLED), m_ownerPermission(0), m_shellApp(false), m_stdoutCacheNum(0),
	  m_startInterval(0), m_bufferTime(0), m_startIntervalValueIsCronExpr(false), m_nextStartTimerId(INVALID_TIMER_ID),
	  m_health(true), m_appId(Utility::createUUID()), m_version(0), m_pid(ACE_INVALID_PID),
	  m_suicideTimerId(INVALID_TIMER_ID), m_starts(std::make_shared<prometheus::Counter>())
{
	const static char fname[] = "Application::Application() ";
	LOG_DBG << fname << "Entered.";
	m_regTime = std::chrono::system_clock::now();
	m_posixTimeZone = DateTime::getLocalZoneUTCOffset();
	m_metadata = EMPTY_STR_JSON;
}

Application::~Application()
{
	const static char fname[] = "Application::~Application() ";
	LOG_DBG << fname << "Entered. Application: " << m_name;
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
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	return m_pid;
}

int Application::health() const
{
	return 1 - m_health;
}

bool Application::isEnabled() const
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
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
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	return m_status;
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
	if (m_endTimeValue != AppTimer::EPOCH_ZERO_TIME && now >= m_endTimeValue)
	{
		return false;
	}
	// check enable
	return isEnabled();
}

void Application::FromJson(const std::shared_ptr<Application> &app, const web::json::value &jsonObj)
{
	app->m_name = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_name));
	auto ownerStr = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_owner));
	if (ownerStr.length())
		app->m_owner = Security::instance()->getUserInfo(ownerStr);
	app->m_ownerPermission = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_owner_permission);
	app->m_shellApp = GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_APP_shell_mode);
	if (jsonObj.has_field(JSON_KEY_APP_metadata))
	{
		app->m_metadata = jsonObj.at(JSON_KEY_APP_metadata);
		if (!jsonObj.at(JSON_KEY_APP_metadata).is_object())
		{
			try
			{
				const auto str = Utility::unEscape(jsonObj.at(JSON_KEY_APP_metadata).as_string());
				// handle escape
				app->m_metadata = web::json::value::string(str);
				// try to load as JSON
				app->m_metadata = web::json::value::parse(str);
			}
			catch (...)
			{
				// use text field in case of not JSON format
			}
		}
	}

	app->m_commandLine = Utility::unEscape(Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_command)));
	app->m_description = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_description));
	// TODO: consider i18n and  legal file name
	app->m_stdoutFile = Utility::stringFormat("%s/appmesh.%s.out", Configuration::instance()->getWorkDir().c_str(), app->m_name.c_str());
	app->m_stdoutCacheNum = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_stdout_cache_num);
	app->m_stdoutFileQueue = std::make_shared<LogFileQueue>(app->m_stdoutFile, app->m_stdoutCacheNum);
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
		auto envs = jsonObj.at(JSON_KEY_APP_env).as_object();
		for (auto env : envs)
		{
			app->m_envMap[GET_STD_STRING(env.first)] = GET_STD_STRING(env.second.as_string());
		}
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_sec_env))
	{
		bool fromRecover = HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_from_recover);
		auto envs = jsonObj.at(JSON_KEY_APP_sec_env).as_object();
		for (auto env : envs)
		{
			// from register, env was not encrypted
			if (fromRecover && app->m_owner != nullptr)
			{
				app->m_secEnvMap[GET_STD_STRING(env.first)] = app->m_owner->decrypt(GET_STD_STRING(env.second.as_string()));
			}
			else
			{
				app->m_secEnvMap[GET_STD_STRING(env.first)] = GET_STD_STRING(env.second.as_string());
			}
		}
	}

	app->m_dockerImage = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_docker_image);
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_pid))
		app->attach(GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_pid));
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_version))
		SET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_version, app->m_version);
	app->m_posixTimeZone = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_posix_timezone);
	if (app->m_dockerImage.length() == 0 && app->m_commandLine.length() == 0)
		throw std::invalid_argument("no command line provide");
	if (app->m_dockerImage.length()) // docker app does not support reserve more output backup files
		app->m_stdoutCacheNum = 0;

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_time))
	{
		app->m_startTime = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_time);
		app->m_startTimeValue = DateTime::parseISO8601DateTime(app->m_startTime, app->m_posixTimeZone);
	}
	else if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds))
	{
		// for periodic run, set default startTime to now in case of no specified
		app->m_startTime = DateTime::formatLocalTime(std::chrono::system_clock::now());
		app->m_startTimeValue = DateTime::parseISO8601DateTime(app->m_startTime, app->m_posixTimeZone);
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_end_time))
	{
		app->m_endTime = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SHORT_APP_end_time);
		app->m_endTimeValue = DateTime::parseISO8601DateTime(app->m_endTime, app->m_posixTimeZone);
	}
	if (app->m_endTimeValue.time_since_epoch().count())
	{
		if (app->m_startTimeValue > app->m_endTimeValue)
			throw std::invalid_argument("end_time should greater than the start_time");
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_daily_limitation))
	{
		app->m_dailyLimit = DailyLimitation::FromJson(jsonObj.at(JSON_KEY_APP_daily_limitation), app->m_posixTimeZone);
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_REG_TIME))
	{
		app->m_regTime = DateTime::parseISO8601DateTime(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_REG_TIME));
	}

	// init error handling
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_behavior))
	{
		app->behaviorInit(jsonObj.at(JSON_KEY_APP_behavior));
	}

	// init m_timer
	DurationParse duration;
	app->m_bufferTimeValue = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_retention);
	app->m_bufferTime = duration.parse(app->m_bufferTimeValue);
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds))
	{
		// short running
		app->m_startIntervalValueIsCronExpr = GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_SHORT_APP_cron_interval);
		app->m_startIntervalValue = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_interval_seconds);
		app->m_startInterval = duration.parse(app->m_startIntervalValue);
		assert(app->m_startInterval > 0);

		if (app->m_startIntervalValueIsCronExpr)
		{
			app->m_timer = std::make_shared<AppTimerCron>(app->m_startTimeValue, app->m_endTimeValue, app->m_dailyLimit, app->m_startIntervalValue, app->m_startInterval);
			app->m_timer->nextTime(); // test to validate cron expression
		}
		else
		{
			app->m_timer = std::make_shared<AppTimerPeriod>(app->m_startTimeValue, app->m_endTimeValue, app->m_dailyLimit, app->m_startInterval);
		}
	}
	else
	{
		// long running
		app->m_timer = std::make_shared<AppTimer>(app->m_startTimeValue, app->m_endTimeValue, app->m_dailyLimit);
	}
}

std::shared_ptr<int> Application::refresh(void *ptree)
{
	std::shared_ptr<int> exitCode;
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		// 1. Try to get return code.
		if (m_process != nullptr)
		{
			if (m_process->running())
			{
				m_pid = m_process->getpid();
				if (m_process->wait(m_waitTimeout) > 0)
				{
					m_return = std::make_shared<int>(m_process->returnValue());
					exitCode = m_return;
					m_pid = ACE_INVALID_PID;
					m_procExitTime = std::chrono::system_clock::now();
					setLastError(Utility::stringFormat("exited with return code: %d, msg: %s", *m_return, m_process->startError().c_str()));
				}
			}
			else if (m_pid > 0)
			{
				m_return = std::make_shared<int>(m_process->returnValue());
				exitCode = m_return;
				m_pid = ACE_INVALID_PID;
				m_procExitTime = std::chrono::system_clock::now();
				setLastError(Utility::stringFormat("exited with return code: %d, msg: %s", *m_return, m_process->startError().c_str()));
			}
		}

		// 2. Try to get return code from Buffer process again
		//    If there have buffer process, current process is still running, so get return code from buffer process
		if (m_bufferProcess && m_bufferProcess->running())
		{
			if (m_bufferProcess->wait(m_waitTimeout) > 0)
			{
				m_return = std::make_shared<int>(m_process->returnValue());
				m_procExitTime = std::chrono::system_clock::now();
				setLastError(Utility::stringFormat("exited with return code: %d, msg: %s", *m_return, m_process->startError().c_str()));
			}
		}
	}

	// health check
	healthCheck();

	// 4. Prometheus
	if (PrometheusRest::instance() != nullptr && PrometheusRest::instance()->collected())
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
			m_metricAppPid->metric().Set(m_pid);
	}

	return exitCode;
}

bool Application::attach(int pid)
{
	const static char fname[] = "Application::attach() ";

	if (pid > 1)
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		if (m_process && m_process->running())
		{
			m_process->killgroup();
		}
		m_process.reset(new AppProcess());
		m_process->attach(pid);
		m_pid = m_process->getpid();
		LOG_INF << fname << "attached pid <" << pid << "> to application " << m_name;
	}
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
			LOG_INF << fname << "Application <" << m_name << "> was not in start time";
			m_process->killgroup();
			m_pid = ACE_INVALID_PID;
			m_procExitTime = now;
			setInvalidError();
			m_nextLaunchTime = nullptr;
		}
		scheduleNextRun = (m_nextLaunchTime == nullptr);
	}
	else if (m_status != STATUS::NOTAVIALABLE)
	{
		// not available
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		if (m_process && m_process->running())
		{
			LOG_INF << fname << "Application <" << m_name << "> was not available";
			m_process->killgroup();
			m_pid = ACE_INVALID_PID;
			m_procExitTime = now;
			setInvalidError();
			m_nextLaunchTime = nullptr;
		}
	}

	std::shared_ptr<std::chrono::system_clock::time_point> nextRunTime;
	if (scheduleNextRun)
	{
		// trigger first run without app lock
		nextRunTime = scheduleNext(now);
	}

	auto exitCode = refresh(ptree);
	if (exitCode != nullptr && nextRunTime == nullptr)
	{
		// error handling
		onExit(*exitCode);
	}
}

void Application::spawn(int timerId)
{
	const static char fname[] = "Application::spawn() ";
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
				m_process->killgroup();
			}
		}

		// 2. start new process
		const auto execUser = getExecUser();
		LOG_INF << fname << "Starting application <" << m_name << "> with user: " << execUser;
		m_process.reset();
		m_process = allocProcess(false, m_dockerImage, m_name);
		m_procStartTime = std::chrono::system_clock::now();
		m_pid = m_process->spawnProcess(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata);

		// 3. post process
		setLastError(m_process->startError());
		if (m_metricStartCount)
			m_metricStartCount->metric().Increment();
	}

	// 4. schedule next run for period run
	if (this->isEnabled() && m_startInterval > 0)
	{
		// note: timer lock can hold app lock, app lock should not hold timer lock
		this->scheduleNext(std::chrono::system_clock::now() + std::chrono::seconds(1));
	}
}

void Application::disable()
{
	const static char fname[] = "Application::stop() ";

	// clean old timer
	int timerId = INVALID_TIMER_ID;
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		timerId = m_nextStartTimerId;
		m_nextStartTimerId = INVALID_TIMER_ID;
	}
	this->cancelTimer(timerId);

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (m_status == STATUS::ENABLED)
	{
		m_status = STATUS::DISABLED;
		m_return = nullptr;
		LOG_INF << fname << "Application <" << m_name << "> disabled.";
	}
	// kill process
	if (m_process != nullptr)
		m_process->killgroup();
	m_nextLaunchTime = nullptr;
}

void Application::enable()
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (m_status == STATUS::DISABLED)
	{
		m_status = STATUS::ENABLED;
	}
}

std::string Application::runAsyncrize(int timeoutSeconds)
{
	const static char fname[] = "Application::runAsyncrize() ";
	LOG_DBG << fname << "Entered.";
	m_process.reset(); //m_process->killgroup();
	m_process = allocProcess(false, m_dockerImage, m_name);
	return runApp(timeoutSeconds);
}

std::string Application::runSyncrize(int timeoutSeconds, void *asyncHttpRequest)
{
	const static char fname[] = "Application::runSyncrize() ";
	LOG_DBG << fname << "Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	m_process.reset(); //m_process->killgroup();
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
	LOG_INF << fname << "Running application <" << m_name << ">.";
	m_procStartTime = std::chrono::system_clock::now();
	m_pid = m_process->spawnProcess(getCmdLine(), execUser, m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata);
	setLastError(m_process->startError());
	if (m_metricStartCount)
		m_metricStartCount->metric().Increment();

	if (m_pid > 0)
	{
		if (timeoutSeconds > 0)
			m_process->delayKill(timeoutSeconds, __FUNCTION__);
	}
	else
	{
		throw std::invalid_argument("Start process failed");
	}

	return m_process->getuuid();
}

const std::string Application::getExecUser() const
{
	if (!Configuration::instance()->getDisableExecUser())
	{
		if (m_owner && !(m_owner->getExecUser().empty()))
		{
			return m_owner->getExecUser();
		}
		else
		{
			return Configuration::instance()->getDefaultExecUser();
		}
	}
	return std::string();
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
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		auto health = (getpid() > 0) || (m_return && 0 == *m_return);
		this->health(health);
	}
}

std::tuple<std::string, bool, int> Application::getOutput(long &position, long maxSize, const std::string &processUuid, int index)
{
	const static char fname[] = "Application::getOutput() ";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	bool finished = false;
	int exitCode = 0;
	if (m_process != nullptr && index == 0)
	{
		if (processUuid.length() && m_process->getuuid() != processUuid)
		{
			throw std::invalid_argument("No corresponding process running or the given process uuid is wrong");
		}
		auto output = m_process->getOutputMsg(&position, maxSize);
		if (m_process->getuuid() == processUuid)
		{
			if (!m_process->running())
			{
				exitCode = m_process->returnValue();
				finished = true;
				LOG_DBG << fname << "process:" << processUuid << " finished with exit code: " << exitCode;
			}
		}
		return std::make_tuple(output, finished, exitCode);
	}
	auto file = m_stdoutFileQueue->getFileName(index);
	return std::make_tuple(Utility::readFileCpp(file, &position, maxSize), finished, exitCode);
}

void Application::initMetrics(std::shared_ptr<PrometheusRest> prom)
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// must clean first, otherwise the duplicate one will create
	m_metricStartCount = nullptr;
	m_metricAppPid = nullptr;
	m_metricMemory = nullptr;
	m_metricCpu = nullptr;
	m_metricFileDesc = nullptr;

	// update
	if (prom)
	{
		// use uuid in label here to avoid same name app use the same metric cause issue
		m_metricStartCount = prom->createPromCounter(
			PROM_METRIC_NAME_appmesh_prom_process_start_count, PROM_METRIC_HELP_appmesh_prom_process_start_count,
			{{"application", getName()}, {"id", m_appId}});
		m_metricAppPid = prom->createPromGauge(
			PROM_METRIC_NAME_appmesh_prom_process_id_gauge, PROM_METRIC_HELP_appmesh_prom_process_start_count,
			{{"application", getName()}, {"id", m_appId}});
		m_metricMemory = prom->createPromGauge(
			PROM_METRIC_NAME_appmesh_prom_process_memory_gauge, PROM_METRIC_HELP_appmesh_prom_process_memory_gauge,
			{{"application", getName()}, {"id", m_appId}});
		m_metricCpu = prom->createPromGauge(
			PROM_METRIC_NAME_appmesh_prom_process_cpu_gauge, PROM_METRIC_HELP_appmesh_prom_process_cpu_gauge,
			{{"application", getName()}, {"id", m_appId}});
		m_metricFileDesc = prom->createPromGauge(
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

web::json::value Application::AsJson(bool returnRuntimeInfo)
{
	web::json::value result = web::json::value::object();

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	result[JSON_KEY_APP_name] = web::json::value::string(GET_STRING_T(m_name));
	if (m_owner)
		result[JSON_KEY_APP_owner] = web::json::value::string(m_owner->getName());
	if (m_ownerPermission)
		result[JSON_KEY_APP_owner_permission] = web::json::value::number(m_ownerPermission);
	if (m_shellApp)
		result[JSON_KEY_APP_shell_mode] = web::json::value::boolean(m_shellApp);
	if (m_commandLine.length())
		result[GET_STRING_T(JSON_KEY_APP_command)] = web::json::value::string(GET_STRING_T(m_commandLine));
	if (m_description.length())
		result[GET_STRING_T(JSON_KEY_APP_description)] = web::json::value::string(GET_STRING_T(m_description));
	if (m_healthCheckCmd.length())
		result[GET_STRING_T(JSON_KEY_APP_health_check_cmd)] = web::json::value::string(GET_STRING_T(m_healthCheckCmd));
	if (m_workdir.length())
		result[JSON_KEY_APP_working_dir] = web::json::value::string(GET_STRING_T(m_workdir));
	result[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(m_status));
	if (m_stdoutCacheNum)
		result[JSON_KEY_APP_stdout_cache_num] = web::json::value::number(static_cast<int>(m_stdoutCacheNum));
	if (m_metadata != EMPTY_STR_JSON)
		result[JSON_KEY_APP_metadata] = m_metadata;
	if (returnRuntimeInfo)
	{
		if (m_return != nullptr)
			result[JSON_KEY_APP_return] = web::json::value::number(*m_return);
		if (m_process && m_process->running())
		{
			result[JSON_KEY_APP_pid] = web::json::value::number(m_pid);
			auto usage = m_process->getProcessDetails();
			if (std::get<0>(usage))
			{
				result[JSON_KEY_APP_memory] = web::json::value::number(std::get<1>(usage));
				result[JSON_KEY_APP_cpu] = web::json::value::number(std::get<2>(usage));
				result[JSON_KEY_APP_open_fd] = web::json::value::number(std::get<3>(usage));
				result[JSON_KEY_APP_pstree] = web::json::value::string(std::get<4>(usage));
			}
		}
		if (std::chrono::time_point_cast<std::chrono::hours>(m_procStartTime).time_since_epoch().count() > 24) // avoid print 1970-01-01 08:00:00
			result[JSON_KEY_APP_last_start] = web::json::value::string(DateTime::formatLocalTime(m_procStartTime));
		if (std::chrono::time_point_cast<std::chrono::hours>(m_procExitTime).time_since_epoch().count() > 24)
			result[JSON_KEY_APP_last_exit] = web::json::value::string(DateTime::formatLocalTime(m_procExitTime));
		if (m_process && !m_process->containerId().empty())
		{
			result[JSON_KEY_APP_container_id] = web::json::value::string(GET_STRING_T(m_process->containerId()));
		}
		result[JSON_KEY_APP_health] = web::json::value::number(this->health());
		if (m_stdoutFileQueue->size())
			result[JSON_KEY_APP_stdout_cache_num] = web::json::value::number(m_stdoutFileQueue->size());
		//result[JSON_KEY_APP_id] = web::json::value::string(m_appId);
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
		web::json::value envs = web::json::value::object();
		std::for_each(m_envMap.begin(), m_envMap.end(), [&envs](const std::pair<std::string, std::string> &pair)
					  { envs[GET_STRING_T(pair.first)] = web::json::value::string(pair.second); });
		result[JSON_KEY_APP_env] = envs;
	}
	if (m_secEnvMap.size())
	{
		web::json::value envs = web::json::value::object();
		auto owner = getOwner();
		std::for_each(m_secEnvMap.begin(), m_secEnvMap.end(), [&envs, &owner](const std::pair<std::string, std::string> &pair)
					  {
						  auto encryptedEnvValue = owner ? owner->encrypt(pair.second) : pair.second;
						  envs[GET_STRING_T(pair.first)] = web::json::value::string(encryptedEnvValue);
					  });
		result[JSON_KEY_APP_sec_env] = envs;
	}
	if (m_posixTimeZone.length() && m_posixTimeZone != DateTime::getLocalZoneUTCOffset())
		result[JSON_KEY_APP_posix_timezone] = web::json::value::string(m_posixTimeZone);
	if (m_dockerImage.length())
		result[JSON_KEY_APP_docker_image] = web::json::value::string(m_dockerImage);
	if (m_version)
		result[JSON_KEY_APP_version] = web::json::value::number(m_version);

	if (m_startTimeValue.time_since_epoch().count())
		result[JSON_KEY_SHORT_APP_start_time] = web::json::value::string(m_startTime);
	if (m_endTimeValue.time_since_epoch().count())
		result[JSON_KEY_SHORT_APP_end_time] = web::json::value::string(m_endTime);
	result[JSON_KEY_APP_REG_TIME] = web::json::value::string(DateTime::formatLocalTime(m_regTime));
	if (returnRuntimeInfo)
	{
		auto err = getLastError();
		if (err.length())
			result[JSON_KEY_APP_last_error] = web::json::value::string(err);
		result[JSON_KEY_APP_starts] = web::json::value::number(m_starts->Value());
	}

	result[JSON_KEY_APP_behavior] = this->behaviorAsJson();
	if (m_bufferTime)
		result[JSON_KEY_APP_retention] = web::json::value::string(m_bufferTimeValue);
	if (m_startIntervalValueIsCronExpr)
		result[JSON_KEY_SHORT_APP_cron_interval] = web::json::value::boolean(m_startIntervalValueIsCronExpr);
	if (m_startIntervalValue.length())
	{
		result[JSON_KEY_SHORT_APP_start_interval_seconds] = web::json::value::string(m_startIntervalValue);
		if (returnRuntimeInfo)
		{
			if (m_nextLaunchTime != nullptr)
				result[JSON_KEY_SHORT_APP_next_start_time] = web::json::value::string(DateTime::formatLocalTime(*m_nextLaunchTime));
		}
	}
	return result;
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
	LOG_DBG << fname << "behavior:" << behaviorAsJson();
	LOG_DBG << fname << "m_workdir:" << m_workdir;
	if (m_owner)
		LOG_DBG << fname << "m_owner:" << m_owner->getName();
	LOG_DBG << fname << "m_permission:" << m_ownerPermission;
	LOG_DBG << fname << "m_status:" << static_cast<int>(m_status);
	LOG_DBG << fname << "m_pid:" << m_pid;
	LOG_DBG << fname << "m_posixTimeZone:" << m_posixTimeZone;
	LOG_DBG << fname << "m_startTime:" << m_startTime;
	LOG_DBG << fname << "m_startTimeValue:" << DateTime::formatLocalTime(m_startTimeValue);
	LOG_DBG << fname << "m_endTime:" << m_endTime;
	LOG_DBG << fname << "m_endTimeValue:" << DateTime::formatLocalTime(m_endTimeValue);
	LOG_DBG << fname << "m_regTime:" << DateTime::formatLocalTime(m_regTime);
	LOG_DBG << fname << "m_dockerImage:" << m_dockerImage;
	LOG_DBG << fname << "m_stdoutFile:" << m_stdoutFile;
	LOG_DBG << fname << "m_starts:" << m_starts->Value();
	LOG_DBG << fname << "m_version:" << m_version;
	LOG_DBG << fname << "m_lastError:" << getLastError();

	LOG_DBG << fname << "m_startInterval:" << m_startInterval;
	LOG_DBG << fname << "m_bufferTime:" << m_bufferTime;
	if (m_nextLaunchTime != nullptr)
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
	if (m_shellApp && (m_shellAppFile == nullptr || !Utility::isFileExist(m_shellAppFile->getShellFileName())))
	{
		m_shellAppFile = nullptr;
		m_shellAppFile = std::make_shared<ShellAppFileGen>(appName, m_commandLine);
	}

	// alloc process object
	if (dockerImage.length())
	{
		if (Configuration::instance()->getDockerProxyAddress().length() && m_envMap.count(ENV_APP_MANAGER_DOCKER_PARAMS) == 0)
		{
			process.reset(new DockerApiProcess(dockerImage, appName));
		}
		else
		{
			process.reset(new DockerProcess(dockerImage, appName));
		}
	}
	else
	{
		if (monitorProcess)
		{
			process.reset(new MonitoredProcess());
		}
		else
		{
			process.reset(new AppProcess());
		}
	}
	return process;
}

void Application::destroy()
{
	int suicideTimerId = INVALID_TIMER_ID;
	int timerId = INVALID_TIMER_ID;
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		this->disable();
		this->m_status = STATUS::NOTAVIALABLE;
		suicideTimerId = m_suicideTimerId;
		timerId = m_nextStartTimerId;
		m_suicideTimerId = m_nextStartTimerId = INVALID_TIMER_ID;
	}
	this->cancelTimer(suicideTimerId);
	this->cancelTimer(timerId);
}

void Application::onSuicide(int timerId)
{
	const static char fname[] = "Application::onSuicide() ";

	try
	{
		Configuration::instance()->removeApp(m_name);
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << e.what();
	}
	catch (...)
	{
		LOG_ERR << fname << "unknown exception";
	}
}

void Application::onExit(int code)
{
	const static char fname[] = "Application::onExit() ";

	switch (this->exitAction(code))
	{
	case AppBehavior::Action::STANDBY:
		// do nothing
		LOG_DBG << fname << "next action for <" << m_name << "> is STANDBY";
		break;
	case AppBehavior::Action::RESTART:
		// do restart
		this->scheduleNext();
		LOG_DBG << fname << "next action for <" << m_name << "> is RESTART";
		break;
	case AppBehavior::Action::KEEPALIVE:
		// keep alive always, used for period run
		m_nextLaunchTime = std::make_unique<std::chrono::system_clock::time_point>(std::chrono::system_clock::now());
		this->registerTimer(0, 0, std::bind(&Application::spawn, this, std::placeholders::_1), fname);
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

std::shared_ptr<std::chrono::system_clock::time_point> Application::scheduleNext(std::chrono::system_clock::time_point now)
{
	const static char fname[] = "Application::scheduleNext() ";

	int timerId = INVALID_TIMER_ID;
	auto next = m_timer->nextTime(now);

	// 1. update m_nextLaunchTime before register timer, spawn will check m_nextLaunchTime
	if (next != AppTimer::EPOCH_ZERO_TIME)
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		m_nextLaunchTime = std::make_unique<std::chrono::system_clock::time_point>(next);
		LOG_DBG << fname << "next start for <" << m_name << "> is " << DateTime::formatLocalTime(*m_nextLaunchTime);
	}

	// 2. register timer
	if (next != AppTimer::EPOCH_ZERO_TIME)
	{
		auto delay = std::chrono::duration_cast<std::chrono::milliseconds>(next - now).count();
		timerId = this->registerTimer(delay, 0, std::bind(&Application::spawn, this, std::placeholders::_1), fname);
	}

	// 3. update timer id
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (timerId > INVALID_TIMER_ID)
	{
		m_nextStartTimerId = timerId;
		LOG_DBG << fname << "next start for <" << m_name << "> is " << DateTime::formatLocalTime(*m_nextLaunchTime);
	}
	else
	{
		m_nextLaunchTime = nullptr;
	}
	return m_nextLaunchTime;
}

void Application::regSuicideTimer(int timeoutSeconds)
{
	const static char fname[] = "Application::regSuicideTimer() ";
	m_suicideTimerId = this->registerTimer(1000L * timeoutSeconds, 0, std::bind(&Application::onSuicide, this, std::placeholders::_1), fname);
}

void Application::setLastError(const std::string &error)
{
	const static char fname[] = "Application::setLastError() ";

	std::lock_guard<std::recursive_mutex> guard(m_errorMutex);
	if (error != m_lastError)
	{
		if (error.length())
		{
			m_lastError = Utility::stringFormat("%s %s", DateTime::formatLocalTime(std::chrono::system_clock::now()).c_str(), error.c_str());
			LOG_DBG << fname << "last error for <" << getName() << ">: " << m_lastError;
		}
		else
		{
			m_lastError.clear();
		}
	}
}

const std::string Application::getLastError() const
{
	std::lock_guard<std::recursive_mutex> guard(m_errorMutex);
	return m_lastError;
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
