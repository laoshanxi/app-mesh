#include <algorithm>
#include <assert.h>

#include "../../common/DateTime.h"
#include "../../common/Utility.h"
#include "../../common/os/process.hpp"
#include "../../prom_exporter/counter.h"
#include "../../prom_exporter/gauge.h"
#include "../Configuration.h"
#include "../DailyLimitation.h"
#include "../ResourceCollection.h"
#include "../ResourceLimitation.h"
#include "../process/AppProcess.h"
#include "../process/DockerProcess.h"
#include "../process/MonitoredProcess.h"
#include "../rest/PrometheusRest.h"
#include "../security/Security.h"
#include "../security/User.h"
#include "Application.h"

Application::Application()
	: m_status(STATUS::ENABLED), m_ownerPermission(0), m_shellApp(false), m_stdoutCacheNum(0),
	  m_endTimerId(0), m_health(true), m_appId(Utility::createUUID()),
	  m_version(0), m_process(new AppProcess()), m_pid(ACE_INVALID_PID),
	  m_suicideTimerId(0), m_metricStartCount(nullptr), m_metricMemory(nullptr), m_continueFails(0), m_starts(0)
{
	const static char fname[] = "Application::Application() ";
	LOG_DBG << fname << "Entered.";
	m_regTime = std::chrono::system_clock::now();
	m_posixTimeZone = DateTime::getLocalZoneUTCOffset();
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
			this->m_commandLineInit == app->m_commandLineInit &&
			this->m_commandLineFini == app->m_commandLineFini &&
			this->m_owner == app->m_owner &&
			this->m_ownerPermission == app->m_ownerPermission &&
			this->m_dockerImage == app->m_dockerImage &&
			this->m_version == app->m_version &&
			this->m_workdir == app->m_workdir &&
			this->m_stdoutFile == app->m_stdoutFile &&
			this->m_healthCheckCmd == app->m_healthCheckCmd &&
			this->m_startTime == app->m_startTime &&
			this->m_endTime == app->m_endTime &&
			this->m_status == app->m_status);
}

const std::string Application::getName() const
{
	return m_name;
}

bool Application::isEnabled() const
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	return (m_status == STATUS::ENABLED);
}

bool Application::isWorkingState() const
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	return (m_status == STATUS::ENABLED || m_status == STATUS::DISABLED);
}

void Application::FromJson(const std::shared_ptr<Application> &app, const web::json::value &jsonObj)
{
	app->m_name = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_name));
	auto ownerStr = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_owner));
	if (ownerStr.length())
		app->m_owner = Security::instance()->getUserInfo(ownerStr);
	app->m_ownerPermission = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_owner_permission);
	app->m_shellApp = GET_JSON_BOOL_VALUE(jsonObj, JSON_KEY_APP_shell_mode);
	app->m_metadata = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_metadata));
	app->m_commandLine = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_command));
	// TODO: consider i18n and  legal file name
	app->m_stdoutFile = Utility::stringFormat("appmesh.%s.out", app->m_name.c_str());
	app->m_stdoutCacheNum = GET_JSON_INT_VALUE(jsonObj, JSON_KEY_APP_stdout_cache_num);
	app->m_stdoutFileQueue = std::make_shared<LogFileQueue>(app->m_stdoutFile, app->m_stdoutCacheNum);
	if (app->m_commandLine.length() >= MAX_COMMAND_LINE_LENGTH)
		throw std::invalid_argument("command line length should less than 2048");
	app->m_commandLineInit = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_init_command));
	app->m_commandLineFini = Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_fini_command));
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

	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_SHORT_APP_start_time))
	{
		app->m_startTime = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SHORT_APP_start_time);
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
		app->handleEndTimer();
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_daily_limitation))
	{
		app->m_dailyLimit = DailyLimitation::FromJson(jsonObj.at(JSON_KEY_APP_daily_limitation), app->m_posixTimeZone);
	}
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_APP_REG_TIME))
	{
		app->m_regTime = DateTime::parseISO8601DateTime(GET_JSON_STR_VALUE(jsonObj, JSON_KEY_APP_REG_TIME));
	}
}

void Application::refreshPid(void *ptree)
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	// Try to get return code.
	if (m_process != nullptr)
	{
		if (m_process->running())
		{
			m_pid = m_process->getpid();
			ACE_Time_Value tv;
			tv.msec(10);
			int ret = m_process->wait(tv);
			if (ret > 0)
			{
				m_return = std::make_shared<int>(m_process->return_value());
				m_pid = ACE_INVALID_PID;
				setLastError(Utility::stringFormat("exited with return code: %d, error: %s", *m_return, m_process->startError().c_str()));
			}
		}
		else if (m_pid > 0)
		{
			m_return = std::make_shared<int>(m_process->return_value());
			m_pid = ACE_INVALID_PID;
			setLastError(Utility::stringFormat("exited with return code: %d, error: %s", *m_return, m_process->startError().c_str()));
		}
		checkAndUpdateHealth();
	}

	if (PrometheusRest::instance()->collected())
	{
		if (m_metricMemory)
		{
			auto usage = m_process->getProcUsage(ptree);
			m_metricMemory->metric().Set(std::get<1>(usage));
			m_metricCpu->metric().Set(std::get<2>(usage));
		}
		if (m_metricAppPid)
			m_metricAppPid->metric().Set(m_pid);
		if (m_metricFileDesc)
			m_metricFileDesc->metric().Set(os::fileDescriptors(m_pid));
	}
}

bool Application::attach(int pid)
{
	const static char fname[] = "Application::attach() ";

	if (pid > 1)
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		m_process->attach(pid);
		m_pid = m_process->getpid();
		LOG_INF << fname << "attached pid <" << pid << "> to application " << m_name;
	}
	return true;
}

void Application::invoke(void *ptree)
{
	const static char fname[] = "Application::invoke() ";
	if (isWorkingState())
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		if (this->available())
		{
			if (!m_process->running())
			{
				LOG_INF << fname << "Starting application <" << m_name << "> with user: " << getExecUser();
				m_process.reset(); //m_process->killgroup();
				m_process = allocProcess(false, m_dockerImage, m_name);
				m_procStartTime = std::chrono::system_clock::now();
				m_pid = m_process->spawnProcess(getCmdLine(), getExecUser(), m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata);
				setLastError(m_process->startError());
				if (m_metricStartCount)
					m_metricStartCount->metric().Increment();
			}
		}
		else if (m_process->running())
		{
			LOG_INF << fname << "Application <" << m_name << "> was not in start time";
			m_process->killgroup();
			setInvalidError();
		}
	}
	else
	{
		setLastError("not in working state");
	}

	refreshPid(ptree);
}

void Application::invokeNow(int timerId)
{
	Application::invoke();
}

void Application::disable()
{
	const static char fname[] = "Application::stop() ";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (m_status == STATUS::ENABLED)
	{
		m_status = STATUS::DISABLED;
		m_return = nullptr;
		LOG_INF << fname << "Application <" << m_name << "> disabled.";
	}
	if (m_process != nullptr)
		m_process->killgroup();
	this->cancelTimer(m_endTimerId);
}

void Application::enable()
{
	const static char fname[] = "Application::start() ";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (m_status == STATUS::DISABLED)
	{
		m_status = STATUS::ENABLED;
		//invokeNow(0);
		//LOG_INF << fname << "Application <" << m_name << "> started.";
		handleEndTimer();
	}
	else if (!isWorkingState())
	{
		LOG_WAR << fname << "Application <" << m_name << "> is <" << GET_STATUS_STR(static_cast<int>(m_status)) << "> status, enable is forbidden.";
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

	LOG_INF << fname << "Running application <" << m_name << ">.";
	m_procStartTime = std::chrono::system_clock::now();
	m_pid = m_process->spawnProcess(getCmdLine(), getExecUser(), m_workdir, getMergedEnvMap(), m_resourceLimit, m_stdoutFile, m_metadata);
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

void Application::handleEndTimer()
{
	const static char fname[] = "Application::handleEndTimer() ";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (m_endTimerId == 0)
	{
		// reg finish timer
		auto now = std::chrono::system_clock::now();
		if (m_endTimeValue > now)
		{
			m_endTimerId = this->registerTimer(std::chrono::duration_cast<std::chrono::milliseconds>(m_endTimeValue - now).count(),
											   0, std::bind(&Application::onEndEvent, this, std::placeholders::_1), fname);
		}
		else if (m_endTimeValue.time_since_epoch().count())
		{
			LOG_WAR << fname << "end time for <" << m_name << "> was set and expired, set application to end finished.";
			onEndEvent();
		}
	}
	else
	{
		LOG_WAR << fname << "end timer already exist for <" << m_name << ">.";
	}
}

const std::string Application::getExecUser() const
{
	if (m_owner)
	{
		return m_owner->getExecUser();
	}
	else
	{
		return Configuration::instance()->getDefaultExecUser();
	}
}

const std::string &Application::getCmdLine() const
{
	if (m_shellAppFile != nullptr)
		return m_shellAppFile->getShellStartCmd();
	return m_commandLine;
}

std::string Application::getAsyncRunOutput(const std::string &processUuid, int &exitCode, bool &finished)
{
	const static char fname[] = "Application::getAsyncRunOutput() ";
	finished = false;
	if (m_process != nullptr && m_process->getuuid() == processUuid)
	{
		auto output = m_process->fetchOutputMsg();
		if (output.length() == 0 && !m_process->running())
		{
			exitCode = m_process->return_value();
			finished = true;
			LOG_DBG << fname << "process:" << processUuid << " finished with exit code: " << exitCode;
			return std::string();
		}

		return output;
	}
	else
	{
		throw std::invalid_argument("No corresponding process running or the given process uuid is wrong");
	}
}

void Application::checkAndUpdateHealth()
{
	if (m_healthCheckCmd.empty())
	{
		// judged by pid
		setHealth(m_pid > 0);
	}
	else
	{
		// if pid is zero, always un-health
		if (m_pid <= 0)
		{
			setHealth(false);
		}
		// if pid is none-zero, this will depend on health-script
	}
}

pid_t Application::getpid() const
{
	return m_pid;
}

std::string Application::getOutput(int &position, int index)
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	if (m_process != nullptr && index == 0)
	{
		return m_process->getOutputMsg(position);
	}
	auto file = m_stdoutFileQueue->getFileName(index);
	// TODO: limit read file buffer size, or return stream
	return Utility::readFile(file);
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

int Application::getVersion()
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	return m_version;
}

void Application::setVersion(int version)
{
	std::lock_guard<std::recursive_mutex> guard(m_appMutex);
	m_version = version;
}

bool Application::isCloudApp() const
{
	return m_metadata == JSON_KEY_APP_CLOUD_APP;
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
	if (m_commandLineInit.length())
		result[GET_STRING_T(JSON_KEY_APP_init_command)] = web::json::value::string(GET_STRING_T(m_commandLineInit));
	if (m_commandLineFini.length())
		result[GET_STRING_T(JSON_KEY_APP_fini_command)] = web::json::value::string(GET_STRING_T(m_commandLineFini));
	if (m_healthCheckCmd.length())
		result[GET_STRING_T(JSON_KEY_APP_health_check_cmd)] = web::json::value::string(GET_STRING_T(m_healthCheckCmd));
	if (m_workdir.length())
		result[JSON_KEY_APP_working_dir] = web::json::value::string(GET_STRING_T(m_workdir));
	result[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(m_status));
	if (m_stdoutCacheNum)
		result[JSON_KEY_APP_stdout_cache_num] = web::json::value::number(static_cast<int>(m_stdoutCacheNum));
	if (m_metadata.length())
		result[JSON_KEY_APP_metadata] = web::json::value::string(GET_STRING_T(m_metadata));
	if (returnRuntimeInfo)
	{
		if (m_pid > 0)
		{
			result[JSON_KEY_APP_pid] = web::json::value::number(m_pid);
			result[JSON_KEY_APP_open_fd] = web::json::value::number(os::fileDescriptors(m_pid));
		}
		if (m_return != nullptr)
			result[JSON_KEY_APP_return] = web::json::value::number(*m_return);
		if (m_pid > 0)
		{
			auto usage = m_process->getProcUsage();
			if (std::get<0>(usage))
			{
				result[JSON_KEY_APP_memory] = web::json::value::number(std::get<1>(usage));
				result[JSON_KEY_APP_cpu] = web::json::value::number(std::get<2>(usage));
			}
		}
		if (std::chrono::time_point_cast<std::chrono::hours>(m_procStartTime).time_since_epoch().count() > 24) // avoid print 1970-01-01 08:00:00
			result[JSON_KEY_APP_last_start] = web::json::value::string(DateTime::formatLocalTime(m_procStartTime));
		if (!m_process->containerId().empty())
		{
			result[JSON_KEY_APP_container_id] = web::json::value::string(GET_STRING_T(m_process->containerId()));
		}
		result[JSON_KEY_APP_health] = web::json::value::number(this->getHealth());
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
	auto err = getLastError();
	if (err.length())
		result[JSON_KEY_APP_last_error] = web::json::value::string(err);
	result[JSON_KEY_APP_starts] = web::json::value::number(m_starts);
	return result;
}

void Application::dump()
{
	const static char fname[] = "Application::dump() ";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);

	LOG_DBG << fname << "m_name:" << m_name;
	LOG_DBG << fname << "m_commandLine:" << m_commandLine;
	LOG_DBG << fname << "m_metadata:" << m_metadata;
	LOG_DBG << fname << "m_shellApp:" << m_shellApp;
	LOG_DBG << fname << "m_workdir:" << m_workdir;
	if (m_owner)
		LOG_DBG << fname << "m_owner:" << m_owner->getName();
	LOG_DBG << fname << "m_permission:" << m_ownerPermission;
	LOG_DBG << fname << "m_status:" << static_cast<int>(m_status);
	LOG_DBG << fname << "m_pid:" << m_pid;
	LOG_DBG << fname << "m_posixTimeZone:" << m_posixTimeZone;
	LOG_DBG << fname << "m_startTime:" << m_startTime;
	LOG_DBG << fname << "m_endTime:" << m_endTime;
	LOG_DBG << fname << "m_startTimeValue:" << DateTime::formatLocalTime(m_startTimeValue);
	LOG_DBG << fname << "m_endTimeValue:" << DateTime::formatLocalTime(m_endTimeValue);
	LOG_DBG << fname << "m_regTime:" << DateTime::formatLocalTime(m_regTime);
	LOG_DBG << fname << "m_dockerImage:" << m_dockerImage;
	LOG_DBG << fname << "m_stdoutFile:" << m_stdoutFile;
	LOG_DBG << fname << "m_starts:" << m_starts;
	LOG_DBG << fname << "m_version:" << m_version;
	LOG_DBG << fname << "m_lastError:" << getLastError();
	if (m_dailyLimit != nullptr)
		m_dailyLimit->dump();
	if (m_resourceLimit != nullptr)
		m_resourceLimit->dump();
}

std::shared_ptr<AppProcess> Application::allocProcess(bool monitorProcess, const std::string &dockerImage, const std::string &appName)
{
	std::shared_ptr<AppProcess> process;
	m_stdoutFileQueue->enqueue();
	++m_starts;

	// prepare shell mode script
	if (m_shellApp && (m_shellAppFile == nullptr || !Utility::isFileExist(m_shellAppFile->getShellFileName())))
	{
		m_shellAppFile = nullptr;
		m_shellAppFile = std::make_shared<ShellAppFileGen>(appName, m_commandLine, m_workdir);
	}

	// alloc process object
	if (dockerImage.length())
	{
		process.reset(new DockerProcess(dockerImage, appName));
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

bool Application::isInDailyTimeRange()
{
	//const static char fname[] = "Application::isInDailyTimeRange() ";
	auto nowClock = std::chrono::system_clock::now();
	// 1. check date range
	if (nowClock < m_startTimeValue)
		return false;
	if (m_endTimeValue.time_since_epoch().count() && nowClock > m_endTimeValue)
		return false;
	// 2. check daily range
	if (m_dailyLimit != nullptr)
	{
		// Convert now to day time [%H:%M:%S], less than 24h
		auto now = DateTime::pickDayTimeUtcDuration(nowClock);
		//LOG_DBG << fname << "now: " << now << ", startTime: " << m_dailyLimit->m_startTimeValue << ", endTime: " << m_dailyLimit->m_endTimeValue;
		if (m_dailyLimit->m_startTimeValue < m_dailyLimit->m_endTimeValue)
		{
			// Start less than End means valid range should between start and end.
			return (now >= m_dailyLimit->m_startTimeValue && now < m_dailyLimit->m_endTimeValue);
		}
		else if (m_dailyLimit->m_startTimeValue > m_dailyLimit->m_endTimeValue)
		{
			// Start greater than End means from end to start is invalid range (the valid range is across 0:00).
			return !(now >= m_dailyLimit->m_endTimeValue && now < m_dailyLimit->m_startTimeValue);
		}
	}
	return true;
}

bool Application::available()
{
	return (this->isEnabled() && this->isInDailyTimeRange());
}

void Application::destroy()
{
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		this->disable();
		this->m_status = STATUS::NOTAVIALABLE;
		if (m_commandLineFini.length())
		{
			this->registerTimer(0, 0, std::bind(&Application::onFinishEvent, this, std::placeholders::_1), __FUNCTION__);
		}
	}
	this->cancelTimer(m_suicideTimerId);
}

void Application::onSuicideEvent(int timerId)
{
	const static char fname[] = "Application::onSuicideEvent() ";

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

void Application::onFinishEvent(int timerId)
{
	auto jsonApp = this->AsJson(false);
	jsonApp[JSON_KEY_APP_onetime_application_only] = web::json::value::boolean(true);
	Configuration::instance()->addApp(jsonApp);
}

void Application::onEndEvent(int timerId)
{
	const static char fname[] = "Application::onEndEvent() ";

	std::lock_guard<std::recursive_mutex> guard(m_appMutex);

	// reset timer id
	assert(m_endTimerId == timerId);
	m_endTimerId = 0;

	this->disable();
	this->m_status = STATUS::NOTAVIALABLE;

	LOG_DBG << fname << "Application <" << m_name << "> is end finished";
}

void Application::regSuicideTimer(int timeoutSeconds)
{
	const static char fname[] = "Application::regSuicideTimer() ";

	m_suicideTimerId = this->registerTimer(1000L * timeoutSeconds, 0, std::bind(&Application::onSuicideEvent, this, std::placeholders::_1), fname);
}

void Application::setLastError(const std::string &error)
{
	std::lock_guard<std::recursive_mutex> guard(m_errorMutex);
	if (error.length())
	{
		m_lastError = Utility::stringFormat("%s %s", DateTime::formatLocalTime(std::chrono::system_clock::now()).c_str(), error.c_str());
	}
	else
	{
		m_lastError.clear();
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
