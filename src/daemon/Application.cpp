#include <assert.h>

#include <algorithm>

#include "Application.h"
#include "AppProcess.h"
#include "Configuration.h"
#include "DailyLimitation.h"
#include "DockerProcess.h"
#include "MonitoredProcess.h"
#include "PrometheusRest.h"
#include "ResourceCollection.h"
#include "ResourceLimitation.h"
#include "../common/TimeZoneHelper.h"
#include "../common/Utility.h"
#include "../prom_exporter/counter.h"
#include "../prom_exporter/gauge.h"

Application::Application()
	:m_status(STATUS::ENABLED), m_health(true), m_appId(Utility::createUUID())
	, m_version(0), m_cacheOutputLines(0), m_process(new AppProcess()), m_pid(ACE_INVALID_PID)
	, m_metricStartCount(nullptr), m_metricMemory(nullptr)
{
	const static char fname[] = "Application::Application() ";
	LOG_DBG << fname << "Entered.";
}

Application::~Application()
{
	const static char fname[] = "Application::~Application() ";
	LOG_DBG << fname << "Entered.";
}

bool Application::operator==(const std::shared_ptr<Application>& app)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);

	if (app->m_dailyLimit != nullptr && !app->m_dailyLimit->operator==(this->m_dailyLimit))
		return false;
	if (this->m_dailyLimit != nullptr && !this->m_dailyLimit->operator==(app->m_dailyLimit))
		return false;

	if (app->m_resourceLimit != nullptr && !app->m_resourceLimit->operator==(this->m_resourceLimit))
		return false;
	if (this->m_resourceLimit != nullptr && !this->m_resourceLimit->operator==(app->m_resourceLimit))
		return false;

	return (this->m_name == app->m_name &&
		this->m_commandLine == app->m_commandLine &&
		this->m_user == app->m_user &&
		this->m_dockerImage == app->m_dockerImage &&
		this->m_version == app->m_version &&
		this->m_cacheOutputLines == app->m_cacheOutputLines &&
		this->m_healthCheckCmd == app->m_healthCheckCmd &&
		this->m_posixTimeZone == app->m_posixTimeZone &&
		this->m_status == app->m_status);
}

const std::string Application::getName() const
{
	return m_name;
}

bool Application::isEnabled()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return (m_status == STATUS::ENABLED);
}

bool Application::isUnAvialable()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return (m_status == STATUS::NOTAVIALABLE);
}

void Application::FromJson(std::shared_ptr<Application>& app, const web::json::value& jobj)
{
	app->m_name = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_name));
	app->m_user = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_user));
	if (app->m_user.empty()) app->m_user = "root";
	app->m_comments = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_comments));
	// Be noticed do not use multiple spaces between command arguments
	// "ping www.baidu.com    123" equals
	// "ping www.baidu.com 123"
	app->m_commandLine = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_command));
	if (app->m_commandLine.length() >= MAX_COMMAND_LINE_LENGH) throw std::invalid_argument("command line lengh should less than 2048");
	app->m_healthCheckCmd = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_health_check_cmd));
	if (app->m_healthCheckCmd.length() >= MAX_COMMAND_LINE_LENGH) throw std::invalid_argument("health check lengh should less than 2048");
	app->m_workdir = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_working_dir));
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_status))
	{
		app->m_status = static_cast<STATUS>GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_status);
	}
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_daily_limitation))
	{
		app->m_dailyLimit = DailyLimitation::FromJson(jobj.at(JSON_KEY_APP_daily_limitation));
	}
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_resource_limit))
	{
		app->m_resourceLimit = ResourceLimitation::FromJson(jobj.at(JSON_KEY_APP_resource_limit), app->m_name);
	}
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_env))
	{
		auto envs = jobj.at(JSON_KEY_APP_env).as_object();
		for (auto env : envs)
		{
			app->m_envMap[GET_STD_STRING(env.first)] = GET_STD_STRING(env.second.as_string());
		}
	}
	app->m_posixTimeZone = GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_posix_timezone);
	if (app->m_posixTimeZone.length() && app->m_dailyLimit != nullptr)
	{
		app->m_dailyLimit->m_startTime = TimeZoneHelper::convert2tzTime(app->m_dailyLimit->m_startTime, app->m_posixTimeZone);
		app->m_dailyLimit->m_endTime = TimeZoneHelper::convert2tzTime(app->m_dailyLimit->m_endTime, app->m_posixTimeZone);
	}
	app->m_cacheOutputLines = std::min(GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_cache_lines), MAX_APP_CACHED_LINES);
	app->m_dockerImage = GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_docker_image);
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_pid)) app->attach(GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_pid));
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_version)) SET_JSON_INT_VALUE(jobj, JSON_KEY_APP_version, app->m_version);
}

void Application::refreshPid()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
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
				m_return = std::make_unique<int>(m_process->return_value());
				m_pid = ACE_INVALID_PID;
			}
			checkAndUpdateHealth();
		}
		else if (m_pid > 0)
		{
			m_pid = ACE_INVALID_PID;
		}
	}
	if (m_metricMemory) m_metricMemory->metric().Set(ResourceCollection::instance()->getRssMemory(m_pid));
}

bool Application::attach(int pid)
{
	const static char fname[] = "Application::attach() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_process->attach(pid);
	m_pid = m_process->getpid();
	LOG_INF << fname << "attached pid <" << pid << "> to application " << m_name;
	return true;
}

void Application::invoke()
{
	const static char fname[] = "Application::invoke() ";
	if (!isUnAvialable())
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		if (this->avialable())
		{
			if (!m_process->running())
			{
				LOG_INF << fname << "Starting application <" << m_name << ">.";
				m_process = allocProcess(m_cacheOutputLines, m_dockerImage, m_name);
				m_procStartTime = std::chrono::system_clock::now();
				m_pid = m_process->spawnProcess(m_commandLine, m_user, m_workdir, m_envMap, m_resourceLimit);
				if (m_metricStartCount) m_metricStartCount->metric().Increment();
			}
		}
		else if (m_process->running())
		{
			LOG_INF << fname << "Application <" << m_name << "> was not in daily start time";
			m_process->killgroup();
		}
	}
	refreshPid();
}

void Application::invokeNow(int timerId)
{
	Application::invoke();
}

void Application::disable()
{
	const static char fname[] = "Application::stop() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_status == STATUS::ENABLED)
	{
		m_status = STATUS::DISABLED;
		m_return = nullptr;
		LOG_INF << fname << "Application <" << m_name << "> disabled.";
	}
	if (m_process != nullptr) m_process->killgroup();
}

void Application::enable()
{
	const static char fname[] = "Application::start() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_status == STATUS::DISABLED)
	{
		m_status = STATUS::ENABLED;
		invokeNow(0);
		LOG_INF << fname << "Application <" << m_name << "> started.";
	}
	else if (isUnAvialable())
	{
		LOG_WAR << fname << "Application <" << m_name << "> is UNUSEABLE status, enable is forbidden.";
	}
}

std::string Application::runAsyncrize(int timeoutSeconds)
{
	const static char fname[] = "Application::runSyncrize() ";
	LOG_DBG << fname << " Entered.";

	m_process = allocProcess(m_cacheOutputLines, m_dockerImage, m_name);
	return runApp(timeoutSeconds);
}

std::string Application::runSyncrize(int timeoutSeconds, void* asyncHttpRequest)
{
	const static char fname[] = "Application::runAsyncrize() ";
	LOG_DBG << fname << " Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_cacheOutputLines <= 0)
	{
		LOG_ERR << fname << " m_cacheOutputLines is zero, force set to default value for MonitoredProcess";
		m_cacheOutputLines = MAX_APP_CACHED_LINES;
	}
	m_process = allocProcess(m_cacheOutputLines, m_dockerImage, m_name);
	auto monitProc = std::dynamic_pointer_cast<MonitoredProcess>(m_process);
	assert(monitProc != nullptr);
	monitProc->setAsyncHttpRequest(asyncHttpRequest);

	return runApp(timeoutSeconds);
}

std::string Application::runApp(int timeoutSeconds)
{
	const static char fname[] = "Application::runApp() ";
	LOG_DBG << fname << " Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_dockerImage.length())
	{
		throw std::invalid_argument("Docker application does not support this API");
	}
	assert(m_status != STATUS::ENABLED);

	LOG_INF << fname << "Running application <" << m_name << ">.";

	m_procStartTime = std::chrono::system_clock::now();
	m_pid = m_process->spawnProcess(m_commandLine, m_user, m_workdir, m_envMap, m_resourceLimit);

	if (m_metricStartCount) m_metricStartCount->metric().Increment();

	if (m_pid > 0)
	{
		m_process->regKillTimer(timeoutSeconds, __FUNCTION__);
	}
	else
	{
		throw std::invalid_argument("Start process failed");
	}

	return m_process->getuuid();
}

std::string Application::getAsyncRunOutput(const std::string& processUuid, int& exitCode, bool& finished)
{
	const static char fname[] = "Application::getAsyncRunOutput() ";
	finished = false;
	if (m_process != nullptr && m_process->getuuid() == processUuid)
	{
		auto output = m_process->fetchOutputMsg();
		if (output.length() == 0 && !m_process->running() && m_process->complete())
		{
			exitCode = m_process->return_value();
			finished = true;
			LOG_DBG << fname << "process:" << processUuid << " finished with exit code: " << exitCode;
			return std::string();
		}

		return std::move(output);
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

std::string Application::getOutput(bool keepHistory)
{
	if (m_process != nullptr)
	{
		if (keepHistory)
		{
			return m_process->getOutputMsg();
		}
		else
		{
			return m_process->fetchOutputMsg();
		}
	}
	return std::string();
}

void Application::initMetrics(std::shared_ptr<PrometheusRest> prom)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// clean
	m_metricStartCount = nullptr;
	m_metricMemory = nullptr;
	// update
	if (prom)
	{
		// use uuid in label here to avoid same name app use the same metric cause issue
		m_metricStartCount = prom->createPromCounter(
			PROM_METRIC_NAME_appmgr_prom_process_start_count, PROM_METRIC_HELP_appmgr_prom_process_start_count,
			{ {"application", getName()}, {"id", m_appId} }
		);
		m_metricMemory = prom->createPromGauge(
			PROM_METRIC_NAME_appmgr_prom_process_memory_gauge, PROM_METRIC_HELP_appmgr_prom_process_memory_gauge,
			{ {"application", getName()}, {"id", m_appId} }
		);
	}
}

int Application::getVersion()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_version;
}

void Application::setVersion(int version)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_version = version;
}

web::json::value Application::AsJson(bool returnRuntimeInfo)
{
	web::json::value result = web::json::value::object();

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	result[JSON_KEY_APP_name] = web::json::value::string(GET_STRING_T(m_name));
	if (m_user.length()) result[JSON_KEY_APP_user] = web::json::value::string(GET_STRING_T(m_user));
	if (m_commandLine.length()) result[GET_STRING_T(JSON_KEY_APP_command)] = web::json::value::string(GET_STRING_T(m_commandLine));
	if (m_healthCheckCmd.length()) result[GET_STRING_T(JSON_KEY_APP_health_check_cmd)] = web::json::value::string(GET_STRING_T(m_healthCheckCmd));
	if (m_workdir.length()) result[JSON_KEY_APP_working_dir] = web::json::value::string(GET_STRING_T(m_workdir));
	result[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(m_status));
	if (m_comments.length()) result[JSON_KEY_APP_comments] = web::json::value::string(GET_STRING_T(m_comments));
	if (returnRuntimeInfo)
	{
		if (m_pid > 0) result[JSON_KEY_APP_pid] = web::json::value::number(m_pid);
		if (m_return != nullptr) result[JSON_KEY_APP_return] = web::json::value::number(*m_return);
		if (m_pid > 0) result[JSON_KEY_APP_memory] = web::json::value::number(ResourceCollection::instance()->getRssMemory(m_pid));
		if (std::chrono::time_point_cast<std::chrono::hours>(m_procStartTime).time_since_epoch().count() > 24) // avoid print 1970-01-01 08:00:00
			result[JSON_KEY_APP_last_start] = web::json::value::string(Utility::convertTime2Str(m_procStartTime));
		if (!m_process->containerId().empty())
		{
			result[JSON_KEY_APP_container_id] = web::json::value::string(GET_STRING_T(m_process->containerId()));
		}
		result[JSON_KEY_APP_health] = web::json::value::number(this->getHealth());
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
		std::for_each(m_envMap.begin(), m_envMap.end(), [&envs](const std::pair<std::string, std::string>& pair)
			{
				envs[GET_STRING_T(pair.first)] = web::json::value::string(GET_STRING_T(pair.second));
			});
		result[JSON_KEY_APP_env] = envs;
	}
	if (m_posixTimeZone.length()) result[JSON_KEY_APP_posix_timezone] = web::json::value::string(m_posixTimeZone);
	if (m_cacheOutputLines) result[JSON_KEY_APP_cache_lines] = web::json::value::number(m_cacheOutputLines);
	if (m_dockerImage.length()) result[JSON_KEY_APP_docker_image] = web::json::value::string(m_dockerImage);
	if (m_version) result[JSON_KEY_APP_version] = web::json::value::number(m_version);
	return result;
}

void Application::dump()
{
	const static char fname[] = "Application::dump() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);

	LOG_DBG << fname << "m_name:" << m_name;
	LOG_DBG << fname << "m_commandLine:" << m_commandLine;
	LOG_DBG << fname << "m_workdir:" << m_workdir;
	LOG_DBG << fname << "m_user:" << m_user;
	LOG_DBG << fname << "m_status:" << static_cast<int>(m_status);
	LOG_DBG << fname << "m_pid:" << m_pid;
	LOG_DBG << fname << "m_posixTimeZone:" << m_posixTimeZone;
	LOG_DBG << fname << "m_cacheOutputLines:" << m_cacheOutputLines;
	LOG_DBG << fname << "m_dockerImage:" << m_dockerImage;
	LOG_DBG << fname << "m_version:" << m_version;
	if (m_dailyLimit != nullptr) m_dailyLimit->dump();
	if (m_resourceLimit != nullptr) m_resourceLimit->dump();
}

std::shared_ptr<AppProcess> Application::allocProcess(int cacheOutputLines, std::string dockerImage, std::string appName)
{
	std::shared_ptr<AppProcess> process;
	if (dockerImage.length())
	{
		if (cacheOutputLines > 0)
		{
			process.reset(new DockerProcess(cacheOutputLines, dockerImage, appName));
		}
		else
		{
			process.reset(new DockerProcess(256, dockerImage, appName));
		}
	}
	else
	{
		if (cacheOutputLines > 0)
		{
			process.reset(new MonitoredProcess(cacheOutputLines));
		}
		else
		{
			process.reset(new AppProcess(cacheOutputLines));
		}
	}
	return std::move(process);
}

bool Application::isInDailyTimeRange()
{
	if (m_dailyLimit != nullptr)
	{
		// Convert now to day time [%H:%M:%S], less than 24h
		auto now = Utility::convertStr2DayTime(Utility::convertDayTime2Str(std::chrono::system_clock::now()));

		if (m_dailyLimit->m_startTime < m_dailyLimit->m_endTime)
		{
			// Start less than End means valid range should between start and end.
			return (now >= m_dailyLimit->m_startTime && now < m_dailyLimit->m_endTime);
		}
		else if (m_dailyLimit->m_startTime > m_dailyLimit->m_endTime)
		{
			// Start greater than End means from end to start is invalid range (the valid range is across 0:00).
			return !(now >= m_dailyLimit->m_endTime && now < m_dailyLimit->m_startTime);
		}
	}
	return true;
}

bool Application::avialable()
{
	return (this->isEnabled() && this->isInDailyTimeRange());
}

void Application::destroy()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	this->disable();
	this->m_status = STATUS::NOTAVIALABLE;
}

