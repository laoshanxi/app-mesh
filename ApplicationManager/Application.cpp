#include <algorithm>
#include "Application.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"
#include "../common/TimeZoneHelper.h"
#include "Configuration.h"
#include "DockerProcess.h"

Application::Application()
	:m_status(ENABLED), m_return(0), m_cacheOutputLines(0), m_pid(-1), m_processIndex(0)
{
	const static char fname[] = "Application::Application() ";
	LOG_DBG << fname << "Entered.";
	m_process.reset(new AppProcess());
}


Application::~Application()
{
	const static char fname[] = "Application::~Application() ";
	LOG_DBG << fname << "Entered.";
}

std::string Application::getName()
{
	return m_name;
}

bool Application::isNormal()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return (m_status == ENABLED);
}

void Application::FromJson(std::shared_ptr<Application>& app, const web::json::object& jobj)
{
	app->m_name = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_name));
	app->m_user = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_user));
	if (app->m_user.empty()) app->m_user = "root";
	app->m_comments = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_comments));
	// Be noticed do not use multiple spaces between command arguments
	// "ping www.baidu.com    123" equals
	// "ping www.baidu.com 123"
	app->m_commandLine = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_command));
	if (app->m_commandLine.find('>') != std::string::npos)
	{
		throw std::invalid_argument("char '>' is not supported for command line");
	}
	app->m_workdir = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_working_dir));
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_status))
	{
		app->m_status = static_cast<STATUS>GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_status);
	}
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_daily_limitation))
	{
		app->m_dailyLimit = DailyLimitation::FromJson(jobj.at(JSON_KEY_APP_daily_limitation).as_object());
	}
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_resource_limit))
	{
		app->m_resourceLimit = ResourceLimitation::FromJson(jobj.at(JSON_KEY_APP_resource_limit).as_object(), app->m_name);
	}
	if (HAS_JSON_FIELD(jobj, JSON_KEY_APP_env))
	{
		auto env = jobj.at(JSON_KEY_APP_env).as_object();
		for (auto it = env.begin(); it != env.end(); it++)
		{
			app->m_envMap[GET_STD_STRING((*it).first)] = GET_STD_STRING((*it).second.as_string());
		}
	}
	app->m_posixTimeZone = GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_posix_timezone);
	if (app->m_posixTimeZone.length() && app->m_dailyLimit != nullptr)
	{
		app->m_dailyLimit->m_startTime = TimeZoneHelper::convert2tzTime(app->m_dailyLimit->m_startTime, app->m_posixTimeZone);
		app->m_dailyLimit->m_endTime = TimeZoneHelper::convert2tzTime(app->m_dailyLimit->m_endTime, app->m_posixTimeZone);
	}
	app->m_cacheOutputLines = std::min(GET_JSON_INT_VALUE(jobj, JSON_KEY_APP_cache_lines), 128);
	app->m_dockerImage = GET_JSON_STR_VALUE(jobj, JSON_KEY_APP_docker_image);

	app->dump();
}

void Application::refreshPid()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// Try to get return code.
	if (m_process!= nullptr)
	{
		if (m_process->running())
		{
			m_pid = m_process->getpid();
			ACE_Time_Value tv;
			tv.msec(5);
			int ret = m_process->wait(tv);
			if (ret > 0)
			{
				m_return = m_process->return_value();
			}
		}
		else if (m_pid > 0)
		{
			m_pid = -1;
		}		
	}
}

void Application::attach(std::map<std::string, int>& process)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto iter = process.find(m_commandLine);
	if (iter != process.end())
	{
		m_process->attach(iter->second);
		m_pid = m_process->getpid();
		LOG_INF << "Process <" << m_commandLine << "> is running with pid <" << m_pid << ">.";
		process.erase(iter);
	}
}

void Application::invoke()
{
	const static char fname[] = "Application::invoke() ";
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		if (this->avialable())
		{
			if (!m_process->running())
			{
				LOG_INF << fname << "Starting application <" << m_name << ">.";
				m_process = allocProcess(m_cacheOutputLines, m_dockerImage);
				m_pid = m_process->spawnProcess(m_commandLine, m_user, m_workdir, m_envMap, m_resourceLimit);
				m_procStartTime = std::chrono::system_clock::now();
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

void Application::stop()
{
	const static char fname[] = "Application::stop() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_status != STOPPED)
	{
		if (m_process != nullptr) m_process->killgroup();
		m_status = STOPPED;
		m_return = -1;
		LOG_INF << fname << "Application <" << m_name << "> stopped.";
	}
}

void Application::start()
{
	const static char fname[] = "Application::start() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_status == STOPPED)
	{
		m_status = ENABLED;
		invokeNow(0);
		LOG_INF << fname << "Application <" << m_name << "> started.";
	}
}

std::string Application::testRun(int timeoutSeconds, std::map<std::string, std::string> envMap)
{
	const static char fname[] = "Application::testRun() ";
	LOG_DBG << fname << " Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_testProcess != nullptr && m_testProcess->running())
	{
		m_testProcess->killgroup();
	}
	m_testProcess.reset(new MonitoredProcess(256));
	return runTest(timeoutSeconds, envMap);
}

std::string Application::testAsyncRun(int timeoutSeconds, std::map<std::string, std::string> envMap, void* asyncHttpRequest)
{
	const static char fname[] = "Application::testAsyncRun() ";
	LOG_DBG << fname << " Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_testProcess != nullptr && m_testProcess->running())
	{
		m_testProcess->killgroup();
	}
	m_testProcess.reset(new MonitoredProcess(256));
	m_testProcess->setAsyncHttpRequest(asyncHttpRequest);
	return runTest(timeoutSeconds, envMap);
}

std::string Application::runTest(int timeoutSeconds, const std::map<std::string, std::string>& envMap)
{
	const static char fname[] = "Application::runTest() ";
	LOG_DBG << fname << " Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_dockerImage.length())
	{
		throw std::invalid_argument("Docker application does not support this API");
	}
	std::string processUUID = m_testProcess->getuuid();
	auto combinedEnvMap = m_envMap;
	std::for_each(envMap.begin(), envMap.end(), [&combinedEnvMap](const std::pair<std::string, std::string>& pair)
	{
		combinedEnvMap[pair.first] = pair.second;
	});
	if (m_testProcess->spawnProcess(m_commandLine, m_user, m_workdir, combinedEnvMap, m_resourceLimit) > 0)
	{
		m_testProcess->regKillTimer(timeoutSeconds, __FUNCTION__);
	}
	else
	{
		throw std::invalid_argument("Start process failed");
	}

	return processUUID;
}

std::string Application::getTestOutput(const std::string& processUuid, int& exitCode, bool& finished)
{
	const static char fname[] = "Application::getTestOutput() ";

	if (m_testProcess != nullptr && m_testProcess->getuuid() == processUuid)
	{
		auto output = m_testProcess->fetchOutputMsg();
		if (output.length() == 0 && !m_testProcess->running() && m_testProcess->complete())
		{
			exitCode = m_testProcess->return_value();
			finished = true;
			return "";
		}

		// m_testProcess is not refreshed by main thread. so just wait here.
		ACE_Time_Value tv;
		tv.msec(5);
		if (m_testProcess->wait(tv) > 0)
		{
			LOG_WAR << fname << "Application exited " << m_name;
		}
		return std::move(output);
	}
	else
	{
		throw std::invalid_argument("No corresponding process running or the given process uuid is wrong");
	}
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

web::json::value Application::AsJson(bool returnRuntimeInfo)
{
	web::json::value result = web::json::value::object();

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	result[JSON_KEY_APP_name] = web::json::value::string(GET_STRING_T(m_name));
	if (m_user.length()) result[JSON_KEY_APP_user] = web::json::value::string(GET_STRING_T(m_user));
	result[GET_STRING_T(JSON_KEY_APP_command)] = web::json::value::string(GET_STRING_T(m_commandLine));
	if (m_workdir.length()) result[JSON_KEY_APP_working_dir] = web::json::value::string(GET_STRING_T(m_workdir));
	result[JSON_KEY_APP_status] = web::json::value::number(m_status);
	if (m_comments.length()) result[JSON_KEY_APP_comments] = web::json::value::string(GET_STRING_T(m_comments));
	if (returnRuntimeInfo)
	{
		if (m_pid > 0) result[JSON_KEY_APP_pid] = web::json::value::number(m_pid);
		result[JSON_KEY_APP_return] = web::json::value::number(m_return);
		if (m_pid > 0) result[JSON_KEY_APP_memory] = web::json::value::number(ResourceCollection::instance()->getRssMemory(m_pid));
		if (std::chrono::time_point_cast<std::chrono::hours>(m_procStartTime).time_since_epoch().count() > 24) // avoid print 1970-01-01 08:00:00
			result[JSON_KEY_APP_last_start] = web::json::value::number(std::chrono::duration_cast<std::chrono::seconds>(m_procStartTime.time_since_epoch()).count());
		if (!m_process->containerId().empty())
		{
			result[JSON_KEY_APP_container_id] = web::json::value::string(GET_STRING_T(m_process->containerId()));
		}
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
	LOG_DBG << fname << "m_status:" << m_status;
	LOG_DBG << fname << "m_pid:" << m_pid;
	LOG_DBG << fname << "m_posixTimeZone:" << m_posixTimeZone;
	LOG_DBG << fname << "m_cacheOutputLines:" << m_cacheOutputLines;
	LOG_DBG << fname << "m_dockerImage:" << m_dockerImage;
	if (m_dailyLimit != nullptr) m_dailyLimit->dump();
	if (m_resourceLimit != nullptr) m_resourceLimit->dump();
}

std::shared_ptr<AppProcess> Application::allocProcess(int cacheOutputLines, std::string dockerImage)
{
	std::shared_ptr<AppProcess> process;
	if (dockerImage.length())
	{
		if (cacheOutputLines > 0)
		{
			process.reset(new DockerProcess(cacheOutputLines, dockerImage));
		}
		else
		{
			process.reset(new DockerProcess(256, dockerImage));
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
	return (this->isNormal() && this->isInDailyTimeRange());
}

void Application::destroy()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	this->stop();
	this->m_status = DESTROYED;
	// clean test run process
	if (m_testProcess != nullptr)
	{
		m_testProcess->killgroup();
		m_testProcess = nullptr;
	}
}

