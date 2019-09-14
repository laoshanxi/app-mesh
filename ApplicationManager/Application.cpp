#include <algorithm>
#include "Application.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"
#include "../common/TimeZoneHelper.h"
#include "Configuration.h"

Application::Application()
	:m_status(ENABLED), m_return(0), m_cacheOutputLines(0), m_pid(-1), m_processIndex(0)
{
	const static char fname[] = "Application::Application() ";
	LOG_DBG << fname << "Entered.";
	m_process.reset(new Process());
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
	app->m_name = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, "name"));
	app->m_user = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, "run_as"));
	app->m_comments = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, "comments"));
	// Be noticed do not use multiple spaces between command arguments
	// "ping www.baidu.com    123" equals
	// "ping www.baidu.com 123"
	app->m_commandLine = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, "command_line"));
	if (app->m_commandLine.find('>') != std::string::npos)
	{
		throw std::invalid_argument("char '>' is not supported for command line");
	}
	app->m_workdir = Utility::stdStringTrim(GET_JSON_STR_VALUE(jobj, "working_dir"));
	if (HAS_JSON_FIELD(jobj, "status"))
	{
		app->m_status = static_cast<STATUS>GET_JSON_INT_VALUE(jobj, "status");
	}
	if (HAS_JSON_FIELD(jobj, "daily_limitation"))
	{
		app->m_dailyLimit = DailyLimitation::FromJson(jobj.at(GET_STRING_T("daily_limitation")).as_object());
	}
	if (HAS_JSON_FIELD(jobj, "resource_limit"))
	{
		app->m_resourceLimit = ResourceLimitation::FromJson(jobj.at(GET_STRING_T("resource_limit")).as_object(), app->m_name);
	}
	if (HAS_JSON_FIELD(jobj, "env"))
	{
		auto env = jobj.at(GET_STRING_T("env")).as_object();
		for (auto it = env.begin(); it != env.end(); it++)
		{
			app->m_envMap[GET_STD_STRING((*it).first)] = GET_STD_STRING((*it).second.as_string());
		}
	}
	app->m_posixTimeZone = GET_JSON_STR_VALUE(jobj, "posix_timezone");
	if (app->m_posixTimeZone.length() && app->m_dailyLimit != nullptr)
	{
		app->m_dailyLimit->m_startTime = TimeZoneHelper::convert2tzTime(app->m_dailyLimit->m_startTime, app->m_posixTimeZone);
		app->m_dailyLimit->m_endTime = TimeZoneHelper::convert2tzTime(app->m_dailyLimit->m_endTime, app->m_posixTimeZone);
	}
	app->m_cacheOutputLines = std::min(GET_JSON_INT_VALUE(jobj, "cache_lines"), 128);

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
				m_process = allocProcess();
				m_pid = m_process->spawnProcess(m_commandLine, m_user, m_workdir, m_envMap, m_resourceLimit);
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

std::string Application::testRun(int timeoutSeconds, std::map<std::string, std::string> envMap, void* asyncHttpRequest)
{
	const static char fname[] = "Application::testRun() ";
	LOG_DBG << fname << " Entered.";

	std::string processUUID;

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_testProcess != nullptr && m_testProcess->running())
	{
		m_testProcess->killgroup();
	}
	m_testProcess.reset(new MonitoredProcess());
	m_testProcess->setAsyncHttpRequest(asyncHttpRequest);
	processUUID = m_testProcess->getuuid();
	auto oriEnvMap = m_envMap;
	std::for_each(envMap.begin(), envMap.end(), [this](const std::pair<std::string, std::string>& pair)
	{
		m_envMap[pair.first] = pair.second;
	});
	if (m_testProcess->spawnProcess(m_commandLine, m_user, m_workdir, m_envMap, m_resourceLimit) > 0)
	{
		if (envMap.size()) m_envMap = oriEnvMap;	// restore env map
		m_testProcess->regKillTimer(timeoutSeconds, __FUNCTION__);
	}
	else
	{
		if (envMap.size()) m_envMap = oriEnvMap;	// restore env map
		throw std::invalid_argument("Start process failed");
	}

	return processUUID;
}

std::string Application::getTestOutput(const std::string& processUuid, int& exitCode, bool& finished)
{
	const static char fname[] = "Application::getTestOutput() ";

	if (m_testProcess != nullptr && m_testProcess->getuuid() == processUuid)
	{
		auto output = m_testProcess->fecthPipeMessages();
		if (output.length() == 0 && !m_testProcess->running() && m_testProcess->monitorComplete())
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
	if (m_cacheOutputLines)
	{
		auto process = std::dynamic_pointer_cast<MonitoredProcess>(m_process);
		if (process != nullptr)
		{
			if (keepHistory)
				return process->getPipeMessages();
			else
				return process->fecthPipeMessages();
		}
	}
	return std::string();
}

web::json::value Application::AsJson(bool returnRuntimeInfo)
{
	web::json::value result = web::json::value::object();

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	result[GET_STRING_T("name")] = web::json::value::string(GET_STRING_T(m_name));
	result[GET_STRING_T("run_as")] = web::json::value::string(GET_STRING_T(m_user));
	result[GET_STRING_T("command_line")] = web::json::value::string(GET_STRING_T(m_commandLine));
	result[GET_STRING_T("working_dir")] = web::json::value::string(GET_STRING_T(m_workdir));
	result[GET_STRING_T("status")] = web::json::value::number(m_status);
	if (m_comments.length()) result[GET_STRING_T("commentss")] = web::json::value::string(GET_STRING_T(m_comments));
	if (returnRuntimeInfo)
	{
		result[GET_STRING_T("pid")] = web::json::value::number(m_pid);
		result[GET_STRING_T("return")] = web::json::value::number(m_return);
		result[GET_STRING_T("memory")] = web::json::value::number(ResourceCollection::instance()->getRssMemory(m_pid));
	}
	if (m_dailyLimit != nullptr)
	{
		result[GET_STRING_T("daily_limitation")] = m_dailyLimit->AsJson();
	}
	if (m_resourceLimit != nullptr)
	{
		result[GET_STRING_T("resource_limit")] = m_resourceLimit->AsJson();
	}
	if (m_envMap.size())
	{
		web::json::value envs = web::json::value::object();
		std::for_each(m_envMap.begin(), m_envMap.end(), [&envs](const std::pair<std::string, std::string>& pair)
		{
			envs[GET_STRING_T(pair.first)] = web::json::value::string(GET_STRING_T(pair.second));
		});
		result[GET_STRING_T("env")] = envs;
	}
	if (m_posixTimeZone.length()) result[GET_STRING_T("posix_timezone")] = web::json::value::string(m_posixTimeZone);
	if (m_cacheOutputLines) result[GET_STRING_T("cache_lines")] = web::json::value::number(m_cacheOutputLines);
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
	if (m_dailyLimit != nullptr) m_dailyLimit->dump();
	if (m_resourceLimit != nullptr) m_resourceLimit->dump();
}

std::shared_ptr<Process> Application::allocProcess()
{
	std::shared_ptr<Process> process;
	if (m_cacheOutputLines == 0)
	{
		process.reset(new Process());
	}
	else
	{
		process.reset(new MonitoredProcess(m_cacheOutputLines));
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

