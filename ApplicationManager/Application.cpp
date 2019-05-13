#include "Application.h"
#include "ResourceCollection.h"
#include "../common/Utility.h"
#include "../common/TimeZoneHelper.h"
#include "Configuration.h"

Application::Application()
	:m_active(NORMAL), m_return(0), m_runOnce(false), m_pid(-1), m_processIndex(0)
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
	return (m_active == NORMAL);
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
	if (HAS_JSON_FIELD(jobj, "active"))
	{
		app->m_active = static_cast<STATUS>GET_JSON_INT_VALUE(jobj, "active");
	}
	if (HAS_JSON_FIELD(jobj, "daily_limitation"))
	{
		app->m_dailyLimit = DailyLimitation::FromJson(jobj.at(GET_STRING_T("daily_limitation")).as_object());
	}
	if (HAS_JSON_FIELD(jobj, "resource_limit"))
	{
		app->m_resourceLimit = ResourceLimitation::FromJson(jobj.at(GET_STRING_T("resource_limit")).as_object());
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
	app->m_runOnce = GET_JSON_BOOL_VALUE(jobj, "run_once");
	if (app->m_runOnce) app->m_active = STOPPED;	// Just set to stopped for shell app
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
				m_pid = this->spawnProcess(m_process);
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
	if (m_active != STOPPED)
	{
		if (m_process != nullptr) m_process->killgroup();
		m_active = STOPPED;
		m_return = -1;
		LOG_INF << fname << "Application <" << m_name << "> stopped.";
	}
}

void Application::start()
{
	const static char fname[] = "Application::start() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_active == STOPPED)
	{
		m_active = NORMAL;
		invokeNow(0);
		LOG_INF << fname << "Application <" << m_name << "> started.";
	}
}

std::string Application::testRun(size_t timeoutSeconds)
{
	const static char fname[] = "Application::testRun() ";
	LOG_DBG << fname << " Entered.";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (m_testProcess != nullptr && m_testProcess->running())
	{
		m_testProcess->killgroup();
	}
	m_testProcess.reset(new MonitoredProcess());

	if (this->spawnProcess(m_testProcess) > 0)
	{
		m_testProcess->regKillTimer(timeoutSeconds, __FUNCTION__);
		return m_testProcess->getuuid();
	}
	else
	{
		throw std::invalid_argument("Start process failed");
	}
}

std::string Application::getTestOutput(const std::string& processUuid)
{
	const static char fname[] = "Application::getTestOutput() ";

	if (m_testProcess != nullptr && m_testProcess->getuuid() == processUuid)
	{
		auto output = m_testProcess->fecthPipeMessages();
		if (output.length() == 0 && !m_testProcess->running())
		{
			throw std::invalid_argument("Process already finished or killed by timeout event");
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

web::json::value Application::AsJson(bool returnRuntimeInfo)
{
	web::json::value result = web::json::value::object();

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	result[GET_STRING_T("name")] = web::json::value::string(GET_STRING_T(m_name));
	result[GET_STRING_T("run_as")] = web::json::value::string(GET_STRING_T(m_user));
	result[GET_STRING_T("command_line")] = web::json::value::string(GET_STRING_T(m_commandLine));
	result[GET_STRING_T("working_dir")] = web::json::value::string(GET_STRING_T(m_workdir));
	result[GET_STRING_T("active")] = web::json::value::number(m_active);
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
	result[GET_STRING_T("run_once")] = web::json::value::boolean(m_runOnce);
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
	LOG_DBG << fname << "m_status:" << m_active;
	LOG_DBG << fname << "m_pid:" << m_pid;
	LOG_DBG << fname << "m_posixTimeZone:" << m_posixTimeZone;
	if (m_dailyLimit != nullptr) m_dailyLimit->dump();
	if (m_resourceLimit != nullptr) m_resourceLimit->dump();
}

int Application::spawnProcess(std::shared_ptr<Process> process)
{
	const static char fname[] = "Application::spawnProcess() ";

	int pid;
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	unsigned int gid, uid;
	Utility::getUid(m_user, uid, gid);
	size_t cmdLenth = m_commandLine.length() + ACE_Process_Options::DEFAULT_COMMAND_LINE_BUF_LEN;
	int totalEnvSize = 0;
	int totalEnvArgs = 0;
	Utility::getEnvironmentSize(m_envMap, totalEnvSize, totalEnvArgs);
	ACE_Process_Options option(1, cmdLenth, totalEnvSize, totalEnvArgs);
	option.command_line(m_commandLine.c_str());
	//option.avoid_zombies(1);
	option.seteuid(uid);
	option.setruid(uid);
	option.setegid(gid);
	option.setrgid(gid);
	option.setgroup(0);
	option.inherit_environment(true);
	option.handle_inheritance(0);
	option.working_directory(m_workdir.c_str());
	std::for_each(m_envMap.begin(), m_envMap.end(), [&option](const std::pair<std::string, std::string>& pair)
	{
		option.setenv(pair.first.c_str(), "%s", pair.second.c_str());
	});
	if (process->spawn(option) >= 0)
	{
		pid = process->getpid();
		LOG_INF << fname << "Process <" << m_commandLine << "> started with pid <" << pid << ">.";
		process->setCgroup(m_name, ++m_processIndex, m_resourceLimit);
	}
	else
	{
		pid = -1;
		LOG_ERR << fname << "Process:<" << m_commandLine << "> start failed with error : " << std::strerror(errno);
	}
	return pid;
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
	this->m_active = DESTROYED;
	// clean test run process
	if (m_testProcess != nullptr) m_testProcess->killgroup();
}

