#include "ApplicationOnetime.h"
#include "AppProcess.h"
#include "Configuration.h"
#include "../common/Utility.h"

ApplicationOnetime::ApplicationOnetime()
	:m_executed(false)
{
	const static char fname[] = "ApplicationOnetime::ApplicationOnetime() ";
	LOG_DBG << fname << "Entered.";
}


ApplicationOnetime::~ApplicationOnetime()
{
	const static char fname[] = "ApplicationOnetime::~ApplicationOnetime() ";
	LOG_DBG << fname << "Entered.";
}

void ApplicationOnetime::FromJson(std::shared_ptr<ApplicationOnetime>& app, const web::json::value& jobj)
{
	const static char fname[] = "ApplicationOnetime::FromJson() ";
	LOG_DBG << fname << "Entered.";
	auto jsonApp = jobj;
	std::shared_ptr<Application> fatherApp = app;
	Application::FromJson(fatherApp, jsonApp);
	app->m_application = jsonApp;
	app->m_commandLine = app->m_commandLineFini;
	// avoid fini app re-fini again
	app->m_commandLineFini.clear();
}

web::json::value ApplicationOnetime::AsJson(bool returnRuntimeInfo)
{
	const static char fname[] = "ApplicationOnetime::AsJson() ";
	LOG_DBG << fname << "Entered.";
	
	// get runtime info
	auto result = Application::AsJson(returnRuntimeInfo);
	
	// restore original basic info
	for (auto obj : m_application.as_object())
	{
		result[obj.first] = obj.second;
	}

	// override status
	if (returnRuntimeInfo)
	{
		result[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(STATUS::UNINITIALIZING));
	}
	return std::move(result);
}

void ApplicationOnetime::enable()
{
	const static char fname[] = "ApplicationOnetime::enable() ";
	LOG_ERR << fname << "Application is in initialize status, enable is not supported";
}

void ApplicationOnetime::disable()
{
	const static char fname[] = "ApplicationOnetime::disable() ";
	LOG_WAR << fname << "Application is in initialize status, disable is not supported";
}

bool ApplicationOnetime::avialable()
{
	return true;
}

void ApplicationOnetime::dump()
{
	const static char fname[] = "ApplicationOnetime::dump() ";

	Application::dump();
	LOG_DBG << fname << "m_executed:" << m_executed;
}

void ApplicationOnetime::invoke()
{
	const static char fname[] = "ApplicationOnetime::invoke() ";
	LOG_DBG << fname << "Entered.";

	refreshPid();
	if (!m_executed)
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		m_executed = true;
		if (!m_process->running())
		{
			LOG_INF << fname << "Starting uninitializing for application <" << m_name << ">.";
			m_process = allocProcess(m_cacheOutputLines, m_dockerImage, m_name);
			m_procStartTime = std::chrono::system_clock::now();
			m_pid = m_process->spawnProcess(m_commandLine, m_user, m_workdir, m_envMap, m_resourceLimit);
		}
		else
		{
			LOG_ERR << fname << "uninitialize wrongly started for application <" << m_name << ">.";
		}
	}
	else if (m_executed && !m_process->running())
	{
		LOG_DBG << fname << "uninitialize finished for application <" << m_name << ">.";
		Configuration::instance()->removeApp(m_name);
	}
}
