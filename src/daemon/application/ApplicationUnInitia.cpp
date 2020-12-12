#include "ApplicationUnInitia.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../process/AppProcess.h"

ApplicationUnInitia::ApplicationUnInitia()
	: m_executed(false)
{
	const static char fname[] = "ApplicationUnInitia::ApplicationUnInitia() ";
	LOG_DBG << fname << "Entered.";
}

ApplicationUnInitia::~ApplicationUnInitia()
{
	const static char fname[] = "ApplicationUnInitia::~ApplicationUnInitia() ";
	LOG_DBG << fname << "Entered.";
}

void ApplicationUnInitia::FromJson(std::shared_ptr<ApplicationUnInitia> &app, const web::json::value &jsonObj)
{
	const static char fname[] = "ApplicationUnInitia::FromJson() ";
	LOG_DBG << fname << "Entered.";
	auto jsonApp = jsonObj;
	std::shared_ptr<Application> fatherApp = app;
	Application::FromJson(fatherApp, jsonApp);
	app->m_application = jsonApp;
	app->m_commandLine = app->m_commandLineFini;
	// avoid fini app re-fini again
	app->m_commandLineFini.clear();
	// clean un-initial flag
	if (HAS_JSON_FIELD(app->m_application, JSON_KEY_APP_onetime_application_only))
	{
		app->m_application.erase(JSON_KEY_APP_onetime_application_only);
	}
}

web::json::value ApplicationUnInitia::AsJson(bool returnRuntimeInfo)
{
	const static char fname[] = "ApplicationUnInitia::AsJson() ";
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
		result[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(STATUS::UNINITIALIZED));
	}
	return result;
}

void ApplicationUnInitia::enable()
{
	const static char fname[] = "ApplicationUnInitia::enable() ";
	LOG_ERR << fname << "Application is in initialize status, enable is not supported";
}

void ApplicationUnInitia::disable()
{
	const static char fname[] = "ApplicationUnInitia::disable() ";
	LOG_WAR << fname << "Application is in initialize status, disable is not supported";
}

bool ApplicationUnInitia::available()
{
	return true;
}

void ApplicationUnInitia::dump()
{
	const static char fname[] = "ApplicationUnInitia::dump() ";

	Application::dump();
	LOG_DBG << fname << "m_executed:" << m_executed;
}

void ApplicationUnInitia::invoke()
{
	const static char fname[] = "ApplicationUnInitia::invoke() ";
	LOG_DBG << fname << "Entered.";

	refreshPid();
	if (!m_executed)
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		m_executed = true;
		if (!m_process->running())
		{
			LOG_INF << fname << "Starting un-initializing for application <" << m_name << ">.";
			m_process = allocProcess(0, "", m_name);
			m_procStartTime = std::chrono::system_clock::now();
			m_pid = m_process->spawnProcess(getCmdLine(), getExecUser(), m_workdir, m_envMap, m_resourceLimit, m_stdoutFile, m_metadata);
			setLastError(m_process->startError());
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
