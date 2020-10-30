#include "ApplicationInitialize.h"
#include "../process/AppProcess.h"
#include "../Configuration.h"
#include "../../common/Utility.h"

ApplicationInitialize::ApplicationInitialize()
	: m_executed(false)
{
	const static char fname[] = "ApplicationInitialize::ApplicationInitialize() ";
	LOG_DBG << fname << "Entered.";
}

ApplicationInitialize::~ApplicationInitialize()
{
	const static char fname[] = "ApplicationInitialize::~ApplicationInitialize() ";
	LOG_DBG << fname << "Entered.";
}

void ApplicationInitialize::FromJson(std::shared_ptr<ApplicationInitialize> &app, const web::json::value &jsonObj)
{
	const static char fname[] = "ApplicationInitialize::FromJson() ";
	LOG_DBG << fname << "Entered.";

	std::shared_ptr<Application> fatherApp = app;
	Application::FromJson(fatherApp, jsonObj);
	app->m_application = jsonObj;
	app->m_commandLine = app->m_commandLineInit;
	// clean initia flag
	if (HAS_JSON_FIELD(app->m_application, JSON_KEY_APP_initial_application_only))
	{
		app->m_application.erase(JSON_KEY_APP_initial_application_only);
	}
}

web::json::value ApplicationInitialize::AsJson(bool returnRuntimeInfo)
{
	const static char fname[] = "ApplicationInitialize::AsJson() ";
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
		result[JSON_KEY_APP_status] = web::json::value::number(static_cast<int>(STATUS::INITIALIZING));
	}
	return result;
}

void ApplicationInitialize::enable()
{
	const static char fname[] = "ApplicationInitialize::enable() ";
	LOG_ERR << fname << "Application is in initialize status, enable is not supported";
}

void ApplicationInitialize::disable()
{
	const static char fname[] = "ApplicationInitialize::disable() ";
	LOG_WAR << fname << "Application is in initialize status, disable is not supported";
}

bool ApplicationInitialize::available()
{
	return true;
}

void ApplicationInitialize::dump()
{
	const static char fname[] = "ApplicationInitialize::dump() ";

	Application::dump();
	LOG_DBG << fname << "m_executed:" << m_executed;
}

void ApplicationInitialize::invoke()
{
	const static char fname[] = "ApplicationInitialize::invoke() ";
	LOG_DBG << fname << "Entered.";

	refreshPid();
	if (!m_executed)
	{
		std::lock_guard<std::recursive_mutex> guard(m_appMutex);
		m_executed = true;
		if (!m_process->running())
		{
			LOG_INF << fname << "Starting initializing for application <" << m_name << ">.";
			m_process = allocProcess(0, "", m_name);
			m_procStartTime = std::chrono::system_clock::now();
			m_pid = m_process->spawnProcess(getCmdLine(), getExecUser(), m_workdir, m_envMap, m_resourceLimit, m_stdoutFile);
		}
		else
		{
			LOG_ERR << fname << "initialize wrongly started for application <" << m_name << ">.";
		}
	}
	else if (m_executed && !m_process->running())
	{
		LOG_DBG << fname << "initialize finished for application <" << getName() << ">.";
		try
		{
			Configuration::instance()->addApp(m_application);
		}
		catch (std::exception &ex)
		{
			LOG_ERR << fname << ex.what();
		}
	}
}
