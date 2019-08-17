#include <stdio.h>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <fstream>
#include <ace/Init_ACE.h>

#include "RestHandler.h"
#include "../common/Utility.h"
#include "Application.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "TimerHandler.h"

class AppMonitor
{
public:
	void monitorAllApps(int timerId)
	{
		auto apps = Configuration::instance()->getApps();
		for (const auto& app : apps)
		{
			app->invoke();
		}
	}
};

static std::shared_ptr<RestHandler>       m_httpHandler;
static std::shared_ptr<AppMonitor>        m_mainLoopTimer;
static std::shared_ptr<Configuration>     readConfiguration();

int main(int argc, char * argv[])
{
	const static char fname[] = "main() ";
	PRINT_VERSION();

	try
	{
		ACE::init();
		Utility::initLogging();
		LOG_DBG << fname << "Entered.";

		auto config = readConfiguration();
		Utility::setLogLevel(config->getLogLevel());
		if (config->getRestEnabled())
		{
			m_httpHandler = std::make_shared<RestHandler>(config->getRestListenIp(), config->getRestListenPort());
		}

		auto apps = config->getApps();
		std::map<std::string, int> process;
		Process::getSymProcessList(process, nullptr);
		std::for_each(apps.begin(), apps.end(), [&process](std::vector<std::shared_ptr<Application>>::reference p) { p->attach(process); });

		ResourceCollection::instance()->getHostResource();
		ResourceCollection::instance()->dump();

		auto timerThread = std::make_shared<std::thread>(std::bind(&TimerHandler::runEventLoop));
		
		// Should leave AppMonitor::monitorAllApps in main thread that share thread with timer
		// because monitorAllApps will hold much Reactor lock for long time.
		// 'Timer lock visit App' and App register timer visit timer lock cause dead lock
		m_mainLoopTimer.reset(new AppMonitor());
		auto scheduleInterval = Configuration::instance()->getScheduleInterval();
		while (true)
		{
			std::this_thread::sleep_for(std::chrono::seconds(scheduleInterval));
			m_mainLoopTimer->monitorAllApps(0);
		}
	}
	catch (const std::exception& e)
	{
		LOG_ERR << fname << e.what();
	}
	catch (...)
	{
		LOG_ERR << fname << "unknown exception";
	}
	LOG_ERR << fname << "ERROR exited";
	ACE::fini();
	_exit(0);
	return 0;
}

std::shared_ptr<Configuration> readConfiguration()
{
	const static char fname[] = "readConfiguration() ";

	try
	{
		std::shared_ptr<Configuration> config;
		web::json::value jsonValue;
		std::string jsonPath = Utility::getSelfFullPath() + ".json";
		auto fileStr = Utility::readFileCpp(jsonPath);
		if (fileStr.length() == 0)
		{
			LOG_ERR << "can not open configuration file <" << jsonPath << ">";
			config = std::make_shared<Configuration>();
			throw std::runtime_error("can not open configuration file");
		}
		else
		{
			LOG_DBG << fileStr;
			config = Configuration::FromJson(fileStr);
			config->dump();
		}

		return config;
	}
	catch (const std::exception& e)
	{
		LOG_ERR << fname << e.what();
		throw;
	}
	catch (...)
	{
		LOG_ERR << fname << "unknown exception";
		throw;
	}
}

