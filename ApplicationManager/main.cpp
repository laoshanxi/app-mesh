#include <stdio.h>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <fstream>
#include <ace/Init_ACE.h>
#include <pplx/threadpool.h>
#include "RestHandler.h"
#include "../common/Utility.h"
#include "Application.h"
#include "Configuration.h"
#include "ResourceCollection.h"
#include "TimerHandler.h"

static std::shared_ptr<RestHandler> m_httpHandler;

int main(int argc, char * argv[])
{
	const static char fname[] = "main() ";
	PRINT_VERSION();

	try
	{
		ACE::init();
		Utility::initLogging();
		
		LOG_INF << fname << "Entered.";

		// get configuration
		auto config = Configuration::FromJson(Configuration::readConfiguration());

		// set log level
		Utility::setLogLevel(config->getLogLevel());

		// init REST
		if (config->getRestEnabled())
		{
			// Thread pool: 6 threads
			crossplat::threadpool::initialize_with_threads(config->getThreadPoolSize());
			m_httpHandler = std::make_shared<RestHandler>(config->getRestListenAddress(), config->getRestListenPort());
			LOG_INF << fname << "initialize_with_threads:" << config->getThreadPoolSize();
		}

		// HA attach process to App
		auto apps = config->getApps();
		std::map<std::string, int> process;
		AppProcess::getSysProcessList(process, nullptr);
		std::for_each(apps.begin(), apps.end(), [&process](std::vector<std::shared_ptr<Application>>::reference p) { p->attach(process); });

		// Resource init
		ResourceCollection::instance()->getHostResource();
		ResourceCollection::instance()->dump();

		// start one thread for timers
		auto timerThread = std::make_shared<std::thread>(std::bind(&TimerHandler::runTimerThread));
		
		// monitor applications
		auto scheduleInterval = Configuration::instance()->getScheduleInterval();
		while (true)
		{
			std::this_thread::sleep_for(std::chrono::seconds(scheduleInterval));
			auto apps = Configuration::instance()->getApps();
			for (const auto& app : apps)
			{
				app->invoke();
			}
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
