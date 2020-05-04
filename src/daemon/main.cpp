#include <stdio.h>

#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <set>
#include <fstream>

#include <ace/Init_ACE.h>
#include <pplx/threadpool.h>

#include "Application.h"
#include "AppProcess.h"
#include "Configuration.h"
#include "ConsulConnection.h"
#include "HealthCheckTask.h"
#include "PersistManager.h"
#include "PrometheusRest.h"
#include "ResourceCollection.h"
#include "RestHandler.h"
#include "TimerHandler.h"
#include "../common/os/linux.hpp"
#include "../common/Utility.h"
#include "../common/PerfLog.h"

std::set<std::shared_ptr<RestHandler>> m_restList;

int main(int argc, char* argv[])
{
	const static char fname[] = "main() ";
	PRINT_VERSION();

	try
	{
		ACE::init();

		// set working dir
		ACE_OS::chdir(Utility::getSelfDir().c_str());
		LOG_INF << fname << "Entered working dir: " << getcwd(NULL, 0);

		// init log
		Utility::initLogging();
		
		// catch SIGHUP for 'systemctl reload'
		Configuration::handleReloadSignal();

		// Resource init
		ResourceCollection::instance()->getHostResource();
		ResourceCollection::instance()->dump();

		// get configuration
		auto config = Configuration::FromJson(Configuration::readConfiguration());
		Configuration::instance(config);

		// set log level
		Utility::setLogLevel(config->getLogLevel());
		Configuration::instance()->dump();

		std::shared_ptr<RestHandler> httpServerIp4;
		std::shared_ptr<RestHandler> httpServerIp6;
		if (config->getRestEnabled())
		{
			// Thread pool: 6 threads
			crossplat::threadpool::initialize_with_threads(config->getThreadPoolSize());
			LOG_INF << fname << "initialize_with_threads:" << config->getThreadPoolSize();

			// Init Prometheus Exporter
			PrometheusRest::instance(std::make_shared<PrometheusRest>(config->getRestListenAddress(), config->getPromListenPort()));

			// Init REST
			if (!config->getRestListenAddress().empty())
			{
				// just enable for specified address
				httpServerIp4 = std::make_shared<RestHandler>(config->getRestListenAddress(), config->getRestListenPort());
				m_restList.insert(httpServerIp4);
			}
			else
			{
				// enable for both ipv6 and ipv4
				httpServerIp4 = std::make_shared<RestHandler>("0.0.0.0", config->getRestListenPort());
				m_restList.insert(httpServerIp4);
				try
				{
					httpServerIp6 = std::make_shared<RestHandler>(MY_HOST_NAME, config->getRestListenPort());
					m_restList.insert(httpServerIp6);
				}
				catch (const std::exception & e)
				{
					LOG_ERR << fname << e.what();
				}
				catch (...)
				{
					LOG_ERR << fname << "unknown exception";
				}
			}
		}

		// HA attach process to App
		auto snap = std::make_shared<Snapshot>();
		auto apps = config->getApps();
		auto snapfile = Utility::readFileCpp(SNAPSHOT_FILE_NAME);
		try
		{
			snap = Snapshot::FromJson(web::json::value::parse(snapfile.length() ? snapfile : std::string("{}")));
		}
		catch (...)
		{
			LOG_ERR << "recover snapshot failed with error " << std::strerror(errno);
		}
		std::for_each(apps.begin(), apps.end(), [&snap](std::vector<std::shared_ptr<Application>>::reference p)
			{
				if (snap && snap->m_apps.count(p->getName()))
				{
					auto& appSnapshot = snap->m_apps.find(p->getName())->second;
					auto stat = os::status(appSnapshot.m_pid);
					if (stat && appSnapshot.m_startTime == (int64_t)stat->starttime) p->attach(appSnapshot.m_pid);
				}
				
			});
		// reg prometheus
		config->registerPrometheus();

		// start one thread for timer (application & process event & healthcheck & consul report event)
		auto timerThreadA = std::make_unique<std::thread>(std::bind(&TimerHandler::runReactorEvent, ACE_Reactor::instance()));
		// increase thread here
		//auto timerThreadB = std::make_unique<std::thread>(std::bind(&TimerHandler::runReactorEvent, ACE_Reactor::instance()));

		// init consul
		ConsulConnection::instance()->initTimer(snap->m_consulSessionId);
		// init health-check
		HealthCheckTask::instance()->initTimer();

		// monitor applications
		while (true)
		{
			std::this_thread::sleep_for(std::chrono::seconds(Configuration::instance()->getScheduleInterval()));
			PerfLog perf(fname);

			// monitor application
			auto allApp = Configuration::instance()->getApps();
			for (const auto& app : allApp)
			{
				app->invoke();
			}

			PersistManager::instance()->persistSnapshot();
		}
	}
	catch (const std::exception & e)
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
