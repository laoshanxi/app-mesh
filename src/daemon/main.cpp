#include <stdio.h>

#include <atomic>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <set>
#include <fstream>

#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <pplx/threadpool.h>

#include "application/Application.h"
#include "process/AppProcess.h"
#include "Configuration.h"
#include "rest/ConsulConnection.h"
#include "HealthCheckTask.h"
#include "PersistManager.h"
#include "rest/PrometheusRest.h"
#include "ResourceCollection.h"
#include "rest/RestHandler.h"
#include "rest/RestChildObject.h"
#include "rest/RestTcpServer.h"
#include "TimerHandler.h"
#include "../common/os/linux.hpp"
#include "../common/Utility.h"
#include "../common/PerfLog.h"
#ifndef NDEBUG
#include "../common/Valgrind.h"
#endif

std::set<std::shared_ptr<RestHandler>> m_restList;
void initCpprestThreadPool();

int main(int argc, char *argv[])
{
	const static char fname[] = "main() ";
	PRINT_VERSION();
#ifndef NDEBUG
	// enable valgrind in debug mode
	VALGRIND_ENTRYPOINT_ONE_TIME(argv);
#endif

	try
	{
		ACE::init();

		// init log
		Utility::initLogging();
		LOG_INF << fname << "Entered working dir: " << getcwd(NULL, 0);

		// catch SIGHUP for 'systemctl reload'
		Configuration::handleSignal();

		// Resource init
		ResourceCollection::instance()->getHostResource();
		ResourceCollection::instance()->dump();

		// get configuration
		const auto configTxt = Configuration::readConfiguration();
		auto config = Configuration::FromJson(configTxt, true);
		Configuration::instance(config);
		auto configJsonValue = web::json::value::parse(GET_STRING_T(configTxt));
		if (HAS_JSON_FIELD(configJsonValue, JSON_KEY_Applications))
		{
			config->deSerializeApp(configJsonValue.at(JSON_KEY_Applications));
		}

		// init child rest process
		if (argc == 2 && std::string("rest") == argv[1])
		{

			initCpprestThreadPool();
			RestChildObject::instance(std::make_shared<RestChildObject>());
			RestChildObject::instance()->connectAndRun(config->getSeparateRestInternalPort());
			return 0;
		}
		else if (argc > 1)
		{
			LOG_WAR << fname << "no such argument supported";
			return -1;
		}

		// working dir
		Utility::createDirectory(config->getDefaultWorkDir(), 00655);
		ACE_OS::chdir(config->getDefaultWorkDir().c_str());

		// set log level
		Utility::setLogLevel(config->getLogLevel());
		Configuration::instance()->dump();

		// Init Prometheus Exporter
		if (config->getRestEnabled() && config->getPromListenPort())
		{
			initCpprestThreadPool();
			PrometheusRest::instance(std::make_shared<PrometheusRest>(config->getRestListenAddress(), config->getPromListenPort()));
		}

		// // Init REST service
		std::shared_ptr<RestHandler> httpServer;
		if (config->getRestEnabled() && !config->getSeparateRestProcess())
		{
			initCpprestThreadPool();
			// init normal rest service
			httpServer = std::make_shared<RestHandler>(config->getRestListenAddress(), config->getRestListenPort());
			m_restList.insert(httpServer);
		}
		else if (config->getSeparateRestProcess())
		{
			// init TCP rest service
			RestTcpServer::instance(std::make_shared<RestTcpServer>());
			RestTcpServer::instance()->startTcpServer();
			httpServer = RestTcpServer::instance();
			m_restList.insert(httpServer);
			config->addApp(RestTcpServer::instance()->getRestAppJson());
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
			LOG_ERR << "Recover from snapshot failed with error " << std::strerror(errno);
		}
		std::for_each(apps.begin(), apps.end(), [&snap](std::vector<std::shared_ptr<Application>>::reference p) {
			if (snap && snap->m_apps.count(p->getName()))
			{
				auto &appSnapshot = snap->m_apps.find(p->getName())->second;
				auto stat = os::status(appSnapshot.m_pid);
				if (stat && appSnapshot.m_startTime == (int64_t)stat->starttime)
					p->attach(appSnapshot.m_pid);
			}
		});
		// reg prometheus
		config->registerPrometheus();

		// start one thread for timer (application & process event & healthcheck & consul report event)
		auto timerThreadA = std::make_unique<std::thread>(std::bind(&TimerHandler::runReactorEvent, ACE_Reactor::instance()));
		// increase thread here
		//auto timerThreadB = std::make_unique<std::thread>(std::bind(&TimerHandler::runReactorEvent, ACE_Reactor::instance()));

		// init consul
		std::string consulSsnIdFromRecover = snap ? snap->m_consulSessionId : "";
		ConsulConnection::instance()->initTimer(consulSsnIdFromRecover);

		// monitor applications
		while (true)
		{
			std::this_thread::sleep_for(std::chrono::seconds(Configuration::instance()->getScheduleInterval()));
			PerfLog perf(fname);

			// monitor application
			auto allApp = Configuration::instance()->getApps();
			for (const auto &app : allApp)
			{
				app->invoke();
			}

			PersistManager::instance()->persistSnapshot();
			// health-check
			HealthCheckTask::instance()->doHealthCheck();
		}
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << e.what();
	}
	catch (...)
	{
		LOG_ERR << fname << "unknown exception";
	}
	LOG_ERR << fname << "ERROR exited";
	ACE::fini();
	ACE_OS::_exit(0);
	return 0;
}

void initCpprestThreadPool()
{
	const static char fname[] = "initCpprestThreadPool() ";
	static std::atomic_flag initialized = ATOMIC_FLAG_INIT;
	if (!initialized.test_and_set())
	{
		// cpprestsdk thread pool, default will be 40 threads
		crossplat::threadpool::initialize_with_threads(Configuration::instance()->getThreadPoolSize());
		LOG_INF << fname << "REST thread pool size:" << Configuration::instance()->getThreadPoolSize();
	}
}
