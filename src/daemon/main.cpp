#include <chrono>
#include <string>
#include <thread>

#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <boost/filesystem.hpp>

#include "../common/PerfLog.h"
#include "../common/Utility.h"
#include "../common/os/linux.hpp"
#include "Configuration.h"
#include "HealthCheckTask.h"
#include "PersistManager.h"
#include "ResourceCollection.h"
#include "TimerHandler.h"
#include "application/Application.h"
#include "consul/ConsulConnection.h"
#include "process/AppProcess.h"
#include "rest/PrometheusRest.h"
#include "rest/RestChildObject.h"
#include "rest/RestHandler.h"
#include "rest/RestTcpServer.h"
#ifndef NDEBUG
#include "../common/Valgrind.h"
#endif

void initCpprestThreadPool(int);

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

		// umask 0022 => 644(rw,r,r)
		ACE_OS::umask(0022);
		// init log
		Utility::initLogging();
		LOG_INF << fname << "Entered working dir: " << boost::filesystem::current_path().string();

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

		// init child REST process, the REST process will accept HTTP request and
		// forward to TCP rest service in order to avoid fork() impact REST handler
		if (argc == 2 && std::string("rest") == argv[1])
		{

			Utility::initCpprestThreadPool(Configuration::instance()->getThreadPoolSize());
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
		boost::filesystem::current_path(config->getDefaultWorkDir());

		// set log level
		Utility::setLogLevel(config->getLogLevel());
		Configuration::instance()->dump();

		// init TCP rest service
		std::shared_ptr<RestTcpServer> httpServer;
		if (config->getRestEnabled())
		{
			httpServer = std::make_shared<RestTcpServer>();
			RestTcpServer::instance(httpServer);
			PrometheusRest::instance(httpServer);
			RestTcpServer::instance()->startTcpServer();
			Configuration::instance()->addApp(RestTcpServer::instance()->getRestAppJson());
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
		if (Configuration::instance()->getConsul()->consulEnabled())
		{
			ConsulConnection::instance()->init(consulSsnIdFromRecover);
		}

		// monitor applications
		while (true)
		{
			std::this_thread::sleep_for(std::chrono::seconds(Configuration::instance()->getScheduleInterval()));
			PerfLog perf("main while loop");

			// monitor application
			auto allApp = Configuration::instance()->getApps();
			for (const auto &app : allApp)
			{
				PerfLog perf1(app->getName());
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
	ACE_OS::_exit(0);
	return 0;
}
