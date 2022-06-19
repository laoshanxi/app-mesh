#include <chrono>
#include <list>
#include <string>
#include <thread>

#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <ace/TP_Reactor.h>
#include <boost/filesystem.hpp>

#include "../common/PerfLog.h"
#include "../common/TimerHandler.h"
#include "../common/Utility.h"
#include "../common/os/linux.hpp"
#include "../common/os/pstree.hpp"
#include "Configuration.h"
#include "HealthCheckTask.h"
#include "PersistManager.h"
#include "ResourceCollection.h"
#include "application/Application.h"
#include "consul/ConsulConnection.h"
#include "process/AppProcess.h"
#include "rest/PrometheusRest.h"
#include "rest/RestHandler.h"
#include "rest/RestTcpServer.h"
#include "security/Security.h"
#ifndef NDEBUG
#include "../common/Valgrind.h"
#endif

static std::vector<std::unique_ptr<std::thread>> m_threadPool;

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
		// create pid file: /var/run/appmesh.pid
		if (!Utility::createPidFile())
		{
			return -1;
		}
		// https://www.cnblogs.com/shelmean/p/9436425.html
		// umask 0022 => 644(-rw-r--r--)
		// umask 0002 => 664(-rw-rw-r--)
		// umask 0000 => 666(-rw-rw-rw-)
		ACE_OS::umask(0000);

		// init ACE reactor: ACE_TP_Reactor support thread pool-based event dispatching
		ACE_Reactor::instance(new ACE_Reactor(new ACE_TP_Reactor(), true));
		// check reactor
		if (ACE_Reactor::instance()->initialized() == 0)
		{
			std::cerr << "Init reactor failed with error " << std::strerror(errno);
			return -1;
		}

		// init log, before this, do not use logger
		Utility::initLogging("server");
		LOG_INF << fname << "Build: " << __MICRO_VAR__(BUILD_TAG);
		LOG_INF << fname << "Entered working dir: " << fs::current_path().string();

		{
			// catch SIGHUP for 'systemctl reload'
			Configuration::handleSignal();

			// Resource init
			ResourceCollection::instance()->getHostResource();
			ResourceCollection::instance()->dump();
		}

		// get configuration
		const auto configTxt = Configuration::readConfiguration();
		auto config = Configuration::FromJson(configTxt, true);
		Configuration::instance(config);
		const auto configJsonValue = web::json::value::parse(GET_STRING_T(configTxt));

		// init REST thread pool for cpprestsdk (consul client)
		Utility::initCpprestThreadPool(2);

		// init security [both for server side and REST client side (file operation API)]
		Security::init(Configuration::instance()->getJwt()->m_jwtInterface);

		// recover applications
		if (HAS_JSON_FIELD(configJsonValue, JSON_KEY_Applications))
		{
			config->deSerializeApps(configJsonValue.at(JSON_KEY_Applications));
		}

		// working dir
		Utility::createDirectory(config->getWorkDir());
		fs::current_path(config->getWorkDir());

		// set log level
		Utility::setLogLevel(config->getLogLevel());
		Configuration::instance()->dump();

		// start the 2 threads for timer (application & process event & healthcheck & consul report event)
		m_threadPool.push_back(std::make_unique<std::thread>(std::bind(&TimerHandler::runReactorEvent, ACE_Reactor::instance())));
		m_threadPool.push_back(std::make_unique<std::thread>(std::bind(&TimerHandler::runReactorEvent, ACE_Reactor::instance())));

		// init REST
		if (config->getRestEnabled())
		{
			Configuration::instance()->addApp(config->getAgentAppJson(), nullptr, false)->execute();
			RestTcpServer::instance(std::make_shared<RestTcpServer>());
			std::shared_ptr<RestHandler> httpServer = RestTcpServer::instance();
			RestTcpServer::instance()->startTcpServer();
			// start agent
			auto app = Configuration::instance()->addApp(config->getAgentAppJson(), nullptr, false);
			app->execute();
			PrometheusRest::instance(httpServer);

			// reg prometheus
			config->registerPrometheus();
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
		std::for_each(apps.begin(), apps.end(),
					  [&snap](std::vector<std::shared_ptr<Application>>::reference p)
					  {
						  if (snap && snap->m_apps.count(p->getName()))
						  {
							  auto &appSnapshot = snap->m_apps.find(p->getName())->second;
							  auto stat = os::status(appSnapshot.m_pid);
							  if (stat && appSnapshot.m_startTime == (int64_t)stat->starttime)
								  p->attach(appSnapshot.m_pid);
						  }
					  });

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
			std::list<os::Process> ptree;
			if (PrometheusRest::instance() != nullptr && PrometheusRest::instance()->collected())
				ptree = os::processes();
			auto allApp = Configuration::instance()->getApps();
			for (const auto &app : allApp)
			{
				PerfLog perf1(app->getName());
				try
				{
					app->execute((void *)(&ptree));
				}
				catch (...)
				{
					LOG_ERR << "Recover from snapshot failed with error " << std::strerror(errno);
				}
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
