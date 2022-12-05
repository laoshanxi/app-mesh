#include <chrono>
#include <list>
#include <string>
#include <thread>

#include <ace/Acceptor.h>
#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <ace/Reactor.h>
#include <ace/SSL/SSL_SOCK_Acceptor.h>
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
#include "rest/RestHandler.h"
#include "rest/TcpServer.h"
#include "security/Security.h"
#ifndef NDEBUG
#include "../common/Valgrind.h"
#endif

typedef ACE_Acceptor<TcpHandler, ACE_SSL_SOCK_Acceptor> TcpAcceptor; // Specialize a Tcp Acceptor.
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
		// ACE::set_handle_limit(); // TODO: this will cause timer issue.
		// create pid file: /var/run/appmesh.pid
		Utility::createPidFile();

		// https://www.cnblogs.com/shelmean/p/9436425.html
		// umask 0022 => 644(-rw-r--r--)
		// umask 0002 => 664(-rw-rw-r--)
		// umask 0000 => 666(-rw-rw-rw-)
		// ACE_OS::umask(0000);

		// init ACE reactor: ACE_TP_Reactor support thread pool-based event dispatching
		TIMER_MANAGER::instance()->reactor()->open(ACE::max_handles());
		if (!ACE_Reactor::instance()->initialized() || !TIMER_MANAGER::instance()->reactor()->initialized())
		{
			std::cerr << "Init reactor failed with error " << std::strerror(errno);
			return -1;
		}

		// init log, before this, do not use logger
		Utility::initLogging("server");
		LOG_INF << fname << "Build: " << __MICRO_VAR__(BUILD_TAG);
		LOG_INF << fname << "Entered working dir: " << fs::current_path().string();
		Utility::initDateTimeZone(true);

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
		const auto configJsonValue = nlohmann::json::parse((configTxt));

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

		// Register QUIT_HANDLER to receive SIGINT commands.
		ACE_Reactor::instance()->register_handler(SIGINT, QUIT_HANDLER::instance());
		ACE_Reactor::instance()->register_handler(SIGTERM, QUIT_HANDLER::instance());
		// threads for timer (application & process event & healthcheck & consul report event)
		m_threadPool.push_back(std::make_unique<std::thread>(std::bind(&TimerManager::runReactorEvent, TIMER_MANAGER::instance()->reactor())));

		// init ACE SSL
		if (config->getRestEnabled())
		{
			TcpHandler::initTcpSSL();
		}
		// init REST
		TcpAcceptor acceptor; // Acceptor factory.
		if (config->getRestEnabled())
		{
			// thread for TCP reactor
			m_threadPool.push_back(std::make_unique<std::thread>(std::bind(&TimerManager::runReactorEvent, ACE_Reactor::instance())));
			// threads for REST service pool
			for (size_t i = 0; i < Configuration::instance()->getThreadPoolSize(); i++)
			{
				m_threadPool.push_back(std::make_unique<std::thread>(TcpHandler::handleTcpRest));
			}
			LOG_INF << fname << "starting <" << Configuration::instance()->getThreadPoolSize() << "> threads for REST thread pool";

			if (acceptor.open(ACE_INET_Addr(Configuration::instance()->getRestTcpPort(), INADDR_ANY), ACE_Reactor::instance()) == -1)
			{
				throw std::runtime_error(std::string("Failed to listen with error: ") + std::strerror(errno));
			}
			// start agent
			Configuration::instance()->addApp(config->getAgentAppJson(), nullptr, false)->execute();

			// reg prometheus
			config->registerPrometheus();
		}

		// HA attach process to App
		auto snap = std::make_shared<Snapshot>();
		auto apps = config->getApps();
		auto snapfile = Utility::readFileCpp(SNAPSHOT_FILE_NAME);
		try
		{
			snap = Snapshot::FromJson(nlohmann::json::parse(snapfile.length() ? snapfile : std::string("{}")));
		}
		catch (...)
		{
			LOG_ERR << fname << "Recover from snapshot failed with error " << std::strerror(errno);
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
		while (QUIT_HANDLER::instance()->is_set() == 0)
		{
			std::this_thread::sleep_for(std::chrono::seconds(Configuration::instance()->getScheduleInterval()));
			PerfLog perf("main while loop");

			// monitor application
			std::list<os::Process> ptree;
			if (Configuration::instance()->prometheusEnabled() && RESTHANDLER::instance()->collected())
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
					LOG_ERR << fname << "Application <" << app->getName() << "> execute failed with error " << std::strerror(errno);
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

	TIMER_MANAGER::instance()->reactor()->end_reactor_event_loop();
	ACE_Reactor::instance()->end_reactor_event_loop();
	TcpHandler::closeMsgQueue();
	// TODO: close TcpAcceptor
	for (const auto &t : m_threadPool)
		t->join();
	// Configuration::instance()->instance(nullptr); // this help free Application obj which trigger process clean
	LOG_INF << fname << "exited";
	return 0;
}
