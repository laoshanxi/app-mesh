#include <chrono>
#include <list>
#include <string>
#include <thread>

#include <ace/Acceptor.h>
#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <ace/Process_Manager.h>
#include <ace/Reactor.h>
#include <ace/TP_Reactor.h>
#include <boost/filesystem.hpp>
#ifdef __has_include
#if __has_include(<ace/SSL/SSL_Context.h>)
#include <ace/SSL/SSL_Context.h>
#include <ace/SSL/SSL_SOCK_Acceptor.h>
#else
#include <ace/SSL_Context.h>
#include <ace/SSL_SOCK_Acceptor.h>
#endif
#else
#include <ace/SSL/SSL_Context.h>
#include <ace/SSL/SSL_SOCK_Acceptor.h>
#endif

#include "../common/TimerHandler.h"
#include "../common/Utility.h"
#include "../common/os/chown.hpp"
#include "../common/os/pstree.hpp"
#include "Configuration.h"
#include "HealthCheckTask.h"
#include "PersistManager.h"
#include "ResourceCollection.h"
#include "application/Application.h"
#include "process/AppProcess.h"
#include "rest/RestHandler.h"
#include "rest/TcpClient.h"
#include "rest/TcpServer.h"
#include "security/HMACVerifier.h"
#include "security/Security.h"
#include "security/TokenBlacklist.h"
#ifndef NDEBUG
#include "../common/Valgrind.h"
#endif

typedef ACE_Acceptor<TcpHandler, ACE_SSL_SOCK_Acceptor> TcpAcceptor; // Specialize a Tcp Acceptor.
static std::vector<std::unique_ptr<std::thread>> m_threadPool;

void runReactorEvent(ACE_Reactor *reactor);
int endReactorEvent(ACE_Reactor *reactor);

int main(int argc, char *argv[])
{
	const static char fname[] = "main() ";
	PRINT_VERSION();
#ifndef NDEBUG
	VALGRIND_ENTRYPOINT_ONE_TIME(argv); // enable valgrind in debug mode
#endif

	try
	{
		ACE::init();
		// ACE::set_handle_limit(); // TODO: this will cause timer issue.
		fs::current_path(Utility::getHomeDir());

		// create pid file: /appmesh.pid
		Utility::createPidFile();

		// https://www.cnblogs.com/shelmean/p/9436425.html
		// umask 0022 => 644(-rw-r--r--)
		// umask 0002 => 664(-rw-rw-r--)
		// umask 0000 => 666(-rw-rw-rw-)
		// ACE_OS::umask(0000);

		// init ACE reactor: ACE_TP_Reactor support thread pool-based event dispatching
		ACE_Reactor::instance(new ACE_Reactor(new ACE_TP_Reactor(), true));
		ACE_Reactor::instance()->open(ACE::max_handles());
		if (!ACE_Reactor::instance()->initialized())
		{
			std::cerr << "Init reactor failed with error " << std::strerror(errno);
			return -1;
		}

		// Initialize logging. IMPORTANT: Do not use logger before this point
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
		auto configJson = Utility::yamlToJson(YAML::Load(Configuration::readConfiguration()));
		auto config = Configuration::FromJson(configJson, true);
		Configuration::instance(config);
		Utility::initDateTimeZone(Configuration::instance()->getPosixTimezone(), true);

		// init security [both for server side and REST client side (file operation API)]
		Security::init(Configuration::instance()->getJwt()->m_jwtInterface);

		// recover applications
		Utility::removeDir((fs::path(config->getWorkDir()) / "shell").string());
		config->loadApps(fs::path(Utility::getHomeDir()) / APPMESH_APPLICATION_DIR);
		config->loadApps(fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_APPLICATION_DIR);

		// working dir
		Utility::createDirectory(config->getWorkDir());
		const auto tmpDir = (fs::path(config->getWorkDir()) / APPMESH_WORK_TMP_DIR).string();
		const auto outputDir = (fs::path(Configuration::instance()->getWorkDir()) / "stdout").string();
		const auto inputDir = (fs::path(Configuration::instance()->getWorkDir()) / "stdin").string();
		const auto shellDir = (fs::path(Configuration::instance()->getWorkDir()) / "shell").string();
		Utility::createDirectory(tmpDir);
		Utility::createDirectory(outputDir);
		Utility::createDirectory(inputDir);
		Utility::createDirectory(shellDir);
		if (!Configuration::instance()->getDefaultExecUser().empty())
		{
			os::chown(tmpDir, Configuration::instance()->getDefaultExecUser());
			os::chown(outputDir, Configuration::instance()->getDefaultExecUser());
			os::chown(inputDir, Configuration::instance()->getDefaultExecUser());
			os::chown(shellDir, Configuration::instance()->getDefaultExecUser());
		}

		// set log level
		Utility::setLogLevel(config->getLogLevel());
		Configuration::instance()->dump();
		Configuration::instance()->saveConfigToDisk();

		// copy consul config to config dir
		const auto consulConfigSource = (fs::path(Utility::getHomeDir()) / APPMESH_CONSUL_API_CONFIG_FILE).string();
		const auto consulConfigTarget = (fs::path(config->getWorkDir()) / APPMESH_WORK_CONFIG_DIR / APPMESH_CONSUL_API_CONFIG_FILE).string();
		if (Utility::isFileExist(consulConfigSource) && !Utility::isFileExist(consulConfigTarget))
		{
			std::ofstream(consulConfigTarget) << Utility::readFileCpp(consulConfigSource);
		}

		ACE_Reactor::instance()->register_handler(SIGINT, QUIT_HANDLER::instance());
		ACE_Reactor::instance()->register_handler(SIGTERM, QUIT_HANDLER::instance());
		Process_Manager::instance()->open(ACE_Process_Manager::DEFAULT_SIZE, ACE_Reactor::instance());
		// start <1> thread for pooled reactor to handle <Process_Manager> & <ACE_Acceptor>
		m_threadPool.push_back(std::make_unique<std::thread>(std::bind(&runReactorEvent, ACE_Reactor::instance())));

		// start <1> thread for timer event
		TIMER_MANAGER::instance()->activate();

		// init REST
		TcpClient client;
		TcpAcceptor acceptor; // Acceptor factory.
		ACE_INET_Addr acceptorAddr(Configuration::instance()->getRestTcpPort(), Configuration::instance()->getRestListenAddress().c_str());
		if (config->getRestEnabled())
		{
			TcpHandler::initTcpSSL(ACE_SSL_Context::instance());
			// start <1> thread for pooled reactor to handle <Process_Manager> & <ACE_Acceptor>
			m_threadPool.push_back(std::make_unique<std::thread>(std::bind(&runReactorEvent, ACE_Reactor::instance())));
			// start <2> threads for TCP REST service pool
			for (size_t i = 0; i < Configuration::instance()->getThreadPoolSize(); i++)
			{
				m_threadPool.push_back(std::make_unique<std::thread>(TcpHandler::handleTcpRest));
			}
			LOG_INF << fname << "starting <" << Configuration::instance()->getThreadPoolSize() << "> threads for REST thread pool";

			if (acceptor.open(acceptorAddr, ACE_Reactor::instance()) == -1)
			{
				throw std::runtime_error(std::string("Failed to listen with error: ") + std::strerror(errno));
			}
			client.connect(acceptorAddr);
			// start agent
			if (!Configuration::instance()->isAppExist(SEPARATE_AGENT_APP_NAME))
			{
				bool psk = HMACVerifierSingleton::instance()->writePSKToSHM();
				Configuration::instance()->addApp(config->getAgentAppJson(HMACVerifierSingleton::instance()->getShmName()), nullptr, false)->execute();
				if (psk)
					HMACVerifierSingleton::instance()->waitPSKRead();
			}
			// reg prometheus
			config->registerPrometheus();
		}

		// High Availability: Attach existing processes to Applications
		auto snap = std::make_shared<Snapshot>();
		auto apps = config->getApps();
		auto snapfile = Utility::readFileCpp(SNAPSHOT_FILE_NAME);
		try
		{
			snap = Snapshot::FromJson(nlohmann::json::parse(snapfile.length() ? std::move(snapfile) : std::string("{}")));
		}
		catch (...)
		{
			LOG_ERR << fname << "Recover from snapshot failed with error " << std::strerror(errno);
		}
		// token black list recover
		TOKEN_BLACK_LIST::instance()->init(snap->m_tokenBlackList);
		// app pid recover
		std::for_each(apps.begin(), apps.end(),
					  [&snap](std::vector<std::shared_ptr<Application>>::reference p)
					  {
						  if (snap && snap->m_apps.count(p->getName()))
						  {
							  auto &appSnapshot = snap->m_apps.find(p->getName())->second;
							  auto stat = os::status(appSnapshot.m_pid);
							  if (stat && appSnapshot.m_startTime == std::chrono::system_clock::to_time_t(stat->get_starttime()))
								  p->attach(appSnapshot.m_pid);
						  }
					  });

		// Main application monitoring loop
		fs::current_path(tmpDir);
		int tcpErrorCounter = 0;
		while (QUIT_HANDLER::instance()->is_set() == 0)
		{
			std::list<os::Process> ptree;
			auto allApp = Configuration::instance()->getApps();
			for (const auto &app : allApp)
			{
				if (!app->isPersistAble() && app->getName() != SEPARATE_AGENT_APP_NAME)
					continue;
				try
				{
					app->execute((void *)(&ptree));
				}
				catch (...)
				{
					LOG_ERR << fname << "Application <" << app->getName() << "> execute failed with error " << std::strerror(errno);
				}
			}

			// wait and test connect
			if (Configuration::instance()->getRestEnabled())
			{
				// check tcp and wait
				if (!client.testConnection(Configuration::instance()->getScheduleInterval()))
				{
					tcpErrorCounter++;
					if (tcpErrorCounter > 30)
					{
						ACE_OS::_exit(-1);
					}
					std::this_thread::sleep_for(std::chrono::seconds(Configuration::instance()->getScheduleInterval()));
					client.connect(acceptorAddr);
				}
				else
				{
					tcpErrorCounter = 0;
				}
			}
			else
			{
				std::this_thread::sleep_for(std::chrono::seconds(Configuration::instance()->getScheduleInterval()));
			}

			PersistManager::instance()->persistSnapshot();
			HealthCheckTask::instance()->doHealthCheck();
			if (Configuration::instance()->prometheusEnabled() && RESTHANDLER::instance()->collected())
				ptree = os::processes();
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

	endReactorEvent(ACE_Reactor::instance());
	TcpHandler::closeMsgQueue();
	LOG_INF << fname << "exited";
	ACE_OS::_exit(0); // to avoid something hang while exiting, direct exit here.
	ACE::fini();
	return 0;
}

/**
 * @brief Use ACE_Reactor for timer event, block function, should be used in a thread.
 */
void runReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "runReactorEvent() ";
	LOG_DBG << fname << "Entered";

	reactor->owner(ACE_OS::thr_self());
	while (QUIT_HANDLER::instance()->is_set() == 0 && !reactor->reactor_event_loop_done())
	{
		reactor->run_reactor_event_loop();
		LOG_WAR << fname << "reactor_event_loop";
	}
	LOG_WAR << fname << "Exit";
}

/**
 * @brief End ACE_Reactor event loop.
 */
int endReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "endReactorEvent() ";
	LOG_DBG << fname << "Entered";

	return reactor->end_reactor_event_loop();
}
