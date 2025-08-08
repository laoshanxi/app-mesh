#include <chrono>
#include <list>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <ace/Acceptor.h>
#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <ace/Process_Manager.h>
#include <ace/Reactor.h>
#include <ace/TP_Reactor.h>

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

#if defined(WIN32)
#include <windows.h>
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
#if !defined(NDEBUG) && !defined(WIN32)
#include "../common/Valgrind.h"
#endif

typedef ACE_Acceptor<TcpHandler, ACE_SSL_SOCK_Acceptor> TcpAcceptor; // Specialize a Tcp Acceptor.
static std::vector<std::unique_ptr<std::thread>> m_threadPool;

void runReactorEvent(ACE_Reactor *reactor);
int endReactorEvent(ACE_Reactor *reactor);
void startReactorThreads(ACE_Reactor *reactor, size_t threadCount);

// Windows console control handler (cross-platform guarded)
#if defined(WIN32)
static BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD ctrlType)
{
	switch (ctrlType)
	{
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		QUIT_HANDLER::instance()->set(true);
		if (ACE_Reactor::instance() != nullptr)
		{
			// End reactor event loop to wake reactor threads
			ACE_Reactor::instance()->end_reactor_event_loop();
		}
		return TRUE;
	default:
		return FALSE;
	}
}
#endif

int main(int argc, char *argv[])
{
	const static char fname[] = "main() ";
	PRINT_VERSION();
	std::cout << fname << "App Mesh server starting." << std::endl;
#if !defined(NDEBUG) && !defined(WIN32)
	VALGRIND_ENTRYPOINT_ONE_TIME(argv); // enable valgrind in debug mode
#endif

	try
	{
		ACE::init();
		fs::current_path(Utility::getHomeDir());
		Utility::createPidFile(); // create pid file: appmesh.pid

		// Reactor initialization: choose correct implementation per platform
#if defined(WIN32)
		LOG_INF << fname << "Initializing ACE WFMO_Reactor (Windows)";
		ACE_Reactor::instance(new ACE_Reactor(new ACE_WFMO_Reactor(), true));
#else
		LOG_INF << fname << "Initializing ACE TP_Reactor (POSIX)";
		ACE_Reactor::instance(new ACE_Reactor(new ACE_TP_Reactor(), true));
#endif
		ACE_Reactor::instance()->open(ACE::max_handles());

		// Initialize logging. IMPORTANT: Do not use logger before this point
		fs::create_directories(fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR); // create first for logging
		Utility::initLogging("server");
		LOG_INF << fname << "Build: " << __MICRO_VAR__(BUILD_TAG);
		LOG_INF << fname << "Entered working directory: " << fs::current_path().string();

		{
			// catch SIGHUP for 'systemctl reload' (platform specific implementation inside Configuration)
			Configuration::handleSignal();

			// Resource init
			LOG_INF << fname << "Initializing host resource collection";
			ResourceCollection::instance()->getHostResource();
			ResourceCollection::instance()->dump();
		}

		// get configuration
		auto configJson = Utility::yamlToJson(YAML::Load(Configuration::readConfiguration()));
		auto config = Configuration::FromJson(configJson, true);
		Configuration::instance(config);
		Utility::initDateTimeZone(Configuration::instance()->getPosixTimezone(), true);
		// set log level
		Utility::setLogLevel(config->getLogLevel());

		// init security [both for server side and REST client side (file operation API)]
		Security::init(Configuration::instance()->getJwt()->getJwtInterface());

		// recover applications
		LOG_INF << fname << "Starting application recovery process";
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
#if !defined(WIN32)
			LOG_INF << fname << "Setting directory ownership to user <" << Configuration::instance()->getDefaultExecUser() << ">";
			os::chown(tmpDir, Configuration::instance()->getDefaultExecUser());
			os::chown(outputDir, Configuration::instance()->getDefaultExecUser());
			os::chown(inputDir, Configuration::instance()->getDefaultExecUser());
			os::chown(shellDir, Configuration::instance()->getDefaultExecUser());
#endif
		}

		// Signal / console handling: register cross-platform
#if defined(WIN32)
		// On Windows, register native console handler and do NOT rely on ACE_Reactor SIG handlers.
		SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE);
#else
		// POSIX: register SIGINT/SIGTERM with ACE_Reactor (so QUIT_HANDLER is triggered via reactor)
		ACE_Reactor::instance()->register_handler(SIGINT, QUIT_HANDLER::instance());
		ACE_Reactor::instance()->register_handler(SIGTERM, QUIT_HANDLER::instance());
#endif

		// Process manager: attach to reactor so ACE can dispatch handle_exit.
		Process_Manager::instance()->open(ACE_Process_Manager::DEFAULT_SIZE, ACE_Reactor::instance());

		// start reactor threads
		LOG_INF << fname << "Starting thread(s) for reactor event handler";

		// Decide reactor thread count:
		// - On Windows WFMO_Reactor: use a single reactor thread (WFMO waits on handles).
		// - On POSIX TP_Reactor: keep original behavior: start one reactor thread for process_manager & acceptor,
		//   and if REST enabled, spawn extra reactor thread (matching prior code that added another runReactorEvent when REST enabled).
#if defined(WIN32)
		startReactorThreads(ACE_Reactor::instance(), 1);
#else
		startReactorThreads(ACE_Reactor::instance(), 1); // base thread (we'll add another if REST enabled, below)
#endif

		// start timer manager
		LOG_INF << fname << "Activating timer manager";
		TIMER_MANAGER::instance()->activate();

		// init REST
		TcpClient client;
		TcpAcceptor acceptor; // Acceptor factory.
		ACE_INET_Addr acceptorAddr(Configuration::instance()->getRestTcpPort(), Configuration::instance()->getRestListenAddress().c_str());
		if (config->getRestEnabled())
		{
			LOG_INF << fname << "Initializing REST service on <" << Configuration::instance()->getRestListenAddress() << ":" << Configuration::instance()->getRestTcpPort() << ">";
			TcpHandler::initTcpSSL(ACE_SSL_Context::instance());

#if !defined(WIN32)
			// On POSIX/TP_Reactor we used to spawn an extra reactor thread for REST/acceptor.
			// Keep that behavior for platforms where TP_Reactor is used.
			startReactorThreads(ACE_Reactor::instance(), 1); // spawn one additional reactor thread (POSIX only)
#endif

			// start REST thread pool for TCP request workers
			for (size_t i = 0; i < Configuration::instance()->getThreadPoolSize(); i++)
			{
				m_threadPool.push_back(std::make_unique<std::thread>(TcpHandler::handleTcpRest));
			}
			LOG_INF << fname << "Started <" << Configuration::instance()->getThreadPoolSize() << "> threads for REST thread pool";

			int FLAG_ACE_NONBLOCK = 0; // non-blocking mode disabled (default)
			int FLAG_SO_REUSEADDR = 1; // enable address reuse (default)
			if (acceptor.open(acceptorAddr, ACE_Reactor::instance(), FLAG_ACE_NONBLOCK, 1, FLAG_SO_REUSEADDR) == -1)
			{
				throw std::runtime_error(std::string("Failed to listen on port ") + std::to_string(Configuration::instance()->getRestTcpPort()) + " with error: " + std::strerror(errno));
			}
			client.connect(acceptorAddr);

			// start agent
			if (!Configuration::instance()->isAppExist(SEPARATE_AGENT_APP_NAME))
			{
				LOG_INF << fname << "Starting agent application";
				bool psk = HMACVerifierSingleton::instance()->writePSKToSHM();
				Configuration::instance()->addApp(config->getAgentAppJson(HMACVerifierSingleton::instance()->getShmName()), nullptr, false)->execute();
				if (psk)
				{
					if (!HMACVerifierSingleton::instance()->waitPSKRead())
					{
						throw std::runtime_error("Failed to wait for PSK read from agent process");
					}
				}
			}
			// reg prometheus
			config->registerPrometheus();
		}

		// High Availability: Attach existing processes to Applications
		LOG_INF << fname << "Starting high availability process recovery";
		auto snap = std::make_shared<Snapshot>();
		auto apps = config->getApps();
		auto snapfile = Utility::readFileCpp(SNAPSHOT_FILE_NAME);
		try
		{
			snap = Snapshot::FromJson(nlohmann::json::parse(snapfile.length() ? std::move(snapfile) : std::string("{}")));
			LOG_INF << fname << "Successfully loaded snapshot file";
		}
		catch (const std::exception &ex)
		{
			LOG_ERR << fname << "Failed to recover from snapshot with error: " << ex.what();
			snap = std::make_shared<Snapshot>();
		}
		// token black list recover
		LOG_INF << fname << "Recovering token blacklist";
		TOKEN_BLACK_LIST::instance()->init(snap->m_tokenBlackList);
		// app pid recover
		LOG_INF << fname << "Recovering application processes";
		std::for_each(apps.begin(), apps.end(),
					  [&snap](std::vector<std::shared_ptr<Application>>::reference p)
					  {
						  if (snap && snap->m_apps.count(p->getName()))
						  {
							  auto &appSnapshot = snap->m_apps.find(p->getName())->second;
							  auto stat = os::status(appSnapshot.m_pid);
							  if (stat && appSnapshot.m_startTime == std::chrono::system_clock::to_time_t(stat->get_starttime()))
							  {
								  LOG_INF << "Attaching application <" << p->getName() << "> to existing process PID <" << appSnapshot.m_pid << ">";
								  p->attach(appSnapshot.m_pid);
							  }
						  }
					  });

		// Main application monitoring loop
		fs::current_path(tmpDir);
		int tcpErrorCounter = 0;
		LOG_INF << fname << "Entering main application monitoring loop";
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
				catch (const std::exception &ex)
				{
					LOG_ERR << fname << "Application <" << app->getName() << "> execute failed with error: " << ex.what();
				}
				catch (...)
				{
					LOG_ERR << fname << "Application <" << app->getName() << "> execute failed with unknown error";
				}
			}

			// wait and test connect
			if (Configuration::instance()->getRestEnabled())
			{
				// check tcp and wait
				if (!client.testConnection(Configuration::instance()->getScheduleInterval()))
				{
					tcpErrorCounter++;
					LOG_WAR << fname << "REST TCP connection test failed, attempt <" << tcpErrorCounter << ">";
					if (tcpErrorCounter > 30)
					{
						LOG_ERR << fname << "REST TCP connection test failed more than 30 times, exiting";
						QUIT_HANDLER::instance()->set(true);
						break;
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
		std::cerr << "main() Fatal error: " << e.what() << std::endl;
		LOG_ERR << "main() Fatal error: " << e.what();
	}
	catch (...)
	{
		std::cerr << "main() Unknown fatal exception occurred" << std::endl;
		LOG_ERR << "main() Unknown fatal exception occurred";
	}

	// Begin shutdown sequence: stop reactor loops, join threads, cleanup
	LOG_INF << "main() Ending reactor event loop";
	if (ACE_Reactor::instance() != nullptr)
	{
		// set quit flag (if not already)
		QUIT_HANDLER::instance()->set(true);

		// End reactor event loop(s) to wake any reactor thread(s)
		endReactorEvent(ACE_Reactor::instance());
	}

	/*
	// Join and cleanup threads we created (reactor threads + REST workers)
	for (auto &tptr : m_threadPool)
	{
		if (tptr && tptr->joinable())
		{
			try
			{
				tptr->join();
			}
			catch (const std::exception &ex)
			{
				LOG_WAR << "main() Failed to join thread: " << ex.what();
			}
		}
	}
	m_threadPool.clear();
	*/

	TcpHandler::closeMsgQueue();
	Utility::removeFile((fs::path(Utility::getHomeDir()) / PID_FILE).string());

	LOG_INF << "main() AppMesh daemon exited";
	ACE_OS::_exit(0); // to avoid something hang while exiting, direct exit here.
	ACE::fini();
	return 0;
}

/**
 * @brief Use ACE_Reactor for timer/event handling, block function, should be used in a thread.
 */
void runReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "runReactorEvent() ";
	LOG_DBG << fname << "Reactor event thread started";

	// mark this thread as the owner for the reactor implementation
	reactor->owner(ACE_OS::thr_self());
	while (QUIT_HANDLER::instance()->is_set() == 0 && !reactor->reactor_event_loop_done())
	{
		// run reactor event loop; will block until events arrive or end_reactor_event_loop() called
		reactor->run_reactor_event_loop();
		LOG_WAR << fname << "Reactor event loop interrupted or ended, checking quit flag";
		// if we are asked to quit, break the loop; otherwise we'll restart
		if (QUIT_HANDLER::instance()->is_set())
			break;
	}
	LOG_WAR << fname << "Reactor event thread exiting";
}

/**
 * @brief End ACE_Reactor event loop.
 */
int endReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "endReactorEvent() ";
	LOG_DBG << fname << "Ending reactor event loop";

	if (!reactor)
		return -1;

	// Request reactor to end (this wakes run_reactor_event_loop)
	return reactor->end_reactor_event_loop();
}

/**
 * @brief Start one or more threads running the Reactor event loop.
 *
 * Behavior:
 * - If reactor is WFMO (Windows) we recommend only 1 thread.
 * - Otherwise you can start multiple threads (TP_Reactor / other) as needed.
 */
void startReactorThreads(ACE_Reactor *reactor, size_t threadCount)
{
	const static char fname[] = "startReactorThreads() ";
	if (!reactor)
	{
		LOG_ERR << fname << "null reactor";
		return;
	}

#if defined(WIN32)
	// For Windows WFMO_Reactor: enforce single thread
	threadCount = 1;
#endif

	for (size_t i = 0; i < threadCount; ++i)
	{
		m_threadPool.push_back(std::make_unique<std::thread>(std::bind(&runReactorEvent, reactor)));
	}
}
