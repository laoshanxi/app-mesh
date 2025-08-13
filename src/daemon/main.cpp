#include <atomic>
#include <chrono>
#include <exception>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <ace/Acceptor.h>
#include <ace/Init_ACE.h>
#include <ace/OS.h>
#include <ace/Process_Manager.h>
#include <ace/Reactor.h>
#if defined(_WIN32)
#include <ace/WFMO_Reactor.h>
#include <windows.h>
#else
#include <ace/TP_Reactor.h>
#endif

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
#if !defined(NDEBUG) && !defined(_WIN32)
#include "../common/Valgrind.h"
#endif

using TcpAcceptor = ACE_Acceptor<TcpHandler, ACE_SSL_SOCK_Acceptor>;

// Global state management
class AppMeshDaemon
{
public:
	AppMeshDaemon() = default;
	~AppMeshDaemon() = default;

	// Non-copyable, non-movable
	AppMeshDaemon(const AppMeshDaemon &) = delete;
	AppMeshDaemon &operator=(const AppMeshDaemon &) = delete;
	AppMeshDaemon(AppMeshDaemon &&) = delete;
	AppMeshDaemon &operator=(AppMeshDaemon &&) = delete;

	int run(int argc, char *argv[]);

public:
	// Initialization methods
	void initializeEnvironment();
	void initializeACE();
	void initializeLogging();
	void initializeConfiguration();
	void initializeSecurity();
	void initializeDirectories();
	void setupSignalHandlers();
	void recoverApplications();

	// Reactor management
	void startReactorThreads(ACE_Reactor *reactor, size_t threadCount);
	void runReactorEvent(ACE_Reactor *reactor);
	int endReactorEvent(ACE_Reactor *reactor);

	// REST service management
	void initializeRestService();
	void startRestThreadPool();
	void startAgentApplication();

	// High availability
	void performHighAvailabilityRecovery();

	// Main loop
	void runMainLoop();
	bool checkTcpConnection(int &errorCounter);
	void executeApplications();

	// Shutdown
	void performShutdown();
	void joinAllThreads();
	void cleanupResources();

	// Utility methods
	void requestShutdown() { m_shutdownRequested.store(true); }
	bool isShutdownRequested() const { return m_shutdownRequested.load(); }

private:
	std::vector<std::unique_ptr<std::thread>> m_threadPool;
	std::unique_ptr<TcpClient> m_client;
	std::unique_ptr<TcpAcceptor> m_acceptor;
	std::atomic<bool> m_shutdownRequested{false};
	std::mutex m_threadPoolMutex;
	std::list<os::Process> m_ptree;
};

// Global daemon instance
static std::unique_ptr<AppMeshDaemon> g_daemon;
static constexpr int MAX_TCP_ERROR_COUNT = 30;

#if defined(_WIN32)
static BOOL WINAPI ConsoleCtrlHandlerRoutine(DWORD ctrlType)
{
	switch (ctrlType)
	{
	case CTRL_C_EVENT:
	case CTRL_CLOSE_EVENT:
	case CTRL_LOGOFF_EVENT:
	case CTRL_SHUTDOWN_EVENT:
		QUIT_HANDLER::instance()->set(true);
		if (g_daemon)
			g_daemon->requestShutdown();
		if (ACE_Reactor::instance())
			ACE_Reactor::instance()->end_reactor_event_loop(); // End reactor event loop to wake reactor threads
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
#if !defined(NDEBUG) && !defined(_WIN32)
	VALGRIND_ENTRYPOINT_ONE_TIME(argv); // enable valgrind in debug mode
#endif

	try
	{
		g_daemon = std::make_unique<AppMeshDaemon>();
		return g_daemon->run(argc, argv);
	}
	catch (const std::exception &e)
	{
		std::cerr << fname << "Fatal error: " << e.what() << std::endl;
		return 1;
	}
	catch (...)
	{
		std::cerr << fname << "Unknown fatal exception occurred" << std::endl;
		return 1;
	}
}

int AppMeshDaemon::run(int argc, char *argv[])
{
	const static char fname[] = "AppMeshDaemon::run() ";

	try
	{
		initializeEnvironment();
		initializeACE();
		initializeLogging();
		initializeConfiguration();
		initializeSecurity();
		initializeDirectories();
		setupSignalHandlers();
		recoverApplications();

		initializeRestService();

		performHighAvailabilityRecovery();
		runMainLoop();
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "Exception in main loop: " << e.what();
		throw;
	}

	performShutdown();
	return 0;
}

void AppMeshDaemon::initializeEnvironment()
{
	const static char fname[] = "AppMeshDaemon::initializeEnvironment() ";

	ACE::init();
	fs::current_path(Utility::getHomeDir());
	Utility::createPidFile();

	LOG_INF << fname << "Environment initialized";
}

void AppMeshDaemon::initializeACE()
{
	const static char fname[] = "AppMeshDaemon::initializeACE() ";

#if defined(_WIN32)
	// On Windows WFMO_Reactor: use a single reactor thread (WFMO waits on handles).
	LOG_INF << fname << "Initializing ACE WFMO_Reactor (Windows)";
	ACE_Reactor::instance(new ACE_Reactor(new ACE_WFMO_Reactor(), true));
	if (ACE_Reactor::instance()->open(ACE_WFMO_Reactor::DEFAULT_SIZE) == -1)
	{
		LOG_WAR << fname << "Failed to open ACE WFMO_Reactor, using default max handles";
	}
#else
	// On POSIX TP_Reactor: start one thread, and extra reactor threads when REST enabled
	LOG_INF << fname << "Initializing ACE TP_Reactor (POSIX)";
	ACE_Reactor::instance(new ACE_Reactor(new ACE_TP_Reactor(), true));
	if (ACE_Reactor::instance()->open(ACE::max_handles()) == -1)
	{
		LOG_WAR << fname << "Failed to open ACE TP_Reactor, using default max handles";
	}
#endif

	// Reactor thread for (process exit event) / (acceptor handling)
	startReactorThreads(ACE_Reactor::instance(), 1);

	// Activate timer manager (start 1 thread by ACE_Thread_Manager::instance())
	LOG_INF << fname << "Activating timer manager";
	TIMER_MANAGER::instance()->activate();

	LOG_INF << fname << "ACE Reactor initialized";
}

void AppMeshDaemon::initializeLogging()
{
	const static char fname[] = "AppMeshDaemon::initializeLogging() ";

	fs::create_directories(fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR);
	Utility::initLogging("server");

	LOG_INF << fname << "Build: " << __MICRO_VAR__(BUILD_TAG);
	LOG_INF << fname << "Entered working directory: " << fs::current_path().string();
}

void AppMeshDaemon::initializeConfiguration()
{
	const static char fname[] = "AppMeshDaemon::initializeConfiguration() ";

	Configuration::handleSignal();

	LOG_INF << fname << "Initializing host resource collection";
	ResourceCollection::instance()->getHostResource();
	ResourceCollection::instance()->dump();

	auto configJson = Utility::yamlToJson(YAML::Load(Configuration::readConfiguration()));
	auto config = Configuration::FromJson(configJson, true);
	Configuration::instance(config);

	Utility::initDateTimeZone(Configuration::instance()->getPosixTimezone(), true);
	Utility::setLogLevel(config->getLogLevel());

	LOG_INF << fname << "Configuration initialized";
}

void AppMeshDaemon::initializeSecurity()
{
	const static char fname[] = "AppMeshDaemon::initializeSecurity() ";

	Security::init(Configuration::instance()->getJwt()->getJwtInterface());

	LOG_INF << fname << "Security initialized";
}

void AppMeshDaemon::initializeDirectories()
{
	const static char fname[] = "AppMeshDaemon::initializeDirectories() ";

	auto config = Configuration::instance();

	// Create working directories
	Utility::createDirectory(config->getWorkDir());

	const auto tmpDir = (fs::path(config->getWorkDir()) / APPMESH_WORK_TMP_DIR).string();
	const auto outputDir = (fs::path(config->getWorkDir()) / "stdout").string();
	const auto inputDir = (fs::path(config->getWorkDir()) / "stdin").string();
	const auto shellDir = (fs::path(config->getWorkDir()) / "shell").string();

	// Remove old shell directory and recreate
	Utility::removeDir(shellDir);

	// Create directories
	std::vector<std::string> dirs = {tmpDir, outputDir, inputDir, shellDir};
	for (const auto &dir : dirs)
	{
		Utility::createDirectory(dir);
	}

	// Set ownership if default exec user is specified
	if (!config->getDefaultExecUser().empty())
	{
#if !defined(_WIN32)
		LOG_INF << fname << "Setting directory ownership to user <" << config->getDefaultExecUser() << ">";
		for (const auto &dir : dirs)
		{
			os::chown(dir, config->getDefaultExecUser());
		}
#endif
	}

	LOG_INF << fname << "Directories initialized";
}

void AppMeshDaemon::setupSignalHandlers()
{
	const static char fname[] = "AppMeshDaemon::setupSignalHandlers() ";

#if defined(_WIN32)
	// On Windows, register native console handler and do NOT rely on ACE_Reactor SIG handlers.
	SetConsoleCtrlHandler(ConsoleCtrlHandlerRoutine, TRUE);
#else
	// POSIX: register SIGINT/SIGTERM with ACE_Reactor (so QUIT_HANDLER is triggered via reactor)
	ACE_Reactor::instance()->register_handler(SIGINT, QUIT_HANDLER::instance());
	ACE_Reactor::instance()->register_handler(SIGTERM, QUIT_HANDLER::instance());
#endif

	Process_Manager::instance()->open(ACE_Process_Manager::DEFAULT_SIZE, ACE_Reactor::instance());

	LOG_INF << fname << "Signal handlers configured";
}

void AppMeshDaemon::recoverApplications()
{
	const static char fname[] = "AppMeshDaemon::recoverApplications() ";

	LOG_INF << fname << "Starting application recovery process";

	auto config = Configuration::instance();
	config->loadApps(fs::path(Utility::getHomeDir()) / APPMESH_APPLICATION_DIR);
	config->loadApps(fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_APPLICATION_DIR);

	LOG_INF << fname << "Applications recovered";
}

void AppMeshDaemon::startReactorThreads(ACE_Reactor *reactor, size_t threadCount)
{
	const static char fname[] = "AppMeshDaemon::startReactorThreads() ";

	if (!reactor)
	{
		throw std::invalid_argument("Null reactor provided");
	}

#if defined(_WIN32)
	threadCount = 1; // WFMO_Reactor requires single thread
#endif

	std::lock_guard<std::mutex> lock(m_threadPoolMutex);

	for (size_t i = 0; i < threadCount; ++i)
	{
		m_threadPool.emplace_back(std::make_unique<std::thread>(
			[this, reactor]()
			{ runReactorEvent(reactor); }));
	}

	LOG_INF << fname << "Started " << threadCount << " reactor threads";
}

void AppMeshDaemon::runReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "AppMeshDaemon::runReactorEvent() ";

	LOG_DBG << fname << "Reactor event thread started";

	reactor->owner(ACE_OS::thr_self());

	while (!isShutdownRequested() && QUIT_HANDLER::instance()->is_set() == 0 && !reactor->reactor_event_loop_done())
	{
		reactor->run_reactor_event_loop();
		if (QUIT_HANDLER::instance()->is_set() || isShutdownRequested())
		{
			break;
		}
		LOG_WAR << fname << "Reactor event loop interrupted, checking quit flag";
	}

	LOG_WAR << fname << "Reactor event thread exiting";
}

int AppMeshDaemon::endReactorEvent(ACE_Reactor *reactor)
{
	const static char fname[] = "AppMeshDaemon::endReactorEvent() ";

	if (!reactor)
	{
		LOG_ERR << fname << "Null reactor";
		return -1;
	}

	LOG_DBG << fname << "Ending reactor event loop";
	return reactor->end_reactor_event_loop();
}

void AppMeshDaemon::initializeRestService()
{
	const static char fname[] = "AppMeshDaemon::initializeRestService() ";

	auto config = Configuration::instance();

	if (!config->getRestEnabled())
	{
		LOG_INF << fname << "REST service is disabled, skipping initialization";
		return;
	}

	LOG_INF << fname << "Initializing REST service on <" << config->getRestListenAddress() << ":" << config->getRestTcpPort() << ">";

	// Initialize SSL
	TcpHandler::initTcpSSL(ACE_SSL_Context::instance());

#if !defined(_WIN32)
	// On POSIX, start additional reactor thread for REST
	startReactorThreads(ACE_Reactor::instance(), 1);
#endif

	// Start REST thread pool
	startRestThreadPool();

	// Setup acceptor
	m_acceptor = std::make_unique<TcpAcceptor>();
	ACE_INET_Addr acceptorAddr(config->getRestTcpPort(), config->getRestListenAddress().c_str());

	constexpr int FLAG_ACE_NONBLOCK = 0;
	constexpr int FLAG_SO_REUSEADDR = 1;

	if (m_acceptor->open(acceptorAddr, ACE_Reactor::instance(), FLAG_ACE_NONBLOCK, 1, FLAG_SO_REUSEADDR) == -1)
	{
		throw std::runtime_error("Failed to listen on port " + std::to_string(config->getRestTcpPort()) + " with error: " + std::strerror(errno));
	}

	// Setup client connection
	m_client = std::make_unique<TcpClient>();
	m_client->connect(acceptorAddr);

	startAgentApplication();
	config->registerPrometheus();

	LOG_INF << fname << "REST service initialized";
}

void AppMeshDaemon::startRestThreadPool()
{
	const static char fname[] = "AppMeshDaemon::startRestThreadPool() ";

	auto config = Configuration::instance();
	std::lock_guard<std::mutex> lock(m_threadPoolMutex);

	for (size_t i = 0; i < config->getThreadPoolSize(); ++i)
	{
		m_threadPool.emplace_back(std::make_unique<std::thread>(TcpHandler::handleTcpRest));
	}

	LOG_INF << fname << "Started " << config->getThreadPoolSize() << " threads for REST thread pool";
}

void AppMeshDaemon::startAgentApplication()
{
	const static char fname[] = "AppMeshDaemon::startAgentApplication() ";

	auto config = Configuration::instance();

	if (!config->isAppExist(SEPARATE_AGENT_APP_NAME))
	{
		LOG_INF << fname << "Starting agent application";

		bool psk = HMACVerifierSingleton::instance()->writePSKToSHM();
		config->addApp(config->getAgentAppJson(HMACVerifierSingleton::instance()->getShmName()), nullptr, false)->execute();

		if (psk && !HMACVerifierSingleton::instance()->waitPSKRead())
		{
			throw std::runtime_error("Failed to wait for PSK read from agent process");
		}
	}
}

void AppMeshDaemon::performHighAvailabilityRecovery()
{
	const static char fname[] = "AppMeshDaemon::performHighAvailabilityRecovery() ";

	LOG_INF << fname << "Starting high availability process recovery";

	auto config = Configuration::instance();
	auto snap = std::make_shared<Snapshot>();

	// Load snapshot
	try
	{
		auto snapfile = Utility::readFileCpp(SNAPSHOT_FILE_NAME);
		auto jsonData = snapfile.empty() ? std::string("{}") : std::move(snapfile);
		snap = Snapshot::FromJson(nlohmann::json::parse(jsonData));
		LOG_INF << fname << "Successfully loaded snapshot file";
	}
	catch (const std::exception &ex)
	{
		LOG_ERR << fname << "Failed to recover from snapshot: " << ex.what();
		snap = std::make_shared<Snapshot>();
	}

	// Recover token blacklist
	LOG_INF << fname << "Recovering token blacklist";
	TOKEN_BLACK_LIST::instance()->init(snap->m_tokenBlackList);

	// Recover application processes
	LOG_INF << fname << "Recovering application processes";
	auto apps = config->getApps();

	for (const auto &app : apps)
	{
		if (snap && snap->m_apps.count(app->getName()))
		{
			const auto &appSnapshot = snap->m_apps.find(app->getName())->second;
			auto stat = os::status(appSnapshot.m_pid);

			if (stat && appSnapshot.m_startTime == std::chrono::system_clock::to_time_t(stat->get_starttime()))
			{
				LOG_INF << fname << "Attaching application <" << app->getName() << "> to existing process PID <" << appSnapshot.m_pid << ">";
				app->attach(appSnapshot.m_pid);
			}
		}
	}

	LOG_INF << fname << "High availability recovery completed";
}

void AppMeshDaemon::runMainLoop()
{
	const static char fname[] = "AppMeshDaemon::runMainLoop() ";

	// Change to temp directory
	auto config = Configuration::instance();
	const auto tmpDir = (fs::path(config->getWorkDir()) / APPMESH_WORK_TMP_DIR).string();
	fs::current_path(tmpDir);

	int tcpErrorCounter = 0;
	LOG_INF << fname << "Entering main application monitoring loop";

	while (!isShutdownRequested() && QUIT_HANDLER::instance()->is_set() == 0)
	{
		try
		{
			executeApplications();

			if (config->getRestEnabled())
			{
				if (!checkTcpConnection(tcpErrorCounter))
				{
					break; // Exit if TCP connection fails too many times
				}
			}
			else
			{
				std::this_thread::sleep_for(std::chrono::seconds(config->getScheduleInterval()));
			}

			PersistManager::instance()->persistSnapshot();
			HealthCheckTask::instance()->doHealthCheck();

			// Update process tree for prometheus if needed
			if (config->prometheusEnabled() && RESTHANDLER::instance()->collected())
			{
				m_ptree = os::processes();
			}
		}
		catch (const std::exception &ex)
		{
			LOG_ERR << fname << "Exception in main loop: " << ex.what();
		}
	}

	LOG_INF << fname << "Exiting main monitoring loop";
}

bool AppMeshDaemon::checkTcpConnection(int &errorCounter)
{
	const static char fname[] = "AppMeshDaemon::checkTcpConnection() ";

	auto config = Configuration::instance();

	if (!m_client->testConnection(config->getScheduleInterval()))
	{
		errorCounter++;
		LOG_WAR << fname << "REST TCP connection test failed, attempt <" << errorCounter << ">";

		if (errorCounter > MAX_TCP_ERROR_COUNT)
		{
			LOG_ERR << fname << "REST TCP connection test failed more than " << MAX_TCP_ERROR_COUNT << " times, requesting shutdown";
			requestShutdown();
			QUIT_HANDLER::instance()->set(true);
			return false;
		}

		std::this_thread::sleep_for(std::chrono::seconds(config->getScheduleInterval()));

		// Reconnect
		ACE_INET_Addr acceptorAddr(config->getRestTcpPort(), config->getRestListenAddress().c_str());
		m_client->connect(acceptorAddr);
	}
	else
	{
		errorCounter = 0;
	}

	return true;
}

void AppMeshDaemon::executeApplications()
{
	const static char fname[] = "AppMeshDaemon::executeApplications() ";

	auto allApps = Configuration::instance()->getApps();

	for (const auto &app : allApps)
	{
		if (!app->isPersistAble() && app->getName() != SEPARATE_AGENT_APP_NAME)
		{
			continue;
		}

		try
		{
			app->execute(static_cast<void *>(&m_ptree));
		}
		catch (const std::exception &ex)
		{
			LOG_ERR << fname << "Application <" << app->getName() << "> execute failed: " << ex.what();
		}
		catch (...)
		{
			LOG_ERR << fname << "Application <" << app->getName() << "> execute failed with unknown error";
		}
	}
}

void AppMeshDaemon::performShutdown()
{
	const static char fname[] = "AppMeshDaemon::performShutdown() ";

	LOG_INF << fname << "Beginning shutdown sequence";

	requestShutdown();
	QUIT_HANDLER::instance()->set(true);

	endReactorEvent(ACE_Reactor::instance());

	// joinAllThreads();
	cleanupResources();

	LOG_INF << fname << "AppMesh daemon exited";

	ACE_OS::_exit(0);
	ACE::fini();
}

void AppMeshDaemon::joinAllThreads()
{
	const static char fname[] = "AppMeshDaemon::joinAllThreads() ";

	std::lock_guard<std::mutex> lock(m_threadPoolMutex);

	for (auto &threadPtr : m_threadPool)
	{
		if (threadPtr && threadPtr->joinable())
		{
			try
			{
				threadPtr->join();
			}
			catch (const std::exception &ex)
			{
				LOG_WAR << fname << "Failed to join thread: " << ex.what();
			}
		}
	}

	m_threadPool.clear();
	LOG_INF << fname << "All threads joined";
}

void AppMeshDaemon::cleanupResources()
{
	const static char fname[] = "AppMeshDaemon::cleanupResources() ";

	try
	{
		TcpHandler::closeMsgQueue();
		Utility::removeFile((fs::path(Utility::getHomeDir()) / PID_FILE).string());
		LOG_INF << fname << "Resources cleaned up";
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "Error during cleanup: " << ex.what();
	}
}
