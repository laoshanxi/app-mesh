// src/daemon/main.cpp
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
#include <ace/TP_Reactor.h>
#include <spdlog/spdlog.h>

#if defined(_WIN32)
#include "ace/WFMO_Reactor.h" // For windows ACE_Process_Manager
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

#include "../common/QuitHandler.h"
#include "../common/RestClient.h"
#include "../common/TimerHandler.h"
#include "../common/Utility.h"
#include "../common/os/chown.h"
#include "../common/os/pstree.h"
#include "Configuration.h"
#include "HealthCheckTask.h"
#include "PersistManager.h"
#include "ResourceCollection.h"
#include "application/Application.h"
#include "process/AppProcess.h"
#include "rest/RestHandler.h"
#include "rest/SSLHelper.h"
#include "rest/SocketServer.h"
#include "rest/SocketStream.h"
#include "rest/Worker.h"
#include "security/HMACVerifier.h"
#include "security/Security.h"
#include "security/TokenBlacklist.h"
#if !defined(NDEBUG) && !defined(_WIN32)
#include "../common/Valgrind.h"
#endif

#if defined(HAVE_UWEBSOCKETS)
#include "rest/uwebsockets/Adaptor.hpp"
#else
#include "../common/lwsservice/WebSocketService.h"
#endif

using TcpAcceptor = ACE_Acceptor<SocketServer, ACE_SSL_SOCK_Acceptor>;

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

	// REST service management
	void initializeRestService();
	void startWorkerThreadPool();
	void startAgentApplication();

	// High availability
	void performHighAvailabilityRecovery();

	// Main loop
	void runMainLoop();
	bool checkTcpConnection(int &errorCounter);
	void executeApplications();

	// Shutdown
	void performShutdown();
	void cleanWorkerThreads();
	void cleanupResources();

private:
	std::vector<std::unique_ptr<std::thread>> m_threadPool;
	std::shared_ptr<SocketStreamPtr> m_client;
	std::unique_ptr<TcpAcceptor> m_acceptor;
	std::list<os::Process> m_ptree;
};

// Global daemon instance
static std::unique_ptr<AppMeshDaemon> g_daemon;
static constexpr int MAX_TCP_ERROR_COUNT = 30;

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
		initializeLogging();
		initializeConfiguration();
		initializeACE();
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
	}

	performShutdown();
	return 0;
}

void AppMeshDaemon::initializeEnvironment()
{
	// logging not available yet
	ACE::init();
	fs::current_path(Utility::getHomeDir());
	Utility::createPidFile();
	Utility::ensureSystemRoot();
}

void AppMeshDaemon::initializeACE()
{
	const static char fname[] = "AppMeshDaemon::initializeACE() ";

	// Singleton initialization without lock
	TIMER_MANAGER::instance();
	QuitHandler::instance();
	WORKER::instance();

	LOG_INF << fname << "Initializing ACE TP_Reactor (POSIX)";
	ACE_Reactor::instance(new ACE_Reactor(new ACE_TP_Reactor(), true));
	if (ACE_Reactor::instance()->open(ACE::max_handles()) == -1)
	{
		LOG_WAR << fname << "Failed to open ACE TP_Reactor, using default max handles";
	}

	// Reactor thread for (process exit event) / (acceptor handling)
	startReactorThreads(ACE_Reactor::instance(), Configuration::instance()->getIOThreadPoolSize());

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

	setupQuitHandler(ACE_Reactor::instance());

#if defined(_WIN32)
	static auto processReactor = new ACE_Reactor(new ACE_WFMO_Reactor(), 1);
	m_threadPool.emplace_back(std::make_unique<std::thread>(
		[this]()
		{ runReactorEvent(processReactor); }));
#else
	static auto processReactor = ACE_Reactor::instance();
#endif

	Process_Manager::instance()->open(ACE_Process_Manager::DEFAULT_SIZE, processReactor);

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

	// reactor->owner(ACE_OS::thr_self());

	while (!QuitHandler::instance()->shouldExit() && !reactor->reactor_event_loop_done())
	{
		reactor->run_reactor_event_loop();
		if (QuitHandler::instance()->shouldExit())
		{
			break;
		}
		LOG_WAR << fname << "Reactor event loop interrupted, checking quit flag";
	}

	LOG_WAR << fname << "Reactor event thread exiting";
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
	ACE_INET_Addr tcpAddr(config->getRestTcpPort(), config->getRestListenAddress().c_str());
	const std::string homeDir = Utility::getHomeDir();
	const bool verifyClient = Configuration::instance()->getSslVerifyClient();
	const auto cert = ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCertificateFile());					 // Server certificate (PEM, include intermediates)
	const auto key = ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCertificateKeyFile());					 // Private key
	const auto ca = verifyClient ? ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCaPath()) : std::string(); // CA file or directory

	LOG_INF << fname << "Initializing TCP service on <" << tcpAddr.get_host_addr() << ":" << tcpAddr.get_port_number() << ">";

	// Initialize SSL for TCP server and client
	SSLHelper::initServerSSL(ACE_SSL_Context::instance(), cert, key, ca);

	const auto clientCA = ClientSSLConfig::ResolveAbsolutePath(homeDir, Configuration::instance()->getSSLCaPath());
	SSLHelper::initClientSSL(Global::getClientSSL(), "", "", "" /*clientCA*/);

	// Start REST thread pool
	startWorkerThreadPool();

	// Setup acceptor
	m_acceptor = std::make_unique<TcpAcceptor>();

	constexpr int FLAG_ACE_NONBLOCK = 1; // None-blocking mode
	constexpr int FLAG_SO_REUSEADDR = 1;
	if (m_acceptor->open(tcpAddr, ACE_Reactor::instance(), FLAG_ACE_NONBLOCK, 1, FLAG_SO_REUSEADDR) == -1)
	{
		throw std::runtime_error("Failed to listen on port " + std::to_string(config->getRestTcpPort()) + " with error: " + last_error_msg());
	}

	// Setup client connection
	m_client = std::make_shared<SocketStreamPtr>(new SocketStream(Global::getClientSSL()));
	if (m_client->stream()->connect(tcpAddr))
		LOG_INF << fname << "Test local TCP client connected successfully";
	else
		LOG_WAR << fname << "Test local TCP client connection failed";

	// Websocket service
	if (config->getWebSocketPort())
	{
		ACE_INET_Addr addr(config->getWebSocketPort(), config->getRestListenAddress().c_str());
#if defined(HAVE_UWEBSOCKETS)
		// 3 <IO> threads + shared <WORKER> threads
		int ioThreadNumber = Configuration::instance()->getIOThreadPoolSize();
		WebSocketAdaptor::instance()->initialize(addr, cert, key, ca, ioThreadNumber);
		WebSocketAdaptor::instance()->start();
#else
		// 1 <IO> thread + shared <WORKER> threads
		constexpr int workerThreadNumber = 0; // Use shared thread pool
		WebSocketService::instance()->initialize(addr, cert, key, ca);
		WebSocketService::instance()->start(workerThreadNumber);
#endif
		LOG_INF << fname << "Initializing Websocket service on <" << addr.get_host_addr() << ":" << addr.get_port_number() << ">";
	}

	startAgentApplication();
	config->registerPrometheus();

	LOG_INF << fname << "REST service initialized";
}

void AppMeshDaemon::startWorkerThreadPool()
{
	const static char fname[] = "AppMeshDaemon::startWorkerThreadPool() ";

	auto config = Configuration::instance();
	auto workerNum = config->getWorkerThreadPoolSize();

	WORKER::instance()->activate(THR_NEW_LWP | THR_JOINABLE, workerNum);

	LOG_INF << fname << "Started " << workerNum << " threads for REST thread pool";
}

void AppMeshDaemon::startAgentApplication()
{
	const static char fname[] = "AppMeshDaemon::startAgentApplication() ";

	auto config = Configuration::instance();

	if (!config->isAppExist(SEPARATE_AGENT_APP_NAME))
	{
		LOG_INF << fname << "Starting agent application";

		const auto shmName = HMACVerifierSingleton::instance()->writePSKToSHM();
		config->addApp(config->getAgentAppJson(shmName), nullptr, false)->execute();

		if (!shmName.empty() && !HMACVerifierSingleton::instance()->waitPSKRead())
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
	LOG_INF << fname << "Entered working directory: " << fs::current_path().string();

	int tcpErrorCounter = 0;
	LOG_INF << fname << "Entering main application monitoring loop";

	while (!QuitHandler::instance()->shouldExit())
	{
		try
		{
			executeApplications();

			std::this_thread::sleep_for(std::chrono::seconds(config->getScheduleInterval()));

			// Exit if TCP connection fails too many times
			if (config->getRestEnabled() && !checkTcpConnection(tcpErrorCounter))
				break;

			PersistManager::instance()->persistSnapshot();
			HealthCheckTask::instance()->doHealthCheck();
			spdlog::default_logger()->flush();

			// Update process tree for prometheus if needed
			if (config->prometheusEnabled() && RESTHANDLER::instance()->collected())
				m_ptree = os::processes();
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

	// m_client->stream()->shutdown();
	// m_client = std::make_shared<SocketStreamPtr>(new SocketStream(Global::getClientSSL()));
	// m_client->stream()->connect(ACE_INET_Addr(6059, "localhost"));
	if (m_client && m_client->stream() && !m_client->stream()->connected())
	{
		errorCounter++;
		LOG_WAR << fname << "REST TCP connection test failed, attempt <" << errorCounter << ">";

		if (errorCounter > MAX_TCP_ERROR_COUNT)
		{
			LOG_ERR << fname << "REST TCP connection test failed more than " << MAX_TCP_ERROR_COUNT << " times, requesting shutdown";
			QuitHandler::instance()->requestExit();
			return false;
		}

		std::this_thread::sleep_for(std::chrono::seconds(config->getScheduleInterval()));

		// Reconnect
		ACE_INET_Addr acceptorAddr(config->getRestTcpPort(), config->getRestListenAddress().c_str());
		if (m_client->stream()->connect(acceptorAddr))
			LOG_INF << fname << "Test local TCP client reconnected successfully";
		else
			LOG_WAR << fname << "Test local TCP client reconnection failed";
	}
	else
	{
		errorCounter = 0;
	}

	return true;
}

// TODO: health and dependency start
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

	QuitHandler::instance()->requestExit();

#if defined(HAVE_UWEBSOCKETS)
	WebSocketAdaptor::instance()->stop();
#else
	WebSocketService::instance()->stop();
#endif

	cleanWorkerThreads();
	cleanupResources();

	LOG_INF << fname << "AppMesh daemon exited";

	spdlog::shutdown();
	ACE_OS::_exit(0);
	ACE::fini();
}

void AppMeshDaemon::cleanWorkerThreads()
{
	const static char fname[] = "AppMeshDaemon::cleanWorkerThreads() ";

	WORKER::instance()->shutdown();
	WORKER::instance()->wait();
	LOG_INF << fname << "All threads joined";
}

void AppMeshDaemon::cleanupResources()
{
	const static char fname[] = "AppMeshDaemon::cleanupResources() ";

	try
	{
		Utility::removeFile((fs::path(Utility::getHomeDir()) / PID_FILE).string());
		LOG_INF << fname << "Resources cleaned up";
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "Error during cleanup: " << ex.what();
	}
}
