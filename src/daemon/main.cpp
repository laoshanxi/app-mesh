// src/daemon/main.cpp
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <exception>
#include <iostream>
#include <list>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <spdlog/spdlog.h>
#include <trantor/net/InetAddress.h>
#if defined(_WIN32)
#include <process.h> // for _exit()
#include <winsock2.h>
#else
#include <sys/resource.h>
#include <unistd.h> // for _exit()
#endif

#include "../common/QuitHandler.h"
#include "../common/RestClient.h"
#include "../common/TimerHandler.h"
#include "../common/Utility.h"
#include "../common/json.h"
#include "../common/os/chown.h"
#include "../common/os/proc.h"
#include "../common/os/pstree.h"
#include "Configuration.h"
#include "application/HealthCheckTask.h"
#include "security/AuthorizationStore.h"
#include "PersistManager.h"
#include "ResourceCollection.h"
#include "application/Application.h"
#include "process/AppProcess.h"
#include "process/DockerApiProcess.h"
#include "process/LinuxCgroup.h"
#include "process/ProcessService.h"
#include "rest/EventDispatcher.h"
#include "rest/RestHandler.h"
#include "rest/Worker.h"
#include "rest/drogon/Adaptor.h"
#include "rest/tcp/TcpAdaptor.h"
#include "security/AuthReplicator.h"
#include "security/Security.h"
#if !defined(NDEBUG) && !defined(_WIN32)
#include "../common/Valgrind.h"
#endif

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
	void initializeResourceLimits();
	void initializeServices();
	void initializeLogging();
	void logStartupEnvironment();
	void initializeConfiguration();
	void initializeSecurity();
	void initializeDirectories();
	void setupSignalHandlers();
	void recoverApplications();

	// REST service management
	void initializeRestService();
	void startWorkerThreadPool();
	void startAgentApplication();
	void startStartupApplications();
	void prewarmAuthentication();
	void refreshAuthenticationCache();

	// High availability
	void performHighAvailabilityRecovery();

	// Main loop
	void runMainLoop();
	void executeApplications();

	// Shutdown
	/// Terminal shutdown (skips atexit); `exitCode` must reach the watchdog.
	void performShutdown(int exitCode = 0);
	void stopManagedApplications();
	void cleanWorkerThreads();
	void cleanupResources();

private:
	// trantor and drogon call exit(1) on bind failure, which skips performShutdown().
	static void verifyListenerAddress(const trantor::InetAddress &addr, const std::string &service);

	std::vector<std::unique_ptr<std::thread>> m_threadPool;
	std::list<os::Process> m_ptree;
	bool m_ptreeReady = false;
	bool m_ptreeRefreshPending = false;
	uint64_t m_lastPrometheusScrape = 0;
};

// Global daemon instance
static std::unique_ptr<AppMeshDaemon> g_daemon;

int main(int argc, char *argv[])
{
	const static char fname[] = "main() ";

	// First use on the main thread: a signal arriving before setup would
	// otherwise run this static initialization inside the signal handler.
	QuitHandler::instance();

	PRINT_VERSION();
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

// Startup visibility: the locale variables decide how child applications encode their output.
void AppMeshDaemon::logStartupEnvironment()
{
	const static char fname[] = "AppMeshDaemon::logStartupEnvironment() ";
	LOG_INF << fname << "LANG=<" << (Utility::getenv("LANG")) << "> LC_ALL=<" << (Utility::getenv("LC_ALL"))
			<< "> APPMESH_AUTH_MODE=<" << (Utility::getenv(AUTH_MODE_ENV)) << ">";
}

int AppMeshDaemon::run(int argc, char *argv[])
{
	const static char fname[] = "AppMeshDaemon::run() ";
	int result = 0;

	try
	{
		initializeLogging();
		LOG_INF << fname << "App Mesh server starting.";
		logStartupEnvironment();
		initializeEnvironment();
		initializeResourceLimits();
		initializeConfiguration();
		LinuxCgroup::initializeApplicationCgroups();
		initializeServices();
		initializeSecurity();
		initializeDirectories();
		setupSignalHandlers();
		recoverApplications();

		performHighAvailabilityRecovery();
		startStartupApplications();
		prewarmAuthentication();
		initializeRestService();
		// Listeners verified: only a process that can serve pulls the owner
		// policy, so a bind-failed generation never writes the replica cache.
		AuthReplicator::instance().start();
#if !defined(_WIN32)
		// Reconcile App Mesh labeled containers against the restored registry:
		// leftovers of removed applications are logged (and deleted with
		// APPMESH_DOCKER_ORPHAN_SWEEP=delete).
		DockerApiProcess::sweepOrphanContainers();
#endif
		runMainLoop();
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "Fatal exception during daemon startup or execution: " << e.what();
		result = 1;
	}
	catch (...)
	{
		LOG_ERR << fname << "Fatal unknown exception during daemon startup or execution";
		result = 1;
	}

	performShutdown(result);
	return result;
}

void AppMeshDaemon::initializeEnvironment()
{
	const static char fname[] = "AppMeshDaemon::initializeEnvironment() ";
#if defined(_WIN32)
	// Winsock must be up before any socket call (logging, pid file, listeners).
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		std::cerr << "WSAStartup failed" << std::endl;
	}
#endif
	fs::current_path(Utility::getHomeDir());
	LOG_INF << fname << "Entered working directory: " << fs::current_path().string();
	// The pid lock is the single-instance guarantee; createPidFile() printed the specific cause.
	if (!Utility::createPidFile())
	{
		throw std::runtime_error("cannot acquire the PID file lock: another appmesh daemon instance is running for "
								 "this installation, or the PID file is not writable (see the message above)");
	}
	Utility::ensureSystemRoot();
}

void AppMeshDaemon::initializeResourceLimits()
{
#if !defined(_WIN32)
	const static char fname[] = "AppMeshDaemon::initializeResourceLimits() ";
	// Launch services start daemons with a low soft fd limit (macOS: 256), while
	// every concurrent run opens an output file, a stdin handle and a stdout
	// pipe. Raise the soft limit to the hard cap before any listener or app runs.
	struct rlimit limits;
	if (::getrlimit(RLIMIT_NOFILE, &limits) == 0 && limits.rlim_cur < limits.rlim_max)
	{
		const rlim_t previous = limits.rlim_cur;
		limits.rlim_cur = limits.rlim_max;
		if (::setrlimit(RLIMIT_NOFILE, &limits) == 0)
			LOG_INF << fname << "RLIMIT_NOFILE raised from " << previous << " to " << limits.rlim_max;
	}
#endif
}

void AppMeshDaemon::initializeServices()
{
	const static char fname[] = "AppMeshDaemon::initializeServices() ";

	// Construct singletons on the main thread before workers can race their
	// first use. TimerManager and ProcessService start their own io threads.
	TIMER_MANAGER::instance();
	ProcessService::instance();
	EventDispatcher::instance();
	QuitHandler::instance();
	WORKER::instance();
	RESTHANDLER::instance();

	LOG_INF << fname << "Service singletons initialized";
}

void AppMeshDaemon::initializeLogging()
{
	const static char fname[] = "AppMeshDaemon::initializeLogging() ";

	fs::create_directories(fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR);
	Utility::initLogging("server");

	LOG_INF << fname << "Build: " << __MICRO_VAR__(BUILD_TAG);
}

void AppMeshDaemon::initializeConfiguration()
{
	const static char fname[] = "AppMeshDaemon::initializeConfiguration() ";

	Configuration::handleSignal();

	LOG_INF << fname << "Initializing host resource collection";
	const auto hostResources = ResourceCollection::instance()->getHostResource();
	ResourceCollection::instance()->dump(hostResources);

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

	Security::init();
	// The replication worker starts only after the listeners verified bind (see
	// run()): a process that cannot serve must not pull, apply or persist.

	LOG_INF << fname << "Security initialized";
}

// One-shot upgrade from the pre-split layout (work/{tmp,stdout,stdin,shell}).
// The throwing renames abort startup: dropping user data silently is worse.
static void migrateLegacyDirectories(const std::string &workDir, const std::string &runtimeDir,
									 const std::string &stdoutDir, const std::string &shareDir)
{
	const static char fname[] = "migrateLegacyDirectories() ";
	const auto moveEntry = [](const fs::path &from, const fs::path &to) {
		std::error_code ec;
		if (!fs::exists(from, ec))
			return;
		// Win32 rename cannot replace a directory; drop the freshly created
		// empty target so both platforms take the same path.
		if (fs::is_directory(to, ec) && fs::is_empty(to, ec))
			fs::remove_all(to, ec);
		fs::rename(from, to);
		LOG_INF << fname << "Migrated <" << from.string() << "> to <" << to.string() << ">";
	};

	const fs::path legacyTmp = fs::path(workDir) / "tmp";
	if (fs::exists(legacyTmp))
	{
		// Daemon-private residue moves under runtime/; the rest is app data for share/.
		moveEntry(legacyTmp / APPMESH_WORK_UPLOAD_DIR, fs::path(runtimeDir) / APPMESH_WORK_UPLOAD_DIR);
		moveEntry(legacyTmp / SNAPSHOT_FILE_NAME, fs::path(runtimeDir) / SNAPSHOT_FILE_NAME);
		// rename keeps the legacy modes; re-pin the daemon-private ones.
		std::error_code permsEc;
		fs::permissions(fs::path(runtimeDir) / APPMESH_WORK_UPLOAD_DIR, fs::perms::owner_all, permsEc);
		fs::permissions(fs::path(runtimeDir) / SNAPSHOT_FILE_NAME,
						fs::perms::owner_read | fs::perms::owner_write, permsEc);
		for (const auto &entry : fs::directory_iterator(legacyTmp))
			moveEntry(entry.path(), fs::path(shareDir) / entry.path().filename());
		fs::remove(legacyTmp); // fails loudly on anything left behind
	}

	// Stdout history is kept; a same-named file (only possible on a re-run) keeps both.
	const fs::path legacyStdout = fs::path(workDir) / "stdout";
	std::error_code ec;
	if (fs::exists(legacyStdout, ec))
	{
		for (const auto &entry : fs::directory_iterator(legacyStdout))
		{
			auto target = fs::path(stdoutDir) / entry.path().filename();
			if (fs::exists(target, ec))
				target = fs::path(stdoutDir) / (entry.path().filename().string() + ".legacy");
			fs::rename(entry.path(), target);
			LOG_INF << fname << "Migrated <" << entry.path().string() << "> to <" << target.string() << ">";
		}
		fs::remove(legacyStdout);
	}

	// Transient residue: stdin temp files, scripts rebuilt every startup.
	Utility::removeDir((fs::path(workDir) / "stdin").string());
	Utility::removeDir((fs::path(workDir) / "shell").string());
}

void AppMeshDaemon::initializeDirectories()
{
	const static char fname[] = "AppMeshDaemon::initializeDirectories() ";

	auto config = Configuration::instance();

	// Create working directories. runtime/ holds daemon-private state, share/
	// is a sticky world-writable exchange area, workspaces/ the sandbox root.
	Utility::createDirectory(config->getWorkDir());
	// Execution users must reach runtime/, share/ and workspaces/ below it, whatever
	// mode an installer or a container entrypoint left on the directory.
	std::error_code workPermsEc;
	const fs::path workDirPath(config->getWorkDir());
	const auto workDirStatus = fs::status(workDirPath, workPermsEc);
	if (!workPermsEc)
	{
		fs::permissions(workDirPath, workDirStatus.permissions() | fs::perms::group_exec | fs::perms::others_exec,
						workPermsEc);
	}

	const auto runtimeDir = config->getRuntimeDir();
	const auto stdoutDir = (fs::path(runtimeDir) / "stdout").string();
	const auto stdinDir = (fs::path(runtimeDir) / "stdin").string();
	const auto shellDir = (fs::path(runtimeDir) / "shell").string();
	const auto uploadDir = (fs::path(runtimeDir) / APPMESH_WORK_UPLOAD_DIR).string();
	const auto shareDir = config->getWorkShareDir();
	const auto workspacesDir = (fs::path(config->getWorkDir()) / APPMESH_WORKSPACES_DIR).string();

	// Stale scripts from an unclean shutdown must not block script names, and
	// stale launch stdin files have no reader left.
	Utility::removeDir(shellDir);
	Utility::removeDir(stdinDir);

	// No chown to the default exec user: runtime/ stays daemon-private and
	// share/'s sticky-bit owner must stay the daemon user.
	const fs::perms traverseOnly = fs::perms::owner_all | fs::perms::group_exec | fs::perms::others_exec;
	Utility::createDirectory(runtimeDir, traverseOnly);
	Utility::createDirectory(stdoutDir, fs::perms::owner_all);
	Utility::createDirectory(stdinDir, fs::perms::owner_all);
	// Scripts are per-file chowned to the exec user; others only traverse.
	Utility::createDirectory(shellDir, traverseOnly);
	Utility::createDirectory(uploadDir, fs::perms::owner_all);
	Utility::createDirectory(shareDir,
							  fs::perms::owner_all | fs::perms::group_all | fs::perms::others_all | fs::perms::sticky_bit);
	// createDirectory only chmods on first create; re-apply in case the agent
	// pre-created share/ with a private mode before the daemon ever ran.
	std::error_code sharePermsEc;
	fs::permissions(fs::path(shareDir),
					 fs::perms::owner_all | fs::perms::group_all | fs::perms::others_all | fs::perms::sticky_bit, sharePermsEc);
	Utility::createDirectory(workspacesDir, traverseOnly);
	fs::permissions(fs::path(workspacesDir), traverseOnly, sharePermsEc);

	migrateLegacyDirectories(config->getWorkDir(), runtimeDir, stdoutDir, shareDir);

	LOG_INF << fname << "Directories initialized";
}

void AppMeshDaemon::setupSignalHandlers()
{
	const static char fname[] = "AppMeshDaemon::setupSignalHandlers() ";

	setupQuitHandler();

	LOG_INF << fname << "Signal handlers configured";
}

void AppMeshDaemon::recoverApplications()
{
	const static char fname[] = "AppMeshDaemon::recoverApplications() ";

	LOG_INF << fname << "Starting application recovery process";

	auto config = Configuration::instance();
	// Persisted definitions first: a registered app must keep winning over its
	// pre-loaded twin after a restart.
	config->loadApps(fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_APPLICATION_DIR);
	config->loadApps(fs::path(Utility::getHomeDir()) / APPMESH_APPLICATION_DIR);
	// Validate the dependency graph once after both directories are loaded.
	config->validateRecoveredDependencies();

	LOG_INF << fname << "Applications recovered";
}

void AppMeshDaemon::verifyListenerAddress(const trantor::InetAddress &addr, const std::string &service)
{
	const static char fname[] = "AppMeshDaemon::verifyListenerAddress() ";

#if defined(_WIN32)
	const SOCKET probe = ::socket(addr.family(), SOCK_STREAM, 0);
	const bool invalidProbe = probe == INVALID_SOCKET;
#else
	const int probe = ::socket(addr.family(), SOCK_STREAM, 0);
	const bool invalidProbe = probe < 0;
#endif
	if (invalidProbe)
	{
		LOG_WAR << fname << "Cannot create a socket to verify the " << service << " address: " << last_error_msg();
		return;
	}

	// Same option as the listeners before bind, so a TIME_WAIT socket is not a conflict.
	const int reuse = 1;
	::setsockopt(probe, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuse), sizeof(reuse));
	// InetAddress stores a sockaddr_in6 internally; bind wants the exact family size.
	const socklen_t addrLen = addr.isIpV6() ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
	const int bindResult = ::bind(probe, addr.getSockAddr(), addrLen);
	const std::string bindError = last_error_msg();
#if defined(_WIN32)
	::closesocket(probe);
#else
	::close(probe);
#endif

	if (bindResult != 0)
	{
		const std::string endpoint = addr.toIp() + ":" + std::to_string(addr.toPort());
		LOG_ERR << fname << "Cannot bind the " << service << " address <" << endpoint << ">: " << bindError;
		throw std::runtime_error("Cannot listen on " + endpoint + " for the " + service + " service: " + bindError);
	}
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
	// TLS-at-gateway shape: an upstream LB/gateway/sidecar terminates TLS and
	// forwards plaintext on a trusted network. Plaintext is always explicit.
	const bool sslEnabled = config->getSslEnabled();
	if (!sslEnabled)
	{
		LOG_WAR << fname << "SSL is disabled: the REST, WebSocket and TCP listeners accept PLAINTEXT. This is only "
						 "for deployments where TLS terminates at an upstream gateway on a trusted network; keep "
						 "the listeners bound to a private interface.";
	}
	const std::string homeDir = Utility::getHomeDir();
	const bool verifyClient = sslEnabled && Configuration::instance()->getSslVerifyClient();
	const auto cert = sslEnabled ? ClientSSLConfig::resolveAbsolutePath(
									   homeDir, Configuration::instance()->getSSLCertificateFile()) // Server certificate (PEM, include intermediates)
								 : std::string();
	const auto key = sslEnabled ? ClientSSLConfig::resolveAbsolutePath(
										  homeDir, Configuration::instance()->getSSLCertificateKeyFile()) // Private key
								: std::string();
	const auto ca = verifyClient ? ClientSSLConfig::resolveAbsolutePath(homeDir, Configuration::instance()->getSSLCaPath())
								 : std::string(); // CA file or directory

	// Start REST thread pool
	startWorkerThreadPool();

	// drogon and the TCP transport accept numeric addresses only, and the bind
	// probe below must check the same address the listeners will use.
	std::string resolveError;
	const std::string listenIp = Utility::resolveHostAddress(config->getRestListenAddress(), resolveError);
	if (listenIp.empty())
	{
		throw std::runtime_error("Cannot resolve listen address <" + config->getRestListenAddress() + ">: " + resolveError);
	}
	const bool listenV6 = listenIp.find(':') != std::string::npos;

	// TLS TCP service (length-prefixed msgpack frames, same request pipeline
	// as the WebSocket transport); port 0 disables the listener
	if (config->getTcpApiPort())
	{
		const trantor::InetAddress tcpAddr(listenIp, static_cast<uint16_t>(config->getTcpApiPort()), listenV6);
		verifyListenerAddress(tcpAddr, "TCP");
		TcpAdaptor::instance()->initialize(listenIp, config->getTcpApiPort(), cert, key, ca, sslEnabled,
										   static_cast<int>(Configuration::instance()->getTransportIoThreads()));
		TcpAdaptor::instance()->start();
		LOG_INF << fname << "TCP service initialized on <" << tcpAddr.toIp() << ":" << tcpAddr.toPort() << ">";
	}

	// Websocket service
	if (config->getWebSocketPort())
	{
		const trantor::InetAddress wsAddr(listenIp, static_cast<uint16_t>(config->getWebSocketPort()), listenV6);
		verifyListenerAddress(wsAddr, "WebSocket");
		// <IO> threads per transport + shared <WORKER> threads
		int ioThreadNumber = static_cast<int>(Configuration::instance()->getTransportIoThreads());
		DrogonAdaptor::instance()->initialize(listenIp, config->getWebSocketPort(), cert, key, ca, sslEnabled,
											  ioThreadNumber);
		DrogonAdaptor::instance()->start();
		LOG_INF << fname << "WebSocket service initialized on <" << wsAddr.toIp() << ":" << wsAddr.toPort() << ">";
	}

	startAgentApplication();
	config->registerPrometheus();

	LOG_INF << fname << "REST service initialized";
}

void AppMeshDaemon::startWorkerThreadPool()
{
	const static char fname[] = "AppMeshDaemon::startWorkerThreadPool() ";

	auto config = Configuration::instance();
	auto workerNum = config->getWorkerThreads();

	WORKER::instance()->start(workerNum);

	LOG_INF << fname << "Started " << workerNum << " threads for REST thread pool";
}

void AppMeshDaemon::startAgentApplication()
{
	const static char fname[] = "AppMeshDaemon::startAgentApplication() ";

	auto config = Configuration::instance();

	if (!config->isAppExist(SEPARATE_AGENT_APP_NAME))
	{
		LOG_INF << fname << "Starting agent application";

		// startRun hands the agent its pre-shared key through shared memory;
		// block until the agent has read it so startup fails fast on a broken handshake.
		const auto agent = config->addApp(config->getAgentAppJson(), false);
		agent->execute();
		if (!agent->waitProcessProofRead())
		{
			throw std::runtime_error("Failed to wait for PSK read from agent process");
		}
	}
#if !defined(_WIN32)
	// Docker applications dial back through the agent's docker proxy; surface a
	// broken channel at boot instead of the first container start's 407. Runs
	// for a freshly created agent and for one restored from the registry alike.
	DockerApiProcess::selfCheckDockerAgent();
#endif
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
		if (!Utility::isFileExist(Snapshot::filePath()))
		{
			LOG_INF << fname << "No snapshot file, starting with an empty snapshot";
		}
		else
		{
			auto snapfile = Utility::readFileCpp(Snapshot::filePath());
			auto jsonData = snapfile.empty() ? std::string("{}") : std::move(snapfile);
			snap = Snapshot::FromJson(JSON::parse(jsonData));
			LOG_INF << fname << "Successfully loaded snapshot file";
		}
	}
	catch (const std::exception &ex)
	{
		LOG_ERR << fname << "Failed to recover from snapshot: " << ex.what();
		snap = std::make_shared<Snapshot>();
	}

	// Recover application processes
	LOG_INF << fname << "Recovering application processes";
	auto apps = config->getApps();

	for (const auto &app : apps)
	{
		if (snap && snap->m_apps.count(app->getName()))
		{
			const auto &appSnapshot = snap->m_apps.find(app->getName())->second;
			auto stat = os::status(appSnapshot.m_pid);

			if (stat && appSnapshot.m_startTime == std::chrono::system_clock::to_time_t(stat->getStartTime()))
			{
				LOG_INF << fname << "Attaching application <" << app->getName() << "> to existing process PID <"
						<< appSnapshot.m_pid << ">";
				app->attach(appSnapshot.m_pid);
			}
		}
	}

	LOG_INF << fname << "High availability recovery completed";
}

void AppMeshDaemon::runMainLoop()
{
	const static char fname[] = "AppMeshDaemon::runMainLoop() ";

	// The runtime directory is the daemon's working directory.
	auto config = Configuration::instance();
	fs::current_path(config->getRuntimeDir());
	LOG_INF << fname << "Entered working directory: " << fs::current_path().string();

	// Health checks run on a resident worker that sleeps a fixed time between
	// rounds; each check spawns a process and must stay off this loop.
	HealthCheckTask::instance()->start();
	// JWKS refresh every 1800 ticks (~30 min): half the cache TTL, off the request threads.
	int authRefreshTick = 0;
	LOG_INF << fname << "Entering main application monitoring loop";

	while (!QuitHandler::instance()->shouldExit())
	{
		try
		{
			executeApplications();

			// Interruptible: an exit request wakes this immediately instead of
			// waiting out the schedule interval.
			if (QuitHandler::instance()->waitForExit(std::chrono::seconds(config->getScheduleInterval())))
				break;

			// Deferred from the signal handler: the reload must run off it.
			Configuration::reloadOnSignal();

			PersistManager::instance()->persistSnapshot();
			if (authRefreshTick++ % 1800 == 0)
				refreshAuthenticationCache();

			// Refresh all process metrics once per completed scrape.
			if (config->prometheusEnabled())
			{
				const auto scrapeGeneration = RESTHANDLER::instance()->prometheusScrapeGeneration();
				if (scrapeGeneration != m_lastPrometheusScrape)
				{
					std::vector<pid_t> roots = {os::getpid()};
					for (const auto &app : Configuration::instance()->getApps())
					{
						const auto pid = app->getpid();
						if (pid > 1)
							roots.push_back(pid);
					}
					m_ptree = os::processes(roots);
					m_ptreeReady = !m_ptree.empty();
					m_ptreeRefreshPending = true;
					RESTHANDLER::instance()->refreshPrometheusProcessMetrics(m_ptreeReady ? static_cast<void *>(&m_ptree)
																						  : nullptr);
					m_lastPrometheusScrape = scrapeGeneration;
				}
				else
				{
					m_ptreeReady = false;
					m_ptreeRefreshPending = false;
				}
			}
			else
			{
				m_ptreeReady = false;
				m_ptreeRefreshPending = false;
			}
		}
		catch (const std::exception &ex)
		{
			LOG_ERR << fname << "Exception in main loop: " << ex.what();
		}
	}

	LOG_INF << fname << "Exiting main monitoring loop";
}

void AppMeshDaemon::startStartupApplications()
{
	const static char fname[] = "AppMeshDaemon::startStartupApplications() ";
	const auto startupTimeout = std::chrono::seconds(120);
	const auto retryInterval = std::chrono::seconds(1);

	auto config = Configuration::instance();
	// Managed app commands use ../../script-style paths; runtime/ sits two
	// levels below the install root. Match the main scheduler's cwd.
	fs::current_path(config->getRuntimeDir());
	LOG_INF << fname << "Entered working directory: " << fs::current_path().string();

	auto apps = config->getApps();
	std::stable_sort(apps.begin(), apps.end(),
					 [](const std::shared_ptr<Application> &left, const std::shared_ptr<Application> &right)
					 {
						 if (left->startupPhase() != right->startupPhase())
							 return left->startupPhase() < right->startupPhase();
						 return left->getName() < right->getName();
					 });

	std::vector<int> startupPhases;
	for (const auto &app : apps)
	{
		if (!app || !app->isManaged() || !app->isEnabled() || app->startupPhase() >= Application::DEFAULT_STARTUP_PHASE)
			continue;
		if (startupPhases.empty() || startupPhases.back() != app->startupPhase())
			startupPhases.push_back(app->startupPhase());
	}

	for (const int phase : startupPhases)
	{
		LOG_INF << fname << "Starting readiness phase <" << phase << ">";
		const auto deadline = std::chrono::steady_clock::now() + startupTimeout;
		while (!QuitHandler::instance()->shouldExit())
		{
			for (const auto &app : apps)
			{
				if (!app || !app->isManaged() || app->startupPhase() > phase)
					continue;
				try
				{
					app->execute(nullptr, false);
				}
				catch (const std::exception &ex)
				{
					LOG_ERR << fname << "Startup application <" << app->getName() << "> execute failed: " << ex.what();
				}
			}

			HealthCheckTask::instance()->doHealthCheck();
			bool ready = true;
			std::string pending;
			for (const auto &app : apps)
			{
				if (!app || !app->isManaged() || !app->isEnabled() || app->startupPhase() > phase)
					continue;
				if (app->getpid() <= 1 || app->health() != 0)
				{
					ready = false;
					if (!pending.empty())
						pending += ", ";
					pending += app->getName();
				}
			}
			if (ready)
			{
				LOG_INF << fname << "Readiness phase <" << phase << "> completed";
				break;
			}
			if (std::chrono::steady_clock::now() >= deadline)
				throw std::runtime_error("startup readiness timed out for applications: " + pending);
			std::this_thread::sleep_for(retryInterval);
		}
		if (QuitHandler::instance()->shouldExit())
			throw std::runtime_error("shutdown requested during startup readiness");
	}
}

void AppMeshDaemon::prewarmAuthentication()
{
	const static char fname[] = "AppMeshDaemon::prewarmAuthentication() ";
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(120);
	std::string lastError;
	while (!QuitHandler::instance()->shouldExit())
	{
		try
		{
			Security::instance()->prewarmAuthentication();
			LOG_INF << fname << "OIDC discovery and JWKS are ready";
			return;
		}
		catch (const std::exception &ex)
		{
			lastError = ex.what();
			if (std::chrono::steady_clock::now() >= deadline)
				break;
			LOG_WAR << fname << "OIDC discovery/JWKS not ready: " << lastError;
			std::this_thread::sleep_for(std::chrono::seconds(1));
		}
	}
	throw std::runtime_error("OIDC discovery/JWKS readiness failed: " + lastError);
}

void AppMeshDaemon::refreshAuthenticationCache()
{
	const static char fname[] = "AppMeshDaemon::refreshAuthenticationCache() ";

	try
	{
		Security::instance()->prewarmAuthentication();
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "JWKS refresh failed: " << ex.what();
	}
}

void AppMeshDaemon::executeApplications()
{
	const static char fname[] = "AppMeshDaemon::executeApplications() ";

	auto config = Configuration::instance();
	auto allApps = config->getApps();
	std::stable_sort(allApps.begin(), allApps.end(),
					 [](const std::shared_ptr<Application> &left, const std::shared_ptr<Application> &right)
					 {
						 if (left->startupPhase() != right->startupPhase())
							 return left->startupPhase() < right->startupPhase();
						 return left->getName() < right->getName();
					 });
	void *const processSnapshot = m_ptreeReady ? static_cast<void *>(&m_ptree) : nullptr;
	m_ptreeReady = false;
	const bool refreshMetrics = m_ptreeRefreshPending;
	m_ptreeRefreshPending = false;

	for (const auto &app : allApps)
	{
		if (!app->isManaged())
		{
			continue;
		}
		try
		{
			app->execute(processSnapshot, refreshMetrics);
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

void AppMeshDaemon::performShutdown(int exitCode)
{
	const static char fname[] = "AppMeshDaemon::performShutdown() ";

	LOG_INF << fname << "Beginning shutdown sequence";

	QuitHandler::instance()->requestExit();
	// A startup failure before Configuration::instance() is set has no application list.
	if (Configuration::instance())
		stopManagedApplications();
	else
		LOG_WAR << fname << "Configuration is not initialized, skipping application shutdown";
	// Exit finalization ran on the ProcessService thread while the apps
	// stopped; it can be shut down before the workers drain.
	ProcessService::instance()->shutdown();

	// Drain the workers before the transports: a queued reply still holds a
	// connection whose event loop must stay alive until the reply is sent.
	cleanWorkerThreads();

	TcpAdaptor::instance()->stop();
	DrogonAdaptor::instance()->stop();

	cleanupResources();

	LOG_INF << fname << "AppMesh daemon exited";

	spdlog::shutdown();
	// Terminal exit: skip atexit and static destructors on purpose.
	_exit(exitCode);
}

void AppMeshDaemon::stopManagedApplications()
{
	const static char fname[] = "AppMeshDaemon::stopManagedApplications() ";

	auto apps = Configuration::instance()->getApps();
	std::stable_sort(apps.begin(), apps.end(),
					 [](const std::shared_ptr<Application> &left, const std::shared_ptr<Application> &right)
					 {
						 if (left->startupPhase() != right->startupPhase())
							 return left->startupPhase() > right->startupPhase();
						 return left->getName() > right->getName();
					 });
	for (const auto &app : apps)
	{
		if (!app || !app->isManaged())
			continue;
		try
		{
			// destroy() is intentionally non-persistent here: package removal and
			// ordinary service restarts must not rewrite each App's enabled state.
			app->destroy();
			LOG_INF << fname << "Stopped application <" << app->getName() << ">";
		}
		catch (const std::exception &ex)
		{
			LOG_WAR << fname << "Failed to stop application <" << app->getName() << ">: " << ex.what();
		}
		catch (...)
		{
			LOG_WAR << fname << "Failed to stop application <" << app->getName() << ">";
		}
	}
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
		// Only the lock owner may remove the PID file; a failed second instance shares the path.
		if (Utility::ownsPidFileLock())
			Utility::removeFile((fs::path(Utility::getHomeDir()) / PID_FILE).string());
		LOG_INF << fname << "Resources cleaned up";
	}
	catch (const std::exception &ex)
	{
		LOG_WAR << fname << "Error during cleanup: " << ex.what();
	}
}
