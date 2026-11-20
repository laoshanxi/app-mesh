// src/daemon/Configuration.h
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <boost/unordered/concurrent_flat_map.hpp>
#include <filesystem>
#include <json/json.h>

class RestHandler;
class AuthorizationStore;
class Label;
class Application;

/// <summary>
/// Configuration file <config.yaml> parse/update
/// </summary>
struct JsonDocker
{
	// off | audit | enforce; anything else keeps off so a typo cannot weaken it.
	std::string m_hostSecurityPolicy = "off";
	static std::shared_ptr<JsonDocker> FromJson(const Json::Value &jsonValue);
	Json::Value AsJson() const;
};

class Configuration
{
public:
	struct BaseConfig
	{
		BaseConfig();
		static std::shared_ptr<BaseConfig> FromJson(const Json::Value &jsonObj);
		Json::Value AsJson() const;

		std::string m_defaultExecUser;
		std::string m_defaultWorkDir;
		int m_scheduleInterval;
		bool m_disableExecUser;
		std::string m_logLevel;
		std::string m_posixTimezone;
	};
	struct JsonSsl
	{
		static std::shared_ptr<JsonSsl> FromJson(const Json::Value &jsonObj);
		Json::Value AsJson() const;
		// False = plaintext listeners (TLS terminates at an upstream gateway).
		bool m_sslEnabled;
		bool m_sslVerifyServer;
		bool m_sslVerifyClient;
		std::string m_certFile;
		std::string m_certKeyFile;
		std::string m_clientCertFile;
		std::string m_clientCertKeyFile;
		std::string m_sslCaPath;
		JsonSsl();
	};

	struct JsonRest
	{
		JsonRest();
		static std::shared_ptr<JsonRest> FromJson(const Json::Value &jsonObj);
		Json::Value AsJson() const;

		bool m_restEnabled;
		bool m_corsDisabled;
		// Metrics endpoints require bearer auth + config-view; false is an escape
		// hatch for a trusted-network Prometheus scraper (exposes host internals).
		bool m_metricsRequireAuth;
		// CORS: Origins echoed in Access-Control-Allow-Origin. Empty (default)
		// sends no CORS headers at all — the UI is a same-origin proxy.
		std::set<std::string> m_corsAllowOrigins;
		std::set<std::string> m_csrfAllowedOrigins; // CSRF: Origins allowed for cookie-auth state-changing requests
		// Request hardening: nonce replay protection and HMAC request signature,
		// each one of off | audit | enforce; window bounds both the nonce memory
		// and the accepted X-Timestamp skew (10..3600s).
		std::string m_requestReplayProtection;
		std::string m_requestSignature;
		int m_requestReplayWindowSeconds;
		std::string m_fileAllowedBaseDir;
		int m_workerThreads;      // 0 = derive from the CPUs the daemon may use
		int m_transportIoThreads; // 0 = derive from the CPUs the daemon may use
		int m_restListenPort;
		int m_promListenPort;
		std::string m_restListenAddress;
		int m_tcpApiPort;
		int m_webSocketPort;
		std::shared_ptr<JsonSsl> m_ssl;
	};

	Configuration();
	virtual ~Configuration();

	static std::shared_ptr<Configuration> instance();
	static void instance(std::shared_ptr<Configuration> config);
	static std::string readConfiguration();
	static void handleSignal();

	static std::shared_ptr<Configuration> FromJson(Json::Value &jsonValue, bool applyEnv = false) noexcept(false);
	Json::Value AsJson();
	void loadApps(const std::filesystem::path &appDir);
	void saveConfigToDisk();
	void hotUpdateAndSave(Json::Value &config);
	void hotUpdate(Json::Value &config);
	static bool overrideConfigWithEnv(Json::Value &jsonConfig);
	static bool applyEnvConfig(Json::Value &jsonValue, std::string envValue);
	void registerPrometheus();
	bool prometheusEnabled() const;

	std::vector<std::shared_ptr<Application>> getApps() const;
	/// Registers or replaces an application. With enforceRegistration, returns
	/// nullptr on a stale add (registered app != expectedRegistration); slow
	/// replacement and start-up run outside the mutation lock.
	std::shared_ptr<Application> addApp(const Json::Value &jsonApp, bool persistable = true,
										const std::shared_ptr<Application> &expectedRegistration = {},
										bool enforceRegistration = false);
	/// Removes an application. Returns false when `expected` no longer matches
	/// the registered application (stale remove). The map update is atomic;
	/// process destruction and persistence run outside the mutation lock.
	bool removeApp(const std::string &appName, const Application *expected = nullptr);
	std::shared_ptr<Application> parseApp(const Json::Value &jsonApp);
	/// Existing name matching `appName` case-insensitively but not exactly, or empty.
	std::string caseInsensitiveNameConflict(const std::string &appName) const;
	/// Registers a parsed application from app recovery without REST-path
	/// validation (see validateRecoveredDependencies). Takes the app mutation lock.
	void registerRecoveredApp(const std::shared_ptr<Application> &app);
	/// Rejects non-converging depends_on: on-demand or recurring apps, unknown
	/// names, cycles.
	void validateDependencies(const std::shared_ptr<Application> &app, bool persistable) const noexcept(false);
	/// Graph-wide depends_on validation of recovered apps; call once after all
	/// loadApps calls. Cycles refuse partial recovery, dangling names only warn.
	void validateRecoveredDependencies() const noexcept(false);

	int getScheduleInterval();
	int getRestListenPort();
	// Docker.HostSecurityPolicy: off (default) | audit | enforce, hot-reloaded.
	std::string getDockerHostSecurityPolicy();
	int getPromListenPort() const;
	std::string getRestListenAddress();
	int getTcpApiPort();
	int getWebSocketPort();
	Json::Value serializeApplication(bool returnRuntimeInfo, const std::string &user, bool returnUnPersistApp) const;
	std::shared_ptr<Application> getApp(const std::string &appName, bool throwOnNotFound = true) const noexcept(false);
	std::shared_ptr<Application> getApp(const void *app) const;
	bool isAppExist(const std::string &appName);
	std::string generateRunAppName(const std::string &provideAppName);
	/// Stops and removes the on-demand run instances spawned from `baseName`
	/// (their `<base>_N` registrations). Used by base-app delete; the delete
	/// permission check on the base governs the cascade. Returns the removal
	/// count, or -1 when instances kept re-registering past the resweep bound.
	int removeRunInstances(const std::string &baseName);
	/// Disables an application; false on a stale disable. Status flip and save
	/// under the mutation lock, termination outside it.
	bool disableApp(const std::string &appName, const Application *expected = nullptr);
	void enableApp(const std::string &appName);
	const Json::Value getAgentAppJson() const;

	std::shared_ptr<Label> getLabel() { return m_label; }

	const std::string getLogLevel() const;
	const std::string getDefaultExecUser() const;
	bool getDisableExecUser() const;
	const std::string getWorkDir() const;
	bool getSslVerifyClient() const;
	bool getSslVerifyServer() const;
	bool getSslEnabled() const;
	std::string getSSLCertificateFile() const;
	std::string getSSLCertificateKeyFile() const;
	std::string getSSLCaPath() const;
	std::string getSSLClientCertificateFile() const;
	std::string getSSLClientCertificateKeyFile() const;
	bool getRestEnabled() const;
	bool getCorsDisabled() const;
	bool metricsRequireAuth() const;
	std::set<std::string> getCorsAllowOrigins() const;
	std::string getRequestReplayProtection() const;
	std::string getRequestSignature() const;
	int getRequestReplayWindowSeconds() const;
	std::set<std::string> getCsrfAllowedOrigins() const;
	std::string getFileAllowedBaseDir() const;
	/// Effective worker threads: the configured value, or the CPU-derived default
	/// (capped) when the configuration leaves it at 0.
	std::size_t getWorkerThreads() const;
	/// Effective IO threads per transport listener, CPU-derived when configured as 0.
	std::size_t getTransportIoThreads() const;
	const std::string getPosixTimezone() const;

	bool checkOwnerPermission(const std::string &principalId, const std::string &ownerPrincipalId, int appPermission,
							  bool requestWrite) const;

	void dump();

private:
	friend class RestHandler;
	friend class AuthorizationStore;
	std::unique_lock<std::recursive_mutex> lockAppMutation() const;
	bool isCurrentApp(const std::string &appName, const std::shared_ptr<Application> &expected) const;
	/// True when depends_on edges reachable from `seedDeps` reach `targetName`.
	bool dependencyCycleExists(const std::vector<std::string> &seedDeps, const std::string &targetName) const;

private:
	// Registered applications keyed by name; the concurrent maps lock
	// internally per operation. The mutex below still serializes same-name
	// replacement across parse, metric transfer and map mutation.
	mutable boost::concurrent_flat_map<std::string, std::shared_ptr<Application>> m_apps;
	mutable boost::concurrent_flat_map<std::string, int> m_appNameIndexMap;
	// Serializes the multi-step run-name generation (read index, probe, write).
	mutable std::mutex m_appIndexGenMutex;
	mutable std::recursive_mutex m_appMutationMutex;
	std::shared_ptr<BaseConfig> m_baseConfig;
	std::shared_ptr<JsonRest> m_rest;
	std::shared_ptr<JsonDocker> m_docker;
	// Runtime exporter state is fixed at startup.
	std::atomic<bool> m_runtimePrometheusEnabled = false; // read without m_hotupdateMutex

	mutable std::recursive_mutex m_hotupdateMutex;

	std::shared_ptr<Label> m_label;

	static std::shared_ptr<Configuration> m_instance;
};
