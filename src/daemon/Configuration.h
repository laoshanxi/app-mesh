// src/daemon/Configuration.h
#pragma once

#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <ace/Map_Manager.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>

class RestHandler;
class AuthorizationStore;
class Label;
class Application;

/// <summary>
/// Configuration file <config.yaml> parse/update
/// </summary>
class Configuration
{
public:
	struct BaseConfig
	{
		BaseConfig();
		static std::shared_ptr<BaseConfig> FromJson(const nlohmann::json &jsonObj);
		nlohmann::json AsJson() const;

		std::string m_hostDescription;
		std::string m_defaultExecUser;
		std::string m_defaultWorkDir;
		int m_scheduleInterval;
		bool m_disableExecUser;
		std::string m_logLevel;
		std::string m_posixTimezone;
	};
	struct JsonSsl
	{
		static std::shared_ptr<JsonSsl> FromJson(const nlohmann::json &jsonObj);
		nlohmann::json AsJson() const;
		bool m_sslVerifyServer;
		bool m_sslVerifyServerDelegate;
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
		static std::shared_ptr<JsonRest> FromJson(const nlohmann::json &jsonObj);
		nlohmann::json AsJson() const;

		bool m_restEnabled;
		bool m_corsDisabled;
		std::set<std::string> m_csrfAllowedOrigins; // CSRF: Origins allowed for cookie-auth state-changing requests
		std::string m_fileAllowedBaseDir;
		int m_workerThreadPoolSize;
		int m_IOThreadPoolSize;
		int m_restListenPort;
		int m_promListenPort;
		std::string m_restListenAddress;
		int m_restTcpPort;
		int m_webSocketPort;
		std::shared_ptr<JsonSsl> m_ssl;
	};

	Configuration();
	virtual ~Configuration();

	static std::shared_ptr<Configuration> instance();
	static void instance(std::shared_ptr<Configuration> config);
	static std::string readConfiguration();
	static void handleSignal();

	static std::shared_ptr<Configuration> FromJson(nlohmann::json &jsonValue, bool applyEnv = false) noexcept(false);
	nlohmann::json AsJson();
	void loadApps(const boost::filesystem::path &appDir);
	void saveConfigToDisk();
	void hotUpdateAndSave(nlohmann::json &config);
	void hotUpdate(nlohmann::json &config);
	static bool overrideConfigWithEnv(nlohmann::json &jsonConfig);
	static bool applyEnvConfig(nlohmann::json &jsonValue, std::string envValue);
	void registerPrometheus();
	bool prometheusEnabled() const;

	std::vector<std::shared_ptr<Application>> getApps() const;
	std::shared_ptr<Application> addApp(const nlohmann::json &jsonApp, bool persistable = true);
	void removeApp(const std::string &appName, const Application *expected = nullptr);
	std::shared_ptr<Application> parseApp(const nlohmann::json &jsonApp);

	int getScheduleInterval();
	int getRestListenPort();
	int getPromListenPort() const;
	std::string getRestListenAddress();
	int getRestTcpPort();
	int getWebSocketPort();
	nlohmann::json serializeApplication(bool returnRuntimeInfo, const std::string &user, bool returnUnPersistApp) const;
	std::shared_ptr<Application> getApp(const std::string &appName, bool throwOnNotFound = true) const noexcept(false);
	std::shared_ptr<Application> getApp(const void *app) const;
	bool isAppExist(const std::string &appName);
	std::string generateRunAppName(const std::string &provideAppName);
	void disableApp(const std::string &appName);
	void enableApp(const std::string &appName);
	const nlohmann::json getAgentAppJson(const std::string &shmName) const;

	std::shared_ptr<Label> getLabel() { return m_label; }

	const std::string getLogLevel() const;
	const std::string getDefaultExecUser() const;
	bool getDisableExecUser() const;
	const std::string getWorkDir() const;
	bool getSslVerifyClient() const;
	bool getSslVerifyServer() const;
	std::string getSSLCertificateFile() const;
	std::string getSSLCertificateKeyFile() const;
	std::string getSSLCaPath() const;
	bool getRestEnabled() const;
	bool getCorsDisabled() const;
	std::set<std::string> getCsrfAllowedOrigins() const;
	std::string getFileAllowedBaseDir() const;
	std::size_t getWorkerThreadPoolSize() const;
	std::size_t getIOThreadPoolSize() const;
	const std::string getDescription() const;
	const std::string getPosixTimezone() const;

	bool checkOwnerPermission(const std::string &principalId, const std::string &ownerPrincipalId,
		int appPermission, bool requestWrite) const;

	void dump();

private:
	friend class RestHandler;
	friend class AuthorizationStore;
	std::unique_lock<std::recursive_mutex> lockAppMutation() const;
	bool isCurrentApp(const std::string &appName, const std::shared_ptr<Application> &expected) const;
	void addApp2Map(std::shared_ptr<Application> app);

private:
	mutable ACE_Map_Manager<std::string, std::shared_ptr<Application>, ACE_Recursive_Thread_Mutex> m_apps;
	mutable ACE_Map_Manager<std::string, int, ACE_Recursive_Thread_Mutex> m_appNameIndexMap;
	// Serializes same-name replacement/removal across parse, metric transfer and map mutation.
	mutable std::recursive_mutex m_appMutationMutex;
	std::shared_ptr<BaseConfig> m_baseConfig;
	std::shared_ptr<JsonRest> m_rest;
	// Runtime exporter state is fixed at startup.
	bool m_runtimePrometheusEnabled = false;

	mutable std::recursive_mutex m_hotupdateMutex;

	std::shared_ptr<Label> m_label;

	static std::shared_ptr<Configuration> m_instance;
};
