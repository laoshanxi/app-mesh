#pragma once

#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include <ace/Map_Manager.h>
#include <ace/Recursive_Thread_Mutex.h>
#include <nlohmann/json.hpp>

class RestHandler;
class User;
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
		bool m_sslVerifyClient;
		std::string m_certFile;
		std::string m_certKeyFile;
		std::string m_clientCertFile;
		std::string m_clientCertKeyFile;
		std::string m_sslCaPath;
		JsonSsl();
	};

	struct JsonJwt
	{
		JsonJwt();
		static std::shared_ptr<JsonJwt> FromJson(const nlohmann::json &jsonObj);
		nlohmann::json AsJson() const;
		std::string getJwtInterface() const;

		std::string m_jwtSalt;
		std::string m_jwtIssuer;
		std::string m_jwtInterface;
	};

	struct JsonRest
	{
		JsonRest();
		static std::shared_ptr<JsonRest> FromJson(const nlohmann::json &jsonObj);
		nlohmann::json AsJson() const;

		bool m_restEnabled;
		int m_httpThreadPoolSize;
		int m_restListenPort;
		int m_promListenPort;
		std::string m_restListenAddress;
		int m_restTcpPort;
		std::string m_dockerProxyListenAddr;
		std::shared_ptr<JsonSsl> m_ssl;
		std::shared_ptr<JsonJwt> m_jwt;
	};

	struct JsonConsul
	{
		JsonConsul();
		static std::shared_ptr<JsonConsul> FromJson(const nlohmann::json &jsonObj, int appmeshRestPort);
		nlohmann::json AsJson() const;
		bool consulEnabled() const;
		bool consulSecurityEnabled() const;
		const std::string appmeshUrl() const;

		bool m_isMaster;
		bool m_isWorker;
		// http://consul.service.consul:8500
		std::string m_consulUrl;
		// appmesh proxy url, used to report to Consul to expose local appmesh listen port address
		std::string m_proxyUrl;
		// in case of not set m_proxyUrl, use default dynamic value https://localhost:6060
		std::string m_defaultProxyUrl;
		// TTL (string: "") - Specifies the number of seconds (between 10s and 86400s).
		int m_ttl;
		bool m_securitySync;
		std::string m_basicAuthUser;
		std::string m_basicAuthPass;
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
	void hotUpdate(nlohmann::json &config);
	static bool readConfigFromEnv(nlohmann::json &jsonConfig);
	static bool applyEnvConfig(nlohmann::json &jsonValue, std::string envValue);
	void registerPrometheus();
	bool prometheusEnabled() const;

	std::vector<std::shared_ptr<Application>> getApps() const;
	std::shared_ptr<Application> addApp(const nlohmann::json &jsonApp, std::shared_ptr<Application> fromApp = nullptr, bool persistable = true);
	void removeApp(const std::string &appName);
	std::shared_ptr<Application> parseApp(const nlohmann::json &jsonApp);

	int getScheduleInterval();
	int getRestListenPort();
	int getPromListenPort() const;
	std::string getRestListenAddress();
	std::string getRestJwtIssuer();
	std::string getDockerProxyAddress() const;
	int getRestTcpPort();
	nlohmann::json serializeApplication(bool returnRuntimeInfo, const std::string &user, bool returnUnPersistApp) const;
	std::shared_ptr<Application> getApp(const std::string &appName, bool throwOnNotFound = true) const noexcept(false);
	std::shared_ptr<Application> getApp(const void *app) const;
	bool isAppExist(const std::string &appName);
	void disableApp(const std::string &appName);
	void enableApp(const std::string &appName);
	const nlohmann::json getAgentAppJson() const;

	std::shared_ptr<Label> getLabel() { return m_label; }

	const std::string getLogLevel() const;
	const std::string getDefaultExecUser() const;
	bool getDisableExecUser() const;
	const std::string getWorkDir() const;
	bool getSslVerifyClient() const;
	std::string getSSLCertificateFile() const;
	std::string getSSLCertificateKeyFile() const;
	std::string getSSLCaPath() const;
	bool getRestEnabled() const;
	std::size_t getThreadPoolSize() const;
	const std::string getDescription() const;
	const std::string getPosixTimezone() const;

	const std::shared_ptr<Configuration::JsonConsul> getConsul() const;
	const std::shared_ptr<JsonJwt> getJwt() const;
	bool checkOwnerPermission(const std::string &user, const std::shared_ptr<User> &appOwner, int appPermission, bool requestWrite) const;

	void dump();

private:
	void addApp2Map(std::shared_ptr<Application> app);

private:
	mutable ACE_Map_Manager<std::string, std::shared_ptr<Application>, ACE_Recursive_Thread_Mutex> m_apps;
	std::shared_ptr<BaseConfig> m_baseConfig;
	std::shared_ptr<JsonRest> m_rest;
	std::shared_ptr<JsonConsul> m_consul;

	mutable std::recursive_mutex m_hotupdateMutex;

	std::shared_ptr<Label> m_label;

	static std::shared_ptr<Configuration> m_instance;
};
