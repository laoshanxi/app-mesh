#pragma once

#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <set>
#include <cpprest/json.h>

class RestHandler;
class Roles;
class Users;
class User;
class Label;
class Application;

//////////////////////////////////////////////////////////////////////////
/// All the operation functions to access appmg.json
//////////////////////////////////////////////////////////////////////////
class Configuration
{
	struct JsonSsl
	{
		static std::shared_ptr<JsonSsl> FromJson(const web::json::value &jsonObj);
		web::json::value AsJson() const;
		bool m_sslEnabled;
		std::string m_certFile;
		std::string m_certKeyFile;
		JsonSsl();
	};
	struct JsonRest
	{
		static std::shared_ptr<JsonRest> FromJson(const web::json::value &jsonObj);
		web::json::value AsJson() const;

		bool m_restEnabled;
		int m_httpThreadPoolSize;
		int m_restListenPort;
		int m_promListenPort;
		std::string m_restListenAddress;
		std::shared_ptr<JsonSsl> m_ssl;
		JsonRest();
	};
	struct JsonConsul
	{
		JsonConsul();
		static std::shared_ptr<JsonConsul> FromJson(const web::json::value &jsonObj, int appmeshRestPort, bool sslEnabled);
		web::json::value AsJson() const;
		bool consulEnabled() const;
		bool consulSecurityEnabled() const;
		const std::string appmeshUrl() const;

		bool m_isMaster;
		bool m_isNode;
		std::string m_datacenter;
		// http://consul.service.consul:8500
		std::string m_consulUrl;
		// appmesh proxy url, used to report to Consul to expose local appmesh listen port address
		std::string m_proxyUrl;
		// in case of not set m_proxyUrl, use default dynamic value https://localhost:6060
		std::string m_defaultProxyUrl;
		// TTL (string: "") - Specifies the number of seconds (between 10s and 86400s).
		int m_ttl;
		bool m_securitySync;
	};

public:
	struct JsonSecurity
	{
		static std::shared_ptr<JsonSecurity> FromJson(const web::json::value &jsonObj);
		web::json::value AsJson(bool returnRuntimeInfo);
		bool m_jwtEnabled;
		bool m_encryptKey;
		std::shared_ptr<Users> m_jwtUsers;
		std::shared_ptr<Roles> m_roles;
		JsonSecurity();
	};
	Configuration();
	virtual ~Configuration();

	static std::shared_ptr<Configuration> instance();
	static void instance(std::shared_ptr<Configuration> config);
	static std::string readConfiguration();
	static void handleSignal();

	static std::shared_ptr<Configuration> FromJson(const std::string &str, bool applyEnv = false) noexcept(false);
	web::json::value AsJson(bool returnRuntimeInfo, const std::string &user);
	void deSerializeApp(const web::json::value &jsonObj);
	void saveConfigToDisk();
	void hotUpdate(const web::json::value &config);
	static void readConfigFromEnv(web::json::value &jsonConfig);
	static bool applyEnvConfig(web::json::value& jsonValue, std::string envValue);
	void registerPrometheus();

	std::vector<std::shared_ptr<Application>> getApps() const;
	std::shared_ptr<Application> addApp(const web::json::value &jsonApp);
	void removeApp(const std::string &appName);
	std::shared_ptr<Application> parseApp(const web::json::value &jsonApp);

	int getScheduleInterval();
	int getRestListenPort();
	int getPromListenPort();
	std::string getRestListenAddress();
	const web::json::value getSecureConfigJson();
	web::json::value serializeApplication(bool returnRuntimeInfo, const std::string &user) const;
	std::shared_ptr<Application> getApp(const std::string &appName) const noexcept(false);
	bool isAppExist(const std::string &appName);
	void disableApp(const std::string &appName);
	void enableApp(const std::string &appName);

	std::shared_ptr<Label> getLabel() { return m_label; }

	const std::string getLogLevel() const;
	const std::string getDefaultExecUser() const;
	const std::string getDefaultWorkDir() const;
	bool getSslEnabled() const;
	bool getEncryptKey();
	std::string getSSLCertificateFile() const;
	std::string getSSLCertificateKeyFile() const;
	bool getRestEnabled() const;
	bool getJwtEnabled() const;
	const std::size_t getThreadPoolSize() const;
	const std::string getDescription() const;

	const std::shared_ptr<User> getUserInfo(const std::string &userName) const;
	std::set<std::string> getUserPermissions(const std::string &userName);
	std::set<std::string> getAllPermissions();
	const std::shared_ptr<Users> getUsers();
	const std::shared_ptr<Roles> getRoles();
	const std::shared_ptr<Configuration::JsonConsul> getConsul() const;
	const std::shared_ptr<Configuration::JsonSecurity> getSecurity() const;
	void updateSecurity(std::shared_ptr<Configuration::JsonSecurity> security);
	bool checkOwnerPermission(const std::string &user, const std::shared_ptr<User> &appOwner, int appPermission, bool requestWrite) const;

	void dump();

private:
	void addApp2Map(std::shared_ptr<Application> app);

private:
	std::vector<std::shared_ptr<Application>> m_apps;
	std::string m_hostDescription;
	std::string m_defaultExecUser;
	std::string m_defaultWorkDir;
	int m_scheduleInterval;
	std::shared_ptr<JsonRest> m_rest;
	std::shared_ptr<JsonSecurity> m_security;
	std::shared_ptr<JsonConsul> m_consul;

	std::string m_logLevel;
	std::string m_formatPosixZone;

	mutable std::recursive_mutex m_appMutex;
	mutable std::recursive_mutex m_hotupdateMutex;
	std::string m_jsonFilePath;

	std::shared_ptr<Label> m_label;

	static std::shared_ptr<Configuration> m_instance;
};
