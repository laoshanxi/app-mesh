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
	struct JsonSsl {
		static std::shared_ptr<JsonSsl> FromJson(const web::json::value& jobj);
		web::json::value AsJson();
		bool m_sslEnabled;
		std::string m_certFile;
		std::string m_certKeyFile;
		JsonSsl();
	};
	struct JsonRest {
		static std::shared_ptr<JsonRest> FromJson(const web::json::value& jobj);
		web::json::value AsJson();

		bool m_restEnabled;
		int m_httpThreadPoolSize;
		int m_restListenPort;
		int m_promListenPort;
		std::string m_restListenAddress;
		std::shared_ptr<JsonSsl> m_ssl;
		JsonRest();
	};
	struct JsonSecurity {
		static std::shared_ptr<JsonSecurity> FromJson(const web::json::value& jobj);
		web::json::value AsJson(bool returnRuntimeInfo);
		bool m_jwtEnabled;
		std::string m_JwtRedirectUrl;
		bool m_encryptKey;
		std::shared_ptr<Users> m_jwtUsers;
		std::shared_ptr<Roles> m_roles;
		JsonSecurity();
	};
	struct JsonConsul {
		JsonConsul();
		static std::shared_ptr<JsonConsul> FromJson(const web::json::value& jobj);
		web::json::value AsJson();
		bool enabled() const;

		bool m_isMaster;
		bool m_isNode;
		std::string m_datacenter;
		// http://consul.service.consul:8500
		std::string m_consulUrl;
		// TTL (string: "") - Specifies the number of seconds (between 10s and 86400s).
		int m_ttl;
		// report status to consul interval
		int m_reportInterval;
		int m_topologyInterval;
	};
public:
	Configuration();
	virtual ~Configuration();

	static std::shared_ptr<Configuration> instance();
	static void instance(std::shared_ptr<Configuration> config);
	static std::string readConfiguration();
	static void handleReloadSignal();

	static std::shared_ptr<Configuration> FromJson(const std::string& str) noexcept(false);
	web::json::value AsJson(bool returnRuntimeInfo);
	void saveConfigToDisk();
	void hotUpdate(const web::json::value& config);
	void registerPrometheus();

	std::vector<std::shared_ptr<Application>> getApps();
	std::shared_ptr<Application> addApp(const web::json::value& jsonApp);
	void removeApp(const std::string& appName);
	std::shared_ptr<Application> parseApp(const web::json::value& jsonApp);

	int getScheduleInterval();
	int getRestListenPort();
	int getPromListenPort();
	std::string getRestListenAddress();
	const web::json::value getSecureConfigJson();
	web::json::value getApplicationJson(bool returnRuntimeInfo);
	std::shared_ptr<Application> getApp(const std::string& appName) noexcept(false);
	bool isAppExist(const std::string& appName);
	void disableApp(const std::string& appName);
	void enableApp(const std::string& appName);

	std::shared_ptr<Label> getLabel() { return m_label; }

	const std::string getLogLevel() const;
	bool getSslEnabled() const;
	bool getEncryptKey() const;
	std::string getSSLCertificateFile() const;
	std::string getSSLCertificateKeyFile() const;
	bool getRestEnabled() const;
	bool getJwtEnabled() const;
	const size_t getThreadPoolSize() const;
	const std::string getDescription() const { return m_hostDescription; }

	const std::shared_ptr<User> getUserInfo(const std::string& userName);
	std::set<std::string> getUserPermissions(const std::string& userName);
	const std::shared_ptr<Users> getUsers() const;
	const std::shared_ptr<Roles> getRoles() const;
	const std::string& getJwtRedirectUrl();
	const std::shared_ptr<Configuration::JsonConsul> getConsul() const;

	void dump();

private:
		void addApp2Map(std::shared_ptr<Application> app);

private:
	std::vector<std::shared_ptr<Application>> m_apps;
	std::string m_hostDescription;
	int m_scheduleInterval;
	std::shared_ptr<JsonRest> m_rest;
	std::shared_ptr<JsonSecurity> m_security;
	std::shared_ptr<JsonConsul> m_consul;
	
	std::string m_logLevel;

	std::recursive_mutex m_mutex;
	std::string m_jsonFilePath;

	std::shared_ptr<Label> m_label;

	static std::shared_ptr<Configuration> m_instance;
};
