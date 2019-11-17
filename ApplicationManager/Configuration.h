#ifndef CONFIGURATION_H
#define CONFIGURATION_H
#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <map>

#include <cpprest/json.h>

#include "Application.h"
#include "Role.h"
#include "User.h"

//////////////////////////////////////////////////////////////////////////
// All the operation functions to access appmg.json
//////////////////////////////////////////////////////////////////////////
class Configuration
{
public:
	Configuration();
	virtual ~Configuration();

	static std::shared_ptr<Configuration> instance();
	static void instance(std::shared_ptr<Configuration> config);
	static std::string readConfiguration();
	static void handleReloadSignal();

	static std::shared_ptr<Configuration> FromJson(const std::string& str);
	web::json::value AsJson(bool returnRuntimeInfo);
	void saveConfigToDisk();
	void hotUpdate(const std::string& str);

	std::vector<std::shared_ptr<Application>> getApps();
	std::shared_ptr<Application> addApp(const web::json::object& jsonApp);
	void removeApp(const std::string& appName);
	void registerApp(std::shared_ptr<Application> app);
	std::shared_ptr<Application> parseApp(web::json::object jsonApp);

	int getScheduleInterval();
	int getRestListenPort();
	std::string getRestListenAddress();
	const utility::string_t getConfigContentStr();
	const utility::string_t getSecureConfigContentStr();
	web::json::value getApplicationJson(bool returnRuntimeInfo);
	std::shared_ptr<Application> getApp(const std::string& appName);
	void disableApp(const std::string& appName);
	void enableApp(const std::string& appName);

	web::json::value tagToJson();
	void jsonToTag(web::json::value json);

	const std::string getLogLevel() const;
	bool getSslEnabled() const;
	std::string getSSLCertificateFile() const;
	std::string getSSLCertificateKeyFile() const;
	bool getRestEnabled() const;
	bool getJwtEnabled() const;
	const size_t getThreadPoolSize() const { return m_threadPoolSize; }
	const std::string getDescription() const { return m_hostDescription; }

	const std::shared_ptr<User> getUserInfo(const std::string& userName);
	std::set<std::string> getUserPermissions(const std::string& userName);
	const std::string& getJwtRedirectUrl();

	void dump();

private:
	std::vector<std::shared_ptr<Application>> m_apps;
	std::string m_hostDescription;
	int m_scheduleInterval;
	int m_restListenPort;
	std::string m_RestListenAddress;
	std::string m_logLevel;
	std::string m_JwtRedirectUrl;

	std::recursive_mutex m_mutex;
	std::string m_jsonFilePath;
	std::map<std::string, std::string> m_tags;

	bool m_sslEnabled;
	bool m_restEnabled;
	bool m_jwtEnabled;
	std::string m_sslCertificateFile;
	std::string m_sslCertificateKeyFile;

	size_t m_threadPoolSize;
	std::shared_ptr<Roles> m_roles;
	std::shared_ptr<Users> m_users;

	static std::shared_ptr<Configuration> m_instance;
};

#endif