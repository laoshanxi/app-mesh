#ifndef CONFIGURATION_H
#define CONFIGURATION_H
#include <string>
#include <memory>
#include <vector>
#include <mutex>
#include <map>

#include <cpprest/json.h>

#include "Application.h"

//////////////////////////////////////////////////////////////////////////
// All the operation functions to access appmg.json
//////////////////////////////////////////////////////////////////////////
class Configuration
{
public:
	Configuration();
	virtual ~Configuration();

	static std::shared_ptr<Configuration> instance();
	static std::shared_ptr<Configuration> FromJson(const std::string& str);
	static std::string readConfiguration();
	web::json::value AsJson(bool returnRuntimeInfo);
	
	std::vector<std::shared_ptr<Application>> getApps();
	std::shared_ptr<Application> addApp(const web::json::object& jsonApp);
	void removeApp(const std::string& appName);
	void registerApp(std::shared_ptr<Application> app);
	int getScheduleInterval();
	int getRestListenPort();
	std::string getRestListenAddress();
	const utility::string_t getConfigContentStr();
	web::json::value getApplicationJson(bool returnRuntimeInfo);
	std::shared_ptr<Application> getApp(const std::string& appName);
	void stopApp(const std::string& appName);
	void startApp(const std::string& appName);
	const std::string getLogLevel() const;
	web::json::value tagToJson();
	void jsonToTag(web::json::value json);
	void saveTags();

	bool getSslEnabled() const;
	std::string getSSLCertificateFile() const;
	std::string getSSLCertificateKeyFile() const;
	bool getRestEnabled() const;
	bool getJwtEnabled() const;
	const std::string & getJwtAdminName() const;
	const std::string & getJwtUserName() const;
	const std::string & getJwtAdminKey() const;
	const std::string & getJwtUserKey() const;
	const size_t getThreadPoolSize() const { return m_threadPoolSize; }
	
	void dump();

private:
	void saveConfigToDisk();
	std::shared_ptr<Application> parseApp(web::json::object jsonApp);
	
private:
	std::vector<std::shared_ptr<Application>> m_apps;
	std::string m_hostDescription;
	int m_scheduleInterval;
	int m_restListenPort;
	std::string m_RestListenAddress;
	std::string m_logLevel;

	std::recursive_mutex m_mutex;
	std::string m_jsonFilePath;
	std::map<std::string, std::string> m_tags;

	bool m_sslEnabled;
	bool m_restEnabled;
	bool m_jwtEnabled;
	std::string m_sslCertificateFile;
	std::string m_sslCertificateKeyFile;

	std::string m_jwtAdminName;
	std::string m_jwtUserName;
	std::string m_jwtAdminKey;
	std::string m_jwtUserKey;

	size_t m_threadPoolSize;

	static std::shared_ptr<Configuration> m_instance;
};

#endif