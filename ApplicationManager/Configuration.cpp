#include "Configuration.h"
#include <json/reader.h>
#include "../common/Utility.h"
#include "ApplicationPeriodRun.h"

#define DEFAULT_SCHEDULE_INTERVAL 3

std::shared_ptr<Configuration> Configuration::m_instance = nullptr;
Configuration::Configuration()
	:m_scheduleInterval(0), m_restListenPort(DEFAULT_REST_LISTEN_PORT), m_sslEnabled(false), m_restEnabled(true), m_jwtEnabled(true)
{
	m_jsonFilePath = Utility::getSelfFullPath() + ".json";
	LOG_INF << "Configuration file <" << m_jsonFilePath << ">";
}


Configuration::~Configuration()
{
}

std::shared_ptr<Configuration> Configuration::instance()
{
	return m_instance;
}

std::shared_ptr<Configuration> Configuration::FromJson(const std::string& str)
{
	web::json::value jval;
	try
	{
		jval = web::json::value::parse(GET_STRING_T(str));
	}
	catch (const std::exception& e)
	{
		LOG_ERR << "Failed to parse configuration file with error <" << e.what() << ">";
		throw std::invalid_argument("Failed to parse configuration file, please check json configuration file format");
	}
	catch (...)
	{
		LOG_ERR << "Failed to parse configuration file with error <unknown exception>";
		throw std::invalid_argument("Failed to parse configuration file, please check json configuration file format");
	}
	web::json::object jobj = jval.as_object();
	auto config = std::make_shared<Configuration>();
	config->m_hostDescription = GET_JSON_STR_VALUE(jobj, "Description");
	config->m_scheduleInterval = GET_JSON_INT_VALUE(jobj, "ScheduleIntervalSeconds");
	config->m_restListenPort = GET_JSON_INT_VALUE(jobj, "RestListenPort");
	config->m_restListenIp = GET_JSON_STR_VALUE(jobj, "RestListenAddress");
	config->m_logLevel = GET_JSON_STR_VALUE(jobj, "LogLevel");
	SET_JSON_BOOL_VALUE(jobj, "SSLEnabled", config->m_sslEnabled);
	SET_JSON_BOOL_VALUE(jobj, "RestEnabled", config->m_restEnabled);
	SET_JSON_BOOL_VALUE(jobj, "JWTEnabled", config->m_jwtEnabled);
	config->m_sslCertificateFile = GET_JSON_STR_VALUE(jobj, "SSLCertificateFile");
	config->m_sslCertificateKeyFile = GET_JSON_STR_VALUE(jobj, "SSLCertificateKeyFile");
	if (config->m_scheduleInterval < 1 || config->m_scheduleInterval > 100)
	{
		// Use default value instead
		config->m_scheduleInterval = DEFAULT_SCHEDULE_INTERVAL;
		LOG_INF << "Default value <" << config->m_scheduleInterval << "> will by used for ScheduleIntervalSec";
	}
	if (config->m_restListenPort < 1000 || config->m_restListenPort > 65534)
	{
		config->m_restListenPort = DEFAULT_REST_LISTEN_PORT;
		LOG_INF << "Default value <" << config->m_restListenPort << "> will by used for RestListenPort";
	}

	auto& jArr = jobj.at(GET_STRING_T("Applications")).as_array();
	for (auto iterB = jArr.begin(); iterB != jArr.end(); iterB++)
	{
		auto jsonObj = iterB->as_object();
		std::shared_ptr<Application> app = config->parseApp(jsonObj);
		app->dump();
		config->registerApp(app);
	}
	auto& jwt = jobj.at(GET_STRING_T("jwt")).as_object();
	config->m_jwtAdminName = GET_STD_STRING(jwt.at(GET_STRING_T("admin")).as_object().at(GET_STRING_T("name")).as_string());
	config->m_jwtAdminKey = GET_STD_STRING(jwt.at(GET_STRING_T("admin")).as_object().at(GET_STRING_T("key")).as_string());
	config->m_jwtUserName = GET_STD_STRING(jwt.at(GET_STRING_T("user")).as_object().at(GET_STRING_T("name")).as_string());
	config->m_jwtUserKey = GET_STD_STRING(jwt.at(GET_STRING_T("user")).as_object().at(GET_STRING_T("key")).as_string());
	m_instance = config;
	return config;
}

web::json::value Configuration::AsJson(bool returnRuntimeInfo)
{
	// get applications
	auto apps = getApplicationJson();

	// get global parameters
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	web::json::value result = web::json::value::object();

	result[GET_STRING_T("Description")] = web::json::value::string(GET_STRING_T(m_hostDescription));
	result[GET_STRING_T("RestListenPort")] = web::json::value::number(m_restListenPort);
	result[GET_STRING_T("ScheduleIntervalSeconds")] = web::json::value::number(m_scheduleInterval);
	result[GET_STRING_T("LogLevel")] = web::json::value::string(GET_STRING_T(m_logLevel));

	result[GET_STRING_T("SSLEnabled")] = web::json::value::boolean(m_sslEnabled);
	result[GET_STRING_T("SSLCertificateFile")] = web::json::value::string(GET_STRING_T(m_sslCertificateFile));
	result[GET_STRING_T("SSLCertificateKeyFile")] = web::json::value::string(GET_STRING_T(m_sslCertificateKeyFile));

	result[GET_STRING_T("JWTEnabled")] = web::json::value::boolean(m_jwtEnabled);
	if (!returnRuntimeInfo)
	{
		web::json::value jwt = web::json::value::object();
		web::json::value jwtAdmin = web::json::value::object();
		web::json::value jwtUser = web::json::value::object();
		jwtAdmin[GET_STRING_T("name")] = web::json::value::string(m_jwtAdminName);
		jwtAdmin[GET_STRING_T("key")] = web::json::value::string(m_jwtAdminKey);
		jwtUser[GET_STRING_T("name")] = web::json::value::string(m_jwtUserName);
		jwtUser[GET_STRING_T("key")] = web::json::value::string(m_jwtUserKey);
		jwt[GET_STRING_T("admin")] = jwtAdmin;
		jwt[GET_STRING_T("user")] = jwtUser;
		result[GET_STRING_T("jwt")] = jwt;
	}
	
	result[GET_STRING_T("Applications")] = apps;
	return result;
}

std::vector<std::shared_ptr<Application>> Configuration::getApps()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_apps;
}

void Configuration::registerApp(std::shared_ptr<Application> app)
{
	const static char fname[] = "Configuration::registerApp() ";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	for (size_t i = 0; i < m_apps.size(); i++)
	{
		if (m_apps[i]->getName() == app->getName())
		{
			LOG_INF << fname << "Application <" << app->getName() << "> already exist.";
			return;
		}
	}
	m_apps.push_back(app);
}

int Configuration::getScheduleInterval()
{
	return m_scheduleInterval;
}

int Configuration::getRestListenPort()
{
	return m_restListenPort;
}

std::string Configuration::getRestListenIp()
{
	return m_restListenIp;
}

const utility::string_t Configuration::getConfigContentStr()
{
	return this->AsJson(false).serialize();
}

web::json::value Configuration::getApplicationJson()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// Build Json
	auto result = web::json::value::array(m_apps.size());
	for (size_t i = 0; i < m_apps.size(); ++i)
	{
		result[i] = m_apps[i]->AsJson(true);
	}
	return result;
}

void Configuration::stopApp(const std::string& appName)
{
	getApp(appName)->stop();
	saveConfigToDisk();
}
void Configuration::startApp(const std::string& appName)
{
	auto app = getApp(appName);
	app->start();
	saveConfigToDisk();
}

const std::string Configuration::getLogLevel() const
{
	return m_logLevel;
}

bool Configuration::getSslEnabled() const
{
	return m_sslEnabled;
}

std::string Configuration::getSSLCertificateFile() const
{
	return m_sslCertificateFile;
}

std::string Configuration::getSSLCertificateKeyFile() const
{
	return m_sslCertificateKeyFile;
}

bool Configuration::getRestEnabled() const
{
	return m_restEnabled;
}

bool Configuration::getJwtEnabled() const
{
	return m_jwtEnabled;
}

const std::string & Configuration::getJwtAdminName() const
{
	return m_jwtAdminName;
}

const std::string & Configuration::getJwtUserName() const
{
	return m_jwtUserName;
}

const std::string & Configuration::getJwtAdminKey() const
{
	return m_jwtAdminKey;
}

const std::string & Configuration::getJwtUserKey() const
{
	return m_jwtUserKey;
}

void Configuration::dump()
{
	const static char fname[] = "Configuration::dump() ";

	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		LOG_DBG << fname << "m_hostDescription:" << m_hostDescription;
		LOG_DBG << fname << "m_scheduleInterval:" << m_scheduleInterval;
		LOG_DBG << fname << "m_sslEnabled:" << m_sslEnabled;
		LOG_DBG << fname << "m_restEnabled:" << m_restEnabled;
		LOG_DBG << fname << "m_jwtEnabled:" << m_jwtEnabled;
		LOG_DBG << fname << "m_restListenPort:" << m_restListenPort;
		LOG_DBG << fname << "m_configContent:" << GET_STD_STRING(this->getConfigContentStr());

		LOG_DBG << fname << "m_jwtAdminName:" << m_jwtAdminName;
		LOG_DBG << fname << "m_jwtUserName:" << m_jwtUserName;
		LOG_DBG << fname << "m_jwtAdminKey:" << m_jwtAdminKey;
		LOG_DBG << fname << "m_jwtUserKey:" << m_jwtUserKey;
	}
	auto apps = getApps();
	for (auto app : apps)
	{
		app->dump();
	}
}

std::shared_ptr<Application> Configuration::addApp(const web::json::object& jsonApp)
{
	std::shared_ptr<Application> app = parseApp(jsonApp);
	bool update = false;

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	std::for_each(m_apps.begin(), m_apps.end(), [&app, &update](std::shared_ptr<Application>& mapApp)
	{
		if (mapApp->getName() == app->getName())
		{	
			// Stop existing app and replace
			mapApp->stop();
			mapApp = app;
			update = true;
		}
	});

	if (!update)
	{
		// Register app
		registerApp(app);
	}
	// Write to disk
	saveConfigToDisk();

	return app;
}

void Configuration::removeApp(const std::string& appName)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// Update in-memory app
	for (auto iterA = m_apps.begin(); iterA != m_apps.end();)
	{
		if ((*iterA)->getName() == appName)
		{
			(*iterA)->destroy();
			iterA = m_apps.erase(iterA);
		}
		else
		{
			iterA++;
		}
	}

	// Write to disk
	saveConfigToDisk();
}

void Configuration::saveConfigToDisk()
{
	const static char fname[] = "Configuration::saveConfigToDisk() ";

	auto content = GET_STD_STRING(this->getConfigContentStr());
	if (content.length())
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		auto tmpFile = m_jsonFilePath + "." + std::to_string(Utility::getThreadId());
		std::ofstream ofs(tmpFile, ios::trunc);
		if (ofs.is_open())
		{
			ofs << prettyJson(content);
			ofs.close();
			if (ACE_OS::rename(tmpFile.c_str(), m_jsonFilePath.c_str()) == 0)
			{
				LOG_INF << fname << content;
			}
			else
			{
				LOG_ERR << fname << "Failed to write configuration file <" << m_jsonFilePath << ">, error :" << std::strerror(errno);
			}
		}
	}
	else
	{
		LOG_ERR << fname << "Configuration content is empty";
	}
}

std::shared_ptr<Application> Configuration::parseApp(web::json::object jsonApp)
{
	std::shared_ptr<Application> app;

	if (GET_JSON_INT_VALUE(jsonApp, "start_interval_seconds") > 0)
	{
		// Consider as short running application
		std::shared_ptr<ApplicationShortRun> shortApp;
		if (GET_JSON_BOOL_VALUE(jsonApp, "keep_running") == true)
		{
			std::shared_ptr<ApplicationPeriodRun> tmpApp(new ApplicationPeriodRun());
			ApplicationPeriodRun::FromJson(tmpApp, jsonApp);
			shortApp = tmpApp;
		}
		else
		{
			shortApp.reset(new ApplicationShortRun());
			ApplicationShortRun::FromJson(shortApp, jsonApp);
			
		}
		shortApp->initTimer();
		app = shortApp;
	}
	else
	{
		// Long running application
		app.reset(new Application());
		Application::FromJson(app, jsonApp);
	}
	return app;
}

std::string Configuration::prettyJson(const std::string & jsonStr)
{
	static Json::CharReaderBuilder builder;
	static Json::CharReader* reader(builder.newCharReader());
	Json::Value root;
	Json::String errs;
	if (reader->parse(jsonStr.c_str(), jsonStr.c_str() + std::strlen(jsonStr.c_str()), &root, &errs))
	{
		return root.toStyledString();
	}
	else
	{
		std::string msg = "Failed to parse json : " + jsonStr + " with error :" + errs;
		LOG_ERR << msg;
		throw std::invalid_argument(msg);
	}
}

std::shared_ptr<Application> Configuration::getApp(const std::string & appName)
{
	std::vector<std::shared_ptr<Application>> apps = getApps();
	for (auto app : apps)
	{
		if (app->getName() == appName)
		{
			return app;
		}
	}
	throw std::invalid_argument("No such application found");
}

