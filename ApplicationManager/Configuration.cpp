#include "Configuration.h"
#include "../common/Utility.h"
#include "ApplicationPeriodRun.h"

#define DEFAULT_SCHEDULE_INTERVAL 3

std::shared_ptr<Configuration> Configuration::m_instance = nullptr;
Configuration::Configuration()
	:m_scheduleInterval(0), m_restListenPort(DEFAULT_REST_LISTEN_PORT), m_sslEnabled(false), m_restEnabled(true), m_jwtEnabled(true), m_threadPoolSize(6)
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
	config->m_hostDescription = GET_JSON_STR_VALUE(jobj, JSON_KEY_Description);
	config->m_scheduleInterval = GET_JSON_INT_VALUE(jobj, JSON_KEY_ScheduleIntervalSeconds);
	config->m_restListenPort = GET_JSON_INT_VALUE(jobj, JSON_KEY_RestListenPort);
	config->m_RestListenAddress = GET_JSON_STR_VALUE(jobj, JSON_KEY_RestListenAddress);
	config->m_logLevel = GET_JSON_STR_VALUE(jobj, JSON_KEY_LogLevel);
	SET_JSON_BOOL_VALUE(jobj, JSON_KEY_SSLEnabled, config->m_sslEnabled);
	SET_JSON_BOOL_VALUE(jobj, JSON_KEY_RestEnabled, config->m_restEnabled);
	SET_JSON_BOOL_VALUE(jobj, JSON_KEY_JWTEnabled, config->m_jwtEnabled);
	config->m_sslCertificateFile = GET_JSON_STR_VALUE(jobj, JSON_KEY_SSLCertificateFile);
	config->m_sslCertificateKeyFile = GET_JSON_STR_VALUE(jobj, JSON_KEY_SSLCertificateKeyFile);
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

	auto& jArr = jobj.at(JSON_KEY_Applications).as_array();
	for (auto iterB = jArr.begin(); iterB != jArr.end(); iterB++)
	{
		auto jsonObj = iterB->as_object();
		std::shared_ptr<Application> app = config->parseApp(jsonObj);
		app->dump();
		config->registerApp(app);
	}
	auto threadpool = GET_JSON_INT_VALUE(jobj, JSON_KEY_HttpThreadPoolSize);
	if (threadpool > 0 && threadpool < 40)
	{
		config->m_threadPoolSize = threadpool;
	}
	config->jsonToTag(jobj.at(JSON_KEY_Labels));
	config->m_jwtSection = jobj.at(JSON_KEY_jwt);
	config->m_roleSection = jobj.at(JSON_KEY_Roles);

	m_instance = config;
	return config;
}

std::string Configuration::readConfiguration()
{
	std::shared_ptr<Configuration> config;
	web::json::value jsonValue;
	std::string jsonPath = Utility::getSelfFullPath() + ".json";
	return Utility::readFileCpp(jsonPath);
}

web::json::value Configuration::AsJson(bool returnRuntimeInfo)
{
	// get applications
	auto apps = getApplicationJson(false);

	// get global parameters
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	web::json::value result = web::json::value::object();

	result[JSON_KEY_Description] = web::json::value::string(GET_STRING_T(m_hostDescription));
	result[JSON_KEY_RestListenPort] = web::json::value::number(m_restListenPort);
	result[JSON_KEY_RestListenAddress] = web::json::value::string(m_RestListenAddress);
	result[JSON_KEY_ScheduleIntervalSeconds] = web::json::value::number(m_scheduleInterval);
	result[JSON_KEY_LogLevel] = web::json::value::string(GET_STRING_T(m_logLevel));

	result[JSON_KEY_RestEnabled] = web::json::value::boolean(m_restEnabled);
	result[JSON_KEY_SSLEnabled] = web::json::value::boolean(m_sslEnabled);
	result[JSON_KEY_SSLCertificateFile] = web::json::value::string(GET_STRING_T(m_sslCertificateFile));
	result[JSON_KEY_SSLCertificateKeyFile] = web::json::value::string(GET_STRING_T(m_sslCertificateKeyFile));
	result[JSON_KEY_JWTEnabled] = web::json::value::boolean(m_jwtEnabled);
	result[JSON_KEY_HttpThreadPoolSize] = web::json::value::number((uint32_t)m_threadPoolSize);
	if (!returnRuntimeInfo)
	{
		result[JSON_KEY_jwt] = m_jwtSection;
		result[JSON_KEY_Roles] = m_roleSection;
	}
	
	result[JSON_KEY_Applications] = apps;
	result[JSON_KEY_Labels] = tagToJson();
	
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

std::string Configuration::getRestListenAddress()
{
	return m_RestListenAddress;
}

const utility::string_t Configuration::getConfigContentStr()
{
	return this->AsJson(false).serialize();
}

web::json::value Configuration::getApplicationJson(bool returnRuntimeInfo)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// Build Json
	auto result = web::json::value::array(m_apps.size());
	for (size_t i = 0; i < m_apps.size(); ++i)
	{
		result[i] = m_apps[i]->AsJson(returnRuntimeInfo);
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

web::json::value Configuration::tagToJson()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto tags = web::json::value::object();
	for (auto tag : m_tags)
	{
		tags[tag.first] = web::json::value::string(tag.second);
	}
	return tags;
}

void Configuration::jsonToTag(web::json::value json)
{
	const static char fname[] = "Configuration::jsonToTag() ";
	{
		LOG_INF << fname << "reset labels";
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		m_tags.clear();
		auto jobj = json.as_object();
		for (auto iter = jobj.begin(); iter != jobj.end(); iter++)
		{
			std::string lableKey = GET_STD_STRING(iter->first);
			m_tags[lableKey] = GET_STD_STRING(iter->second.as_string());
			LOG_INF << fname << "label: " << lableKey << "=" << m_tags[lableKey];
		}
	}
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

const web::json::value Configuration::getUserInfo(const std::string & userName)
{
	if (m_jwtSection.has_object_field(userName))
	{
		return m_jwtSection.at(userName);
	}
	else
	{
		throw std::invalid_argument(std::string("No such user: ") + userName);
	}
}

bool Configuration::checkUserPermission(const std::string & userName, const std::string & permission)
{
	const static char fname[] = "Configuration::checkUserPermission() ";

	auto userJson = getUserInfo(userName);
	auto roles = userJson.at(JSON_KEY_USER_roles).as_array();
	if (permission.empty()) return true;
	for (auto role : roles)
	{
		if (m_roleSection.has_array_field(role.as_string()))
		{
			auto permissions = m_roleSection.at(role.as_string()).as_array();
			for (auto perm : permissions)
			{
				if (perm.as_string() == permission)
				{
					return true;
				}
			}
		}
	}

	LOG_WAR << fname << "No such permission " << permission << " for user " << userName;
	return false;
}

void Configuration::dump()
{
	const static char fname[] = "Configuration::dump() ";

	LOG_DBG << fname  << '\n' << Utility::prettyJson(this->getConfigContentStr());

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
			ofs << Utility::prettyJson(content);
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

	if (GET_JSON_INT_VALUE(jsonApp, JSON_KEY_SHORT_APP_start_interval_seconds) > 0)
	{
		// Consider as short running application
		std::shared_ptr<ApplicationShortRun> shortApp;
		if (GET_JSON_BOOL_VALUE(jsonApp, JSON_KEY_PERIOD_APP_keep_running) == true)
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

