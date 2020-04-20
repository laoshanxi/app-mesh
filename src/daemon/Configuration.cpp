#include <set>
#include <ace/Signal.h>
#include <boost/algorithm/string_regex.hpp>

#include "Application.h"
#include "ApplicationInitialize.h"
#include "ApplicationUnInitia.h"
#include "ApplicationPeriodRun.h"
#include "Configuration.h"
#include "ConsulConnection.h"
#include "Label.h"
#include "ResourceCollection.h"
#include "PrometheusRest.h"
#include "RestHandler.h"
#include "User.h"

#include "../common/Utility.h"

// from main.cpp
extern std::set<std::shared_ptr<RestHandler>> m_restList;

std::shared_ptr<Configuration> Configuration::m_instance = nullptr;
Configuration::Configuration()
	:m_scheduleInterval(DEFAULT_SCHEDULE_INTERVAL)
{
	m_jsonFilePath = Utility::getSelfFullPath() + ".json";
	m_label = std::make_unique<Label>();
	m_security = std::make_shared<JsonSecurity>();
	m_rest = std::make_shared<JsonRest>();
	m_consul = std::make_shared<JsonConsul>();
	LOG_INF << "Configuration file <" << m_jsonFilePath << ">";
}


Configuration::~Configuration()
{
}

std::shared_ptr<Configuration> Configuration::instance()
{
	return m_instance;
}

void Configuration::instance(std::shared_ptr<Configuration> config)
{
	m_instance = config;
}

std::shared_ptr<Configuration> Configuration::FromJson(const std::string& str)
{
	web::json::value jsonValue;
	try
	{
		jsonValue = web::json::value::parse(GET_STRING_T(str));
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
	auto config = std::make_shared<Configuration>();

	// Global Prameters
	config->m_hostDescription = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_Description);
	config->m_scheduleInterval = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_ScheduleIntervalSeconds);
	config->m_logLevel = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_LogLevel);
	if (config->m_scheduleInterval < 1 || config->m_scheduleInterval > 100)
	{
		// Use default value instead
		config->m_scheduleInterval = DEFAULT_SCHEDULE_INTERVAL;
		LOG_INF << "Default value <" << config->m_scheduleInterval << "> will by used for ScheduleIntervalSec";
	}

	// REST
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_REST))
	{
		config->m_rest = JsonRest::FromJson(jsonValue.at(JSON_KEY_REST));
	}

	// Security
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Security))
	{
		config->m_security = JsonSecurity::FromJson(jsonValue.at(JSON_KEY_Security));
	}
	// Labels	
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Labels))
	{
		config->m_label = Label::FromJson(jsonValue.at(JSON_KEY_Labels));
		// add default label here
		config->m_label->addLabel(DEFAULT_LABLE_HOST_NAME, MY_HOST_NAME);
	}
	// Consul
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_CONSULE))
	{
		config->m_consul = JsonConsul::FromJson(jsonValue.at(JSON_KEY_CONSULE));
	}

	// Applications
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Applications))
	{
		auto& jArr = jsonValue.at(JSON_KEY_Applications).as_array();
		for (auto iterB = jArr.begin(); iterB != jArr.end(); iterB++)
		{
			auto jsonApp = *(iterB);
			auto app = config->parseApp(jsonApp);
			config->addApp2Map(app);
		}
	}

	return config;
}

std::string Configuration::readConfiguration()
{
	std::string jsonPath = Utility::getSelfFullPath() + ".json";
	return Utility::readFileCpp(jsonPath);
}

void SigHupHandler(int signo)
{
	const static char fname[] = "SigHupHandler() ";
	LOG_INF << fname << "Singal :" << signo;
	auto config = Configuration::instance();
	if (config != nullptr)
	{
		try
		{
			config->hotUpdate(web::json::value::parse(Configuration::readConfiguration()));
		}
		catch (const std::exception& e)
		{
			LOG_ERR << fname << e.what();
		}
		catch (...)
		{
			LOG_ERR << fname << "unknown exception";
		}
	}
}

void Configuration::handleReloadSignal()
{
	static ACE_Sig_Action* sig_action = nullptr;
	if (!sig_action)
	{
		sig_action = new ACE_Sig_Action();
		sig_action->handler(SigHupHandler);
		sig_action->register_action(SIGHUP);
	}
}

web::json::value Configuration::AsJson(bool returnRuntimeInfo)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	web::json::value result = web::json::value::object();
	// Applications
	result[JSON_KEY_Applications] = getApplicationJson(false);

	// Global parameters
	result[JSON_KEY_Description] = web::json::value::string(GET_STRING_T(m_hostDescription));
	result[JSON_KEY_ScheduleIntervalSeconds] = web::json::value::number(m_scheduleInterval);
	result[JSON_KEY_LogLevel] = web::json::value::string(GET_STRING_T(m_logLevel));

	// REST
	result[JSON_KEY_REST] = m_rest->AsJson();

	// Labels
	result[JSON_KEY_Labels] = m_label->AsJson();

	// Security
	result[JSON_KEY_Security] = m_security->AsJson(returnRuntimeInfo);

	// Consul
	result[JSON_KEY_CONSULE] = m_consul->AsJson();

	return result;
}

std::vector<std::shared_ptr<Application>> Configuration::getApps()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_apps;
}

void Configuration::addApp2Map(std::shared_ptr<Application> app)
{
	const static char fname[] = "Configuration::addApp2Map() ";

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
	const static char fname[] = "Configuration::getRestListenPort() ";

	static const std::string envStr = ::getenv(ENV_APP_MANAGER_LISTEN_PORT) ? ::getenv(ENV_APP_MANAGER_LISTEN_PORT) : "";
	if (envStr.length())
	{
		static int overrideListenPortValue = 0;
		if (!overrideListenPortValue)
		{
			if (Utility::isNumber(envStr))
			{
				overrideListenPortValue = std::stoi(envStr);
				LOG_INF << fname << ENV_APP_MANAGER_LISTEN_PORT << "=" << overrideListenPortValue;
				return overrideListenPortValue;
			}
			else
			{
				LOG_WAR << fname << ENV_APP_MANAGER_LISTEN_PORT << " is not a number: " << envStr << ", config value will be used";
			}
		}
	}
	return m_rest->m_restListenPort;
}

int Configuration::getPromListenPort()
{
	return m_rest->m_promListenPort;
}

std::string Configuration::getRestListenAddress()
{
	return m_rest->m_restListenAddress;
}

const web::json::value Configuration::getSecureConfigJson()
{
	auto json = this->AsJson(false);
	if (HAS_JSON_FIELD(json, JSON_KEY_Security) && HAS_JSON_FIELD(json.at(JSON_KEY_Security), JSON_KEY_JWT_Users))
	{
		auto& users = json.at(JSON_KEY_Security).at(JSON_KEY_JWT_Users).as_object();
		for (auto& user : users)
		{
			if (HAS_JSON_FIELD(user.second, JSON_KEY_USER_key))
			{
				user.second[JSON_KEY_USER_key] = web::json::value::string(SECURIRE_USER_KEY);
			}
		}
	}

	return std::move(json);
}

web::json::value Configuration::getApplicationJson(bool returnRuntimeInfo)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	std::vector<std::shared_ptr<Application>> apps;
	for (auto app : m_apps)
	{
		// do not persist temp application
		if (returnRuntimeInfo || app->isWorkingState()) apps.push_back(app);
	}
	// Build Json
	auto result = web::json::value::array(apps.size());
	for (size_t i = 0; i < apps.size(); ++i)
	{
		result[i] = apps[i]->AsJson(returnRuntimeInfo);
	}
	return result;
}

void Configuration::disableApp(const std::string& appName)
{
	getApp(appName)->disable();
	saveConfigToDisk();
}
void Configuration::enableApp(const std::string& appName)
{
	auto app = getApp(appName);
	app->enable();
	saveConfigToDisk();
}

const std::string Configuration::getLogLevel() const
{
	return m_logLevel;
}

bool Configuration::getSslEnabled() const
{
	return m_rest->m_ssl->m_sslEnabled;
}

bool Configuration::getEncryptKey()
{
	return getSecurity()->m_encryptKey;
}

std::string Configuration::getSSLCertificateFile() const
{
	return m_rest->m_ssl->m_certFile;
}

std::string Configuration::getSSLCertificateKeyFile() const
{
	return m_rest->m_ssl->m_certKeyFile;
}

bool Configuration::getRestEnabled() const
{
	return m_rest->m_restEnabled;
}

bool Configuration::getJwtEnabled() const
{
	return m_rest->m_restEnabled;
}

const size_t Configuration::getThreadPoolSize() const
{
	return m_rest->m_httpThreadPoolSize;
}

const std::shared_ptr<User> Configuration::getUserInfo(const std::string& userName)
{
	return getSecurity()->m_jwtUsers->getUser(userName);
}

std::set<std::string> Configuration::getUserPermissions(const std::string& userName)
{
	std::set<std::string> permissionSet;
	auto user = getUserInfo(userName);
	for (auto role : user->getRoles())
	{
		for (auto perm : role->getPermissions()) permissionSet.insert(perm);
	}
	return std::move(permissionSet);
}

std::set<std::string> Configuration::getAllPermissions()
{
	std::set<std::string> permissionSet;
	for (auto user : getSecurity()->m_jwtUsers->getUsers())
	{
		for (auto role : user.second->getRoles())
		{
			for (auto perm : role->getPermissions()) permissionSet.insert(perm);
		}
	}
	return std::move(permissionSet);
}

const std::shared_ptr<Users> Configuration::getUsers()
{
	return getSecurity()->m_jwtUsers;
}

const std::shared_ptr<Roles> Configuration::getRoles()
{
	return getSecurity()->m_roles;
}

const std::shared_ptr<Configuration::JsonConsul> Configuration::getConsul() const
{
	return m_consul;
}

const std::shared_ptr<Configuration::JsonSecurity> Configuration::getSecurity()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_security;
}

void Configuration::updateSecurity(std::shared_ptr<Configuration::JsonSecurity> security)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_security = security;
}

void Configuration::dump()
{
	const static char fname[] = "Configuration::dump() ";

	LOG_DBG << fname << '\n' << Utility::prettyJson(this->getSecureConfigJson().serialize());

	auto apps = getApps();
	for (auto app : apps)
	{
		app->dump();
	}
}

std::shared_ptr<Application> Configuration::addApp(const web::json::value& jsonApp)
{
	auto app = parseApp(jsonApp);
	bool update = false;
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	std::for_each(m_apps.begin(), m_apps.end(), [&app, &update](std::shared_ptr<Application>& mapApp)
		{
			if (mapApp->getName() == app->getName())
			{
				// Stop existing app and replace
				mapApp->disable();
				mapApp = app;
				update = true;
				return;
			}
		});

	if (!update)
	{
		// Register app
		addApp2Map(app);
	}
	// Write to disk
	if (app->isWorkingState())
	{
		app->initMetrics(PrometheusRest::instance());
		// invoke immediately
		// TODO: not invoke here, use ACE_Event to trigger main loop
		app->invoke();
		saveConfigToDisk();
	}
	app->dump();
	return std::move(app);
}

void Configuration::removeApp(const std::string& appName)
{
	const static char fname[] = "Configuration::removeApp() ";

	LOG_DBG << fname << appName;

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// Update in-memory app
	for (auto iterA = m_apps.begin(); iterA != m_apps.end();)
	{
		if ((*iterA)->getName() == appName)
		{
			bool needPersist = (*iterA)->isWorkingState();
			(*iterA)->destroy();
			iterA = m_apps.erase(iterA);
			// Write to disk
			if (needPersist) saveConfigToDisk();
			LOG_DBG << fname << "removed " << appName;
		}
		else
		{
			iterA++;
		}
	}
}

void Configuration::saveConfigToDisk()
{
	const static char fname[] = "Configuration::saveConfigToDisk() ";

	auto content = GET_STD_STRING(this->AsJson(false).serialize());
	if (content.length())
	{
		std::lock_guard<std::recursive_mutex> guard(m_mutex);
		auto tmpFile = m_jsonFilePath + "." + std::to_string(Utility::getThreadId());
		std::ofstream ofs(tmpFile, ios::trunc);
		if (ofs.is_open())
		{
			auto formatJson = Utility::prettyJson(content);
			ofs << formatJson;
			ofs.close();
			if (ACE_OS::rename(tmpFile.c_str(), m_jsonFilePath.c_str()) == 0)
			{
				LOG_DBG << fname << '\n' << formatJson;
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

void Configuration::hotUpdate(const web::json::value& config)
{
	const static char fname[] = "Configuration::hotUpdate() ";

	LOG_DBG << fname << "Entered";

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	// not support update [Application] section
	auto jsonValue = config;
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Applications)) jsonValue.erase(GET_STRING_T(JSON_KEY_Applications));

	// parse
	auto newConfig = Configuration::FromJson(GET_STD_STRING(jsonValue.serialize()));

	// update
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Description))
		SET_COMPARE(this->m_hostDescription, newConfig->m_hostDescription);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_LogLevel))
	{
		if (this->m_logLevel != newConfig->m_logLevel)
		{
			Utility::setLogLevel(newConfig->m_logLevel);
			SET_COMPARE(this->m_logLevel, newConfig->m_logLevel);
		}
	}
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_ScheduleIntervalSeconds)) SET_COMPARE(this->m_scheduleInterval, newConfig->m_scheduleInterval);

	// REST
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_REST))
	{
		auto rest = jsonValue.at(JSON_KEY_REST);
		if (HAS_JSON_FIELD(rest, JSON_KEY_RestEnabled)) SET_COMPARE(this->m_rest->m_restEnabled, newConfig->m_rest->m_restEnabled);
		if (HAS_JSON_FIELD(rest, JSON_KEY_RestListenPort)) SET_COMPARE(this->m_rest->m_restListenPort, newConfig->m_rest->m_restListenPort);
		if (HAS_JSON_FIELD(rest, JSON_KEY_RestListenAddress)) SET_COMPARE(this->m_rest->m_restListenAddress, newConfig->m_rest->m_restListenAddress);
		if (HAS_JSON_FIELD(rest, JSON_KEY_HttpThreadPoolSize)) SET_COMPARE(this->m_rest->m_httpThreadPoolSize, newConfig->m_rest->m_httpThreadPoolSize);
		if (HAS_JSON_FIELD(rest, JSON_KEY_PrometheusExporterListenPort) && (this->m_rest->m_promListenPort != newConfig->m_rest->m_promListenPort))
		{
			SET_COMPARE(this->m_rest->m_promListenPort, newConfig->m_rest->m_promListenPort);
			PrometheusRest::instance(nullptr);
			PrometheusRest::instance(std::make_shared<PrometheusRest>(this->getRestListenAddress(), this->getPromListenPort()));
			registerPrometheus();
		}
		// SSL
		if (HAS_JSON_FIELD(rest, JSON_KEY_SSL))
		{
			auto ssl = rest.at(JSON_KEY_SSL);
			if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLCertificateFile)) SET_COMPARE(this->m_rest->m_ssl->m_certFile, newConfig->m_rest->m_ssl->m_certFile);
			if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLCertificateKeyFile)) SET_COMPARE(this->m_rest->m_ssl->m_certKeyFile, newConfig->m_rest->m_ssl->m_certKeyFile);
			if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLEnabled)) SET_COMPARE(this->m_rest->m_ssl->m_sslEnabled, newConfig->m_rest->m_ssl->m_sslEnabled);
		}
	}

	// Security
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Security))
	{
		auto sec = jsonValue.at(JSON_KEY_Security);
		if (HAS_JSON_FIELD(sec, JSON_KEY_JWTEnabled)) SET_COMPARE(this->m_security->m_jwtEnabled, newConfig->m_security->m_jwtEnabled);
		if (HAS_JSON_FIELD(sec, JSON_KEY_JWT_Users)) SET_COMPARE(this->m_security->m_jwtUsers, newConfig->m_security->m_jwtUsers);

		// Roles
		if (HAS_JSON_FIELD(sec, JSON_KEY_Roles)) SET_COMPARE(this->m_security->m_roles, newConfig->m_security->m_roles);
	}

	// Labels
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Labels)) SET_COMPARE(this->m_label, newConfig->m_label);

	// Consul
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_CONSULE))
	{
		SET_COMPARE(this->m_consul, newConfig->m_consul);
		ConsulConnection::instance()->initTimer();
	}

	ResourceCollection::instance()->getHostName(true);

	this->dump();
	ResourceCollection::instance()->dump();
}

void Configuration::registerPrometheus()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	std::for_each(m_apps.begin(), m_apps.end(), [](std::vector<std::shared_ptr<Application>>::reference p)
		{
			p->initMetrics(PrometheusRest::instance());
		});
	for (auto rest : m_restList)
	{
		rest->initMetrics(PrometheusRest::instance());
	}
}

std::shared_ptr<Application> Configuration::parseApp(const web::json::value& jsonApp)
{
	std::shared_ptr<Application> app;

	// check initial application
	if (GET_JSON_BOOL_VALUE(jsonApp, JSON_KEY_APP_initial_application_only) && Utility::stdStringTrim(GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_init_command)).length())
	{
		std::shared_ptr<ApplicationInitialize> initApp(new ApplicationInitialize());
		app = initApp;
		ApplicationInitialize::FromJson(initApp, jsonApp);
		return app;
	}
	// check uninitial application
	if (GET_JSON_BOOL_VALUE(jsonApp, JSON_KEY_APP_onetime_application_only))
	{
		std::shared_ptr<ApplicationUnInitia> oneApp(new ApplicationUnInitia());
		app = oneApp;
		ApplicationUnInitia::FromJson(oneApp, jsonApp);
		return app;
	}

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

std::shared_ptr<Application> Configuration::getApp(const std::string& appName)
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

bool Configuration::isAppExist(const std::string& appName)
{
	std::vector<std::shared_ptr<Application>> apps = getApps();
	for (auto app : apps)
	{
		if (app->getName() == appName)
		{
			return true;
		}
	}
	return false;
}

std::shared_ptr<Configuration::JsonRest> Configuration::JsonRest::FromJson(const web::json::value& jsonValue)
{
	const static char fname[] = "Configuration::JsonRest::FromJson() ";

	auto rest = std::make_shared<JsonRest>();
	rest->m_restListenPort = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_RestListenPort);
	rest->m_restListenAddress = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_RestListenAddress);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_RestEnabled, rest->m_restEnabled);
	SET_JSON_INT_VALUE(jsonValue, JSON_KEY_PrometheusExporterListenPort, rest->m_promListenPort);
	auto threadpool = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_HttpThreadPoolSize);
	if (threadpool > 0 && threadpool < 40)
	{
		rest->m_httpThreadPoolSize = threadpool;
	}
	if (rest->m_restListenPort < 1000 || rest->m_restListenPort > 65534)
	{
		rest->m_restListenPort = DEFAULT_REST_LISTEN_PORT;
		LOG_INF << fname << "Default value <" << rest->m_restListenPort << "> will by used for RestListenPort";
	}
	// SSL
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_SSL))
	{
		rest->m_ssl = JsonSsl::FromJson(jsonValue.at(JSON_KEY_SSL));
	}
	return rest;
}

web::json::value Configuration::JsonRest::AsJson()
{
	auto result = web::json::value::object();
	result[JSON_KEY_RestEnabled] = web::json::value::boolean(m_restEnabled);
	result[JSON_KEY_HttpThreadPoolSize] = web::json::value::number((uint32_t)m_httpThreadPoolSize);
	result[JSON_KEY_RestListenPort] = web::json::value::number(m_restListenPort);
	result[JSON_KEY_PrometheusExporterListenPort] = web::json::value::number(m_promListenPort);
	result[JSON_KEY_RestListenAddress] = web::json::value::string(m_restListenAddress);
	// SSL
	result[JSON_KEY_SSL] = m_ssl->AsJson();
	return result;
}

Configuration::JsonRest::JsonRest()
	:m_restEnabled(false), m_httpThreadPoolSize(DEFAULT_HTTP_THREAD_POOL_SIZE),
	m_restListenPort(DEFAULT_REST_LISTEN_PORT), m_promListenPort(DEFAULT_PROM_LISTEN_PORT)
{
	m_ssl = std::make_shared<JsonSsl>();
}

std::shared_ptr<Configuration::JsonSsl> Configuration::JsonSsl::FromJson(const web::json::value& jsonValue)
{
	auto ssl = std::make_shared<JsonSsl>();
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_SSLEnabled, ssl->m_sslEnabled);
	ssl->m_certFile = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLCertificateFile);
	ssl->m_certKeyFile = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLCertificateKeyFile);
	if (ssl->m_sslEnabled && !Utility::isFileExist(ssl->m_certFile))
	{
		throw std::invalid_argument("SSLCertificateFile not exist");
	}
	if (ssl->m_sslEnabled && !Utility::isFileExist(ssl->m_certKeyFile))
	{
		throw std::invalid_argument("SSLCertificateKeyFile not exist");
	}
	return ssl;
}

web::json::value Configuration::JsonSsl::AsJson()
{
	auto result = web::json::value::object();
	result[JSON_KEY_SSLEnabled] = web::json::value::boolean(m_sslEnabled);
	result[JSON_KEY_SSLCertificateFile] = web::json::value::string(m_certFile);
	result[JSON_KEY_SSLCertificateKeyFile] = web::json::value::string(m_certKeyFile);
	return result;
}

Configuration::JsonSsl::JsonSsl()
	:m_sslEnabled(false)
{
}

std::shared_ptr<Configuration::JsonSecurity> Configuration::JsonSecurity::FromJson(const web::json::value& jsonValue)
{
	auto security = std::make_shared<Configuration::JsonSecurity>();
	// Roles
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Roles)) security->m_roles = Roles::FromJson(jsonValue.at(JSON_KEY_Roles));
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_JWTEnabled, security->m_jwtEnabled);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_SECURITY_EncryptKey, security->m_encryptKey);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_JWT_Users)) security->m_jwtUsers = Users::FromJson(jsonValue.at(JSON_KEY_JWT_Users), security->m_roles);
	return security;
}

web::json::value Configuration::JsonSecurity::AsJson(bool returnRuntimeInfo)
{
	auto result = web::json::value::object();
	result[JSON_KEY_JWTEnabled] = web::json::value::boolean(m_jwtEnabled);
	result[JSON_KEY_SECURITY_EncryptKey] = web::json::value::boolean(m_encryptKey);
	if (!returnRuntimeInfo)
	{
		result[JSON_KEY_JWT_Users] = m_jwtUsers->AsJson();
	}
	//Roles
	result[JSON_KEY_Roles] = m_roles->AsJson();
	return result;
}

Configuration::JsonSecurity::JsonSecurity()
	:m_jwtEnabled(true), m_encryptKey(false)
{
	m_roles = std::make_shared<Roles>();
	m_jwtUsers = std::make_shared<Users>();
}

std::shared_ptr<Configuration::JsonConsul> Configuration::JsonConsul::FromJson(const web::json::value& jobj)
{
	auto consul = std::make_shared<JsonConsul>();
	consul->m_consulUrl = GET_JSON_STR_VALUE(jobj, JSON_KEY_CONSULE_URL);
	consul->m_datacenter = GET_JSON_STR_VALUE(jobj, JSON_KEY_CONSULE_DATACENTER);
	consul->m_isMaster = GET_JSON_BOOL_VALUE(jobj, JSON_KEY_CONSULE_IS_MASTER);
	consul->m_isNode = GET_JSON_BOOL_VALUE(jobj, JSON_KEY_CONSULE_IS_NODE);
	SET_JSON_INT_VALUE(jobj, JSON_KEY_CONSULE_SESSION_TTL, consul->m_ttl);
	SET_JSON_INT_VALUE(jobj, JSON_KEY_CONSULE_REPORT_INTERVAL, consul->m_reportInterval);
	SET_JSON_INT_VALUE(jobj, JSON_KEY_CONSULE_SCHEDULE_INTERVAL, consul->m_scheduleInterval);
	SET_JSON_INT_VALUE(jobj, JSON_KEY_CONSUL_SECURITY_INTERVAL, consul->m_securitySyncInterval);
	const static boost::regex urlExrp("(http|https)://((\\w+\\.)*\\w+)(\\:[0-9]+)?");
	if (consul->m_consulUrl.length() && !boost::regex_match(consul->m_consulUrl, urlExrp))
	{
		throw std::invalid_argument("consul URL is not correct");
	}
	return consul;
}

web::json::value Configuration::JsonConsul::AsJson()
{
	auto result = web::json::value::object();
	result[JSON_KEY_CONSULE_URL] = web::json::value::string(m_consulUrl);
	result[JSON_KEY_CONSULE_DATACENTER] = web::json::value::string(m_datacenter);
	result[JSON_KEY_CONSULE_IS_MASTER] = web::json::value::boolean(m_isMaster);
	result[JSON_KEY_CONSULE_IS_NODE] = web::json::value::boolean(m_isNode);
	result[JSON_KEY_CONSULE_SESSION_TTL] = web::json::value::number(m_ttl);
	result[JSON_KEY_CONSULE_REPORT_INTERVAL] = web::json::value::number(m_reportInterval);
	result[JSON_KEY_CONSULE_SCHEDULE_INTERVAL] = web::json::value::number(m_scheduleInterval);
	result[JSON_KEY_CONSUL_SECURITY_INTERVAL] = web::json::value::number(m_securitySyncInterval);
	return result;
}

bool Configuration::JsonConsul::consulEnabled() const
{
	return !m_consulUrl.empty();
}

bool Configuration::JsonConsul::consulSecurityEnabled() const
{
	return !m_consulUrl.empty() && m_securitySyncInterval > 0;
}

Configuration::JsonConsul::JsonConsul()
	:m_isMaster(false), m_isNode(false), m_ttl(CONSUL_SESSION_DEFAULT_TTL), 
	m_reportInterval(CONSUL_REPORT_DEFAULT_INTERVAL), m_scheduleInterval(CONSUL_TOPOLOGY_DEFAULT_INTERVAL),
	m_securitySyncInterval(CONSUL_SECURITY_SYNC_DEFAULT_INTERVAL)
{
}
