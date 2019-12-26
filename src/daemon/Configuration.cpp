#include <ace/Signal.h>
#include <pplx/threadpool.h>
#include "Configuration.h"
#include "../common/Utility.h"
#include "ApplicationPeriodRun.h"
#include "ResourceCollection.h"
#include "PrometheusRest.h"

std::shared_ptr<Configuration> Configuration::m_instance = nullptr;
Configuration::Configuration()
	:m_threadPoolSize(6), m_scheduleInterval(0), m_restListenPort(DEFAULT_REST_LISTEN_PORT),
	m_promListenPort(DEFAULT_PROM_LISTEN_PORT),	m_sslEnabled(false), m_restEnabled(true), m_jwtEnabled(true)
{
	m_jsonFilePath = Utility::getSelfFullPath() + ".json";
	m_label = std::make_unique<Label>();
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
	catch (const std::exception & e)
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
	config->m_hostDescription = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_Description);
	config->m_scheduleInterval = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_ScheduleIntervalSeconds);
	config->m_restListenPort = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_RestListenPort);
	config->m_RestListenAddress = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_RestListenAddress);
	config->m_logLevel = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_LogLevel);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_SSLEnabled, config->m_sslEnabled);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_RestEnabled, config->m_restEnabled);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_JWTEnabled, config->m_jwtEnabled);
	config->m_sslCertificateFile = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLCertificateFile);
	config->m_sslCertificateKeyFile = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLCertificateKeyFile);
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
	SET_JSON_INT_VALUE(jsonValue, JSON_KEY_PrometheusExporterListenPort, config->m_promListenPort);
	auto threadpool = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_HttpThreadPoolSize);
	if (threadpool > 0 && threadpool < 40)
	{
		config->m_threadPoolSize = threadpool;
	}
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Labels)) config->m_label = Label::FromJson(jsonValue.at(JSON_KEY_Labels));

	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Roles))	config->m_roles = Roles::FromJson(jsonValue.at(JSON_KEY_Roles));
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_JWT)) config->m_jwtUsers = Users::FromJson(jsonValue.at(JSON_KEY_JWT), config->m_roles);

	config->m_JwtRedirectUrl = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_JWTRedirectUrl);

	static bool initialized = false;
	if (!initialized)
	{
		initialized = true;
		// Thread pool: 6 threads
		crossplat::threadpool::initialize_with_threads(config->getThreadPoolSize());
		// Init Prometheus Exporter
		PrometheusRest::instance(std::make_shared<PrometheusRest>(config->getRestListenAddress(), config->getPromListenPort()));
	}

	// Leave application init at last, application init depend on Prometheus
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Applications))
	{
		auto& jArr = jsonValue.at(JSON_KEY_Applications).as_array();
		for (auto iterB = jArr.begin(); iterB != jArr.end(); iterB++)
		{
			auto jsonApp = *(iterB);
			auto app = config->parseApp(jsonApp);
			app->dump();
			config->registerApp(app);
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
		catch (const std::exception & e)
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
	static ACE_Sig_Action* sig_action = NULL;
	if (!sig_action)
	{
		sig_action = new ACE_Sig_Action();
		sig_action->handler(SigHupHandler);
		sig_action->register_action(SIGHUP);
	}
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
	result[JSON_KEY_PrometheusExporterListenPort] = web::json::value::number(m_promListenPort);
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
		result[JSON_KEY_JWT] = m_jwtUsers->AsJson();
		result[JSON_KEY_Roles] = m_roles->AsJson();
	}

	result[JSON_KEY_Applications] = apps;
	result[JSON_KEY_Labels] = getLabel()->AsJson();
	result[JSON_KEY_JWTRedirectUrl] = web::json::value::string(GET_STRING_T(m_JwtRedirectUrl));

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
			}
			else
			{
				overrideListenPortValue = m_restListenPort;
				LOG_WAR << fname << ENV_APP_MANAGER_LISTEN_PORT << " is not a number: " << envStr << ", config value will be used: " << m_restListenPort;
			}
		}
		return overrideListenPortValue;
	}
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

const utility::string_t Configuration::getSecureConfigContentStr()
{
	auto json = this->AsJson(false);
	if (HAS_JSON_FIELD(json, JSON_KEY_JWT))
	{
		auto& jwtObj = json.at(JSON_KEY_JWT).as_object();
		for (auto& user : jwtObj)
		{
			if (HAS_JSON_FIELD(user.second, JSON_KEY_USER_key))
			{
				user.second[JSON_KEY_USER_key] = web::json::value::string("*****");
			}
		}
	}

	return json.serialize();
}

web::json::value Configuration::getApplicationJson(bool returnRuntimeInfo)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	std::vector<std::shared_ptr<Application>> apps;
	for (auto app : m_apps)
	{
		// do not persist temp application
		if (returnRuntimeInfo || !app->isUnAvialable()) apps.push_back(app);
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

const std::shared_ptr<User> Configuration::getUserInfo(const std::string& userName)
{
	return m_jwtUsers->getUser(userName);
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

const std::string& Configuration::getJwtRedirectUrl()
{
	return m_JwtRedirectUrl;
}

void Configuration::dump()
{
	const static char fname[] = "Configuration::dump() ";

	LOG_DBG << fname << '\n' << Utility::prettyJson(this->getSecureConfigContentStr());

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
			}
		});

	if (!update)
	{
		// Register app
		registerApp(app);
	}
	// Write to disk
	if (!app->isUnAvialable()) saveConfigToDisk();

	return app;
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
			bool tempApp = (*iterA)->isUnAvialable();
			(*iterA)->destroy();
			iterA = m_apps.erase(iterA);
			// Write to disk
			if (!tempApp) saveConfigToDisk();
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

	auto content = GET_STD_STRING(this->getConfigContentStr());
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

void Configuration::hotUpdate(const web::json::value& config, bool updateBasicConfig)
{
	const static char fname[] = "Configuration::hotUpdate() ";

	LOG_DBG << fname << "Entered";

	// not support update [Application] section
	auto jsonValue = config;
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Applications)) jsonValue.erase(GET_STRING_T(JSON_KEY_Applications));

	// parse
	auto newConfig = Configuration::FromJson(GET_STD_STRING(jsonValue.serialize()));

	// update
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Description)) SET_COMPARE(this->m_hostDescription, newConfig->m_hostDescription);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_RestListenPort)) SET_COMPARE(this->m_restListenPort, newConfig->m_restListenPort);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_RestListenAddress)) SET_COMPARE(this->m_RestListenAddress, newConfig->m_RestListenAddress);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_JWTEnabled)) SET_COMPARE(this->m_jwtEnabled, newConfig->m_jwtEnabled);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_HttpThreadPoolSize)) SET_COMPARE(this->m_threadPoolSize, newConfig->m_threadPoolSize);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_PrometheusExporterListenPort) && (this->m_promListenPort != newConfig->m_promListenPort))
	{
		SET_COMPARE(this->m_promListenPort, newConfig->m_promListenPort);
		PrometheusRest::instance(nullptr);
		PrometheusRest::instance(std::make_shared<PrometheusRest>(this->getRestListenAddress(), this->getPromListenPort()));
	}
	if (!updateBasicConfig)
	{
		if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Roles)) SET_COMPARE(this->m_roles, newConfig->m_roles);
		if (HAS_JSON_FIELD(jsonValue, JSON_KEY_JWT)) SET_COMPARE(this->m_jwtUsers, newConfig->m_jwtUsers);
		if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Labels)) SET_COMPARE(this->m_label, newConfig->m_label);
		ResourceCollection::instance()->getHostName(true);
	}
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_RestEnabled)) SET_COMPARE(this->m_restEnabled, newConfig->m_restEnabled);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_LogLevel))
	{
		if (this->m_logLevel != newConfig->m_logLevel)
		{
			Utility::setLogLevel(newConfig->m_logLevel);
			SET_COMPARE(this->m_logLevel, newConfig->m_logLevel);
		}
	}
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_ScheduleIntervalSeconds)) SET_COMPARE(this->m_scheduleInterval, newConfig->m_scheduleInterval);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_SSLCertificateFile)) SET_COMPARE(this->m_sslCertificateFile, newConfig->m_sslCertificateFile);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_SSLCertificateKeyFile)) SET_COMPARE(this->m_sslCertificateKeyFile, newConfig->m_sslCertificateKeyFile);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_SSLEnabled)) SET_COMPARE(this->m_sslEnabled, newConfig->m_sslEnabled);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_JWTRedirectUrl)) SET_COMPARE(this->m_JwtRedirectUrl, newConfig->m_JwtRedirectUrl);

	this->dump();
	ResourceCollection::instance()->dump();
}

std::shared_ptr<Application> Configuration::parseApp(const web::json::value& jsonApp)
{
	const static char fname[] = "Configuration::parseApp() ";

	LOG_DBG << fname << "Json Object:\n" << Utility::prettyJson(jsonApp.serialize());

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
