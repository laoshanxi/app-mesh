#include <set>
#if !defined(WIN32)
#include <unistd.h> //environ
#endif

#include <ace/Signal.h>
#include <boost/algorithm/string_regex.hpp>
#include <boost/filesystem.hpp>
#include <nlohmann/json.hpp>

#include "Configuration.h"
#include "Label.h"
#include "ResourceCollection.h"
#include "application/Application.h"
#include "rest/PrometheusRest.h"
#include "rest/RestHandler.h"
#include "security/HMACVerifier.h"
#include "security/Security.h"
#include "security/User.h"

#include "../common/DateTime.h"
#include "../common/DurationParse.h"
#include "../common/Utility.h"
#if !defined(WIN32)
#include "../common/os/pstree.hpp"
#endif

extern char **environ; // unistd.h

std::shared_ptr<Configuration> Configuration::m_instance = nullptr;
Configuration::Configuration()
{
	m_baseConfig = std::make_shared<BaseConfig>();
	m_label = std::make_unique<Label>();
	m_rest = std::make_shared<JsonRest>();
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

std::shared_ptr<Configuration> Configuration::FromJson(nlohmann::json &jsonValue, bool applyEnv)
{
	try
	{
		if (applyEnv)
		{
			Configuration::overrideConfigWithEnv(jsonValue);
		}
	}
	catch (const std::exception &e)
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

	// Base config
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_BaseConfig))
	{
		config->m_baseConfig = BaseConfig::FromJson(jsonValue.at(JSON_KEY_BaseConfig));
	}

	// REST
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_REST))
	{
		config->m_rest = JsonRest::FromJson(jsonValue.at(JSON_KEY_REST));
	}

	// Labels
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Labels))
	{
		config->m_label = Label::FromJson(jsonValue.at(JSON_KEY_Labels));
		// add default label here
		config->m_label->readDefaultLabel();
	}

	return config;
}

std::string Configuration::readConfiguration()
{
	return Utility::readFileCpp(Utility::getConfigFilePath(APPMESH_CONFIG_YAML_FILE));
}

void SigHupHandler(int signo)
{
	const static char fname[] = "SigHupHandler() ";

	LOG_INF << fname << "Handle singal :" << signo;
	auto config = Configuration::instance();
	if (config != nullptr)
	{
		try
		{
			auto configJson = Utility::yamlToJson(YAML::Load(Configuration::readConfiguration()));
			config->hotUpdate(configJson);
		}
		catch (const std::exception &e)
		{
			LOG_ERR << fname << e.what();
		}
		catch (...)
		{
			LOG_ERR << fname << "unknown exception";
		}
	}
}

void Configuration::handleSignal()
{
	static ACE_Sig_Action *sig_action = nullptr;
	if (!sig_action)
	{
		sig_action = new ACE_Sig_Action();
		sig_action->handler(SigHupHandler);
		sig_action->register_action(SIGHUP);
	}

	static ACE_Sig_Action *sig_pipe = nullptr;
	if (!sig_pipe)
	{
		sig_pipe = new ACE_Sig_Action((ACE_SignalHandler)SIG_IGN);
		sig_pipe->register_action(SIGPIPE, 0);
	}
}

nlohmann::json Configuration::AsJson()
{
	nlohmann::json result = nlohmann::json::object();

	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);

	// base config
	result[JSON_KEY_BaseConfig] = m_baseConfig->AsJson();

	// REST
	result[JSON_KEY_REST] = m_rest->AsJson();

	// Labels
	result[JSON_KEY_Labels] = m_label->AsJson();

	// Build version
	result[JSON_KEY_VERSION] = std::string(__MICRO_VAR__(BUILD_TAG));

	return result;
}

std::vector<std::shared_ptr<Application>> Configuration::getApps() const
{
	std::vector<std::shared_ptr<Application>> apps;
	apps.reserve(m_apps.current_size());

	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_apps.mutex());
	for (const auto &entry : m_apps)
	{
		apps.push_back(entry.int_id_);
	}
	return apps;
}

void Configuration::addApp2Map(std::shared_ptr<Application> app)
{
	const static char fname[] = "Configuration::addApp2Map() ";
	if (m_apps.bind(app->getName(), app) == 1)
	{
		LOG_ERR << fname << "Application <" << app->getName() << "> already exist.";
	}
}

int Configuration::getScheduleInterval()
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_baseConfig->m_scheduleInterval;
}

int Configuration::getRestListenPort()
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_restListenPort;
}

int Configuration::getPromListenPort() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_promListenPort;
}

std::string Configuration::getRestListenAddress()
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_restListenAddress;
}

std::string Configuration::getRestJwtIssuer()
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_jwt->m_jwtIssuer.empty() ? MY_HOST_NAME : m_rest->m_jwt->m_jwtIssuer;
}

int Configuration::getRestTcpPort()
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_restTcpPort;
}

nlohmann::json Configuration::serializeApplication(bool returnRuntimeInfo, const std::string &user, bool returnUnPersistApp) const
{
	auto allApp = getApps();
	std::vector<std::shared_ptr<Application>> apps;
	std::copy_if(allApp.begin(), allApp.end(), std::back_inserter(apps),
				 [this, &user, returnUnPersistApp](std::shared_ptr<Application> app)
				 {
					 return (checkOwnerPermission(user, app->getOwner(), app->getOwnerPermission(), false) && // access permission check
							 ((returnUnPersistApp) || (!returnUnPersistApp && app->isPersistAble())) &&		  // status filter
							 (app->getName() != SEPARATE_AGENT_APP_NAME));									  // not expose rest process
				 });

	auto result = nlohmann::json::array();
	// Build Json
	if (returnRuntimeInfo)
	{
#if defined(WIN32)
		void *ptree = nullptr;
#else
		std::list<os::Process> ptree = os::processes();
#endif
		for (std::size_t i = 0; i < apps.size(); ++i)
		{
			result.push_back(apps[i]->AsJson(returnRuntimeInfo, (void *)(&ptree)));
		}
	}
	else
	{
		for (std::size_t i = 0; i < apps.size(); ++i)
		{
			result[i] = apps[i]->AsJson(returnRuntimeInfo);
		}
	}

	return result;
}

void Configuration::loadApps(const boost::filesystem::path &appDir)
{
	const static char fname[] = "Configuration::loadApps() ";

	if (fs::exists(appDir) && fs::is_directory(appDir))
	{
		// parse YAML format
		for (const auto &jsonFile : fs::directory_iterator(appDir))
		{
			auto path = jsonFile.path().string();
			if (Utility::isFileExist(path) && (Utility::endWith(path, ".yml") || Utility::endWith(path, ".yaml")))
			{
				LOG_INF << fname << "loading <" << path << ">.";
				try
				{
					auto app = this->parseApp(Utility::yamlToJson(YAML::LoadFile(path)));
					this->addApp2Map(app);
				}
				catch (const std::exception &e)
				{
					LOG_ERR << fname << "Failed load application file <" << path << ">, error :" << e.what();
				}
			}
		}
		// parse JSON format
		for (const auto &jsonFile : fs::directory_iterator(appDir))
		{
			auto path = jsonFile.path().filename().string();
			if (Utility::isFileExist(path) && Utility::endWith(path, ".json"))
			{
				LOG_INF << fname << "loading <" << path << ">.";
				auto app = this->parseApp(nlohmann::json::parse(std::ifstream(path)));
				this->addApp2Map(app);
			}
		}
	}
	else
	{
		Utility::createDirectory(appDir.string());
	}
}

void Configuration::disableApp(const std::string &appName)
{
	getApp(appName)->disable();
}
void Configuration::enableApp(const std::string &appName)
{
	auto app = getApp(appName);
	app->enable();
}

const std::string Configuration::getLogLevel() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_baseConfig->m_logLevel;
}

const std::string Configuration::getDefaultExecUser() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_baseConfig->m_defaultExecUser;
}

bool Configuration::getDisableExecUser() const
{
	return m_baseConfig->m_disableExecUser;
}

const std::string Configuration::getWorkDir() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	if (m_baseConfig->m_defaultWorkDir.length())
		return m_baseConfig->m_defaultWorkDir;
	else
		return (fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR).string();
}

bool Configuration::getSslVerifyClient() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_ssl->m_sslVerifyClient;
}

std::string Configuration::getSSLCertificateFile() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_ssl->m_certFile;
}

std::string Configuration::getSSLCertificateKeyFile() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_ssl->m_certKeyFile;
}

std::string Configuration::getSSLCaPath() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_ssl->m_sslCaPath;
}

bool Configuration::getRestEnabled() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_restEnabled;
}

std::size_t Configuration::getThreadPoolSize() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_httpThreadPoolSize;
}

const std::string Configuration::getDescription() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_baseConfig->m_hostDescription;
}

const std::string Configuration::getPosixTimezone() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_baseConfig->m_posixTimezone;
}

const std::shared_ptr<Configuration::JsonJwt> Configuration::getJwt() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_jwt;
}

bool Configuration::checkOwnerPermission(const std::string &user, const std::shared_ptr<User> &appOwner, int appPermission, bool requestWrite) const
{
	// if app has not defined user, return true
	// if same user, return true
	// if not defined permission, return true
	// if no session user which is internal call, return true
	// if user is admin, return true
	if (user.empty() || appOwner == nullptr || user == appOwner->getName() || appPermission == 0 || user == JWT_ADMIN_NAME)
	{
		return true;
	}

	auto userObj = Security::instance()->getUserInfo(user);
	if (userObj->getGroup() == appOwner->getGroup())
	{
		auto groupPerm = appPermission / 1 % 10;
		if (groupPerm <= static_cast<int>(PERMISSION::GROUP_DENY))
			return false;
		if (!requestWrite &&
			(groupPerm == static_cast<int>(PERMISSION::GROUP_READ) ||
			 groupPerm == static_cast<int>(PERMISSION::GROUP_WRITE)))
		{
			return true;
		}
		if (requestWrite && groupPerm == static_cast<int>(PERMISSION::GROUP_WRITE))
			return true;
	}
	else
	{
		auto otherPerm = 10 * (appPermission / 10 % 10);
		if (otherPerm <= static_cast<int>(PERMISSION::OTHER_DENY))
			return false;
		if (!requestWrite &&
			(otherPerm == static_cast<int>(PERMISSION::OTHER_READ) ||
			 otherPerm == static_cast<int>(PERMISSION::OTHER_WRITE)))
		{
			return true;
		}
		if (requestWrite && otherPerm == static_cast<int>(PERMISSION::OTHER_WRITE))
			return true;
	}
	return false;
}

void Configuration::dump()
{
	const static char fname[] = "Configuration::dump() ";

	LOG_DBG << fname << '\n'
			<< Utility::prettyJson(this->AsJson().dump());

	auto apps = getApps();
	for (auto &app : apps)
	{
		app->dump();
	}
}

std::shared_ptr<Application> Configuration::addApp(const nlohmann::json &jsonApp, std::shared_ptr<Application> fromApp, bool persistable)
{
	auto app = parseApp(jsonApp);
	std::shared_ptr<Application> oldApp = getApp(app->getName(), false);
	if (oldApp)
	{
		if (app->getName() == SEPARATE_AGENT_APP_NAME)
		{
			throw std::invalid_argument("not permited");
		}
		oldApp->destroy();
		oldApp.reset();
	}
	m_apps.rebind(app->getName(), app, oldApp);

	// Write to disk
	if (!persistable)
	{
		app->setUnPersistable();
	}
	if (fromApp)
	{
		app->initMetrics(fromApp);
	}
	else
	{
		app->initMetrics();
	}

	// invoke immediately
	app->execute();
	app->dump();
	return app;
}

void Configuration::removeApp(const std::string &appName)
{
	const static char fname[] = "Configuration::removeApp() ";

	LOG_DBG << fname << appName;
	std::shared_ptr<Application> app, empty;
	{
		// TODO: workaround to release memory immediately in case of
		// ACE_Map_Manager manage shared_ptr (might be ACE_HAS_LAZY_MAP_MANAGER)
		ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_apps.mutex());
		m_apps.rebind(appName, empty, app);
		m_apps.unbind(appName);
	}
	if (app)
	{
		// Write to disk
		app->destroy();
		app->remove();
		LOG_DBG << fname << "removed " << appName;
	}
	m_appNameIndexMap.unbind(appName);
}

void Configuration::saveConfigToDisk()
{
	const static char fname[] = "Configuration::saveConfigToDisk() ";

	auto content = this->AsJson();
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	const auto configFilePath = Utility::getConfigFilePath(APPMESH_CONFIG_YAML_FILE, true);
	auto tmpFile = configFilePath + "." + std::to_string(Utility::getThreadId());
	if (Utility::runningInContainer())
	{
		tmpFile = configFilePath;
	}
	std::ofstream ofs(tmpFile, ios::trunc);
	if (ofs.is_open())
	{
		auto formatJson = Utility::jsonToYaml(content);
		ofs << formatJson;
		ofs.close();
		if (tmpFile != configFilePath)
		{
			if (ACE_OS::rename(tmpFile.c_str(), configFilePath.c_str()) == 0)
			{
				LOG_INF << fname << "saving config file to disk <" << configFilePath << ">";
			}
			else
			{
				LOG_ERR << fname << "Failed to write configuration file <" << configFilePath << ">, error :" << std::strerror(errno);
			}
		}
	}

	LOG_DBG << fname;
}

void Configuration::hotUpdate(nlohmann::json &jsonValue)
{
	const static char fname[] = "Configuration::hotUpdate() ";

	LOG_DBG << fname << "update configuration: " << jsonValue.dump();
	{
		std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);

		// parse
		auto newConfig = Configuration::FromJson(jsonValue);

		// Base config
		if (HAS_JSON_FIELD(jsonValue, JSON_KEY_BaseConfig))
		{
			auto baseConfig = jsonValue.at(JSON_KEY_BaseConfig);
			if (HAS_JSON_FIELD(baseConfig, JSON_KEY_Description))
				SET_COMPARE(this->m_baseConfig->m_hostDescription, newConfig->m_baseConfig->m_hostDescription);
			if (HAS_JSON_FIELD(baseConfig, JSON_KEY_LogLevel))
			{
				if (this->m_baseConfig->m_logLevel != newConfig->m_baseConfig->m_logLevel)
				{
					Utility::setLogLevel(newConfig->m_baseConfig->m_logLevel);
					SET_COMPARE(this->m_baseConfig->m_logLevel, newConfig->m_baseConfig->m_logLevel);
				}
			}

			if (HAS_JSON_FIELD(baseConfig, JSON_KEY_ScheduleIntervalSeconds))
				SET_COMPARE(this->m_baseConfig->m_scheduleInterval, newConfig->m_baseConfig->m_scheduleInterval);
			if (HAS_JSON_FIELD(baseConfig, JSON_KEY_DefaultExecUser))
				SET_COMPARE(this->m_baseConfig->m_defaultExecUser, newConfig->m_baseConfig->m_defaultExecUser);
			if (HAS_JSON_FIELD(baseConfig, JSON_KEY_DisableExecUser))
				SET_COMPARE(this->m_baseConfig->m_disableExecUser, newConfig->m_baseConfig->m_disableExecUser);
			if (HAS_JSON_FIELD(baseConfig, JSON_KEY_WorkingDirectory))
				SET_COMPARE(this->m_baseConfig->m_defaultWorkDir, newConfig->m_baseConfig->m_defaultWorkDir);
		}

		// REST
		if (HAS_JSON_FIELD(jsonValue, JSON_KEY_REST))
		{
			auto rest = jsonValue.at(JSON_KEY_REST);
			if (HAS_JSON_FIELD(rest, JSON_KEY_RestEnabled))
				SET_COMPARE(this->m_rest->m_restEnabled, newConfig->m_rest->m_restEnabled);
			if (HAS_JSON_FIELD(rest, JSON_KEY_RestListenPort))
				SET_COMPARE(this->m_rest->m_restListenPort, newConfig->m_rest->m_restListenPort);
			if (HAS_JSON_FIELD(rest, JSON_KEY_RestTcpPort))
				SET_COMPARE(this->m_rest->m_restTcpPort, newConfig->m_rest->m_restTcpPort);
			if (HAS_JSON_FIELD(rest, JSON_KEY_RestListenAddress))
				SET_COMPARE(this->m_rest->m_restListenAddress, newConfig->m_rest->m_restListenAddress);
			if (HAS_JSON_FIELD(rest, JSON_KEY_HttpThreadPoolSize))
				SET_COMPARE(this->m_rest->m_httpThreadPoolSize, newConfig->m_rest->m_httpThreadPoolSize);
			if (HAS_JSON_FIELD(rest, JSON_KEY_PrometheusExporterListenPort) && (this->m_rest->m_promListenPort != newConfig->m_rest->m_promListenPort))
			{
				SET_COMPARE(this->m_rest->m_promListenPort, newConfig->m_rest->m_promListenPort);
			}
			// SSL
			if (HAS_JSON_FIELD(rest, JSON_KEY_SSL))
			{
				auto ssl = rest.at(JSON_KEY_SSL);
				if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLCertificateFile))
					SET_COMPARE(this->m_rest->m_ssl->m_certFile, newConfig->m_rest->m_ssl->m_certFile);
				if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLCertificateKeyFile))
					SET_COMPARE(this->m_rest->m_ssl->m_certKeyFile, newConfig->m_rest->m_ssl->m_certKeyFile);
				if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLClientCertificateFile))
					SET_COMPARE(this->m_rest->m_ssl->m_clientCertFile, newConfig->m_rest->m_ssl->m_clientCertFile);
				if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLClientCertificateKeyFile))
					SET_COMPARE(this->m_rest->m_ssl->m_clientCertKeyFile, newConfig->m_rest->m_ssl->m_clientCertKeyFile);
				if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLCaPath))
					SET_COMPARE(this->m_rest->m_ssl->m_sslCaPath, newConfig->m_rest->m_ssl->m_sslCaPath);
				if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLVerifyServer))
					SET_COMPARE(this->m_rest->m_ssl->m_sslVerifyServer, newConfig->m_rest->m_ssl->m_sslVerifyServer);
				if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLVerifyServerDelegate))
					SET_COMPARE(this->m_rest->m_ssl->m_sslVerifyServerDelegate, newConfig->m_rest->m_ssl->m_sslVerifyServerDelegate);
				if (HAS_JSON_FIELD(ssl, JSON_KEY_SSLVerifyClient))
					SET_COMPARE(this->m_rest->m_ssl->m_sslVerifyClient, newConfig->m_rest->m_ssl->m_sslVerifyClient);
			}

			// JWT
			if (HAS_JSON_FIELD(rest, JSON_KEY_JWT))
			{
				auto sec = rest.at(JSON_KEY_JWT);
				if (HAS_JSON_FIELD(sec, JSON_KEY_JWTSalt))
					SET_COMPARE(this->m_rest->m_jwt->m_jwtSalt, newConfig->m_rest->m_jwt->m_jwtSalt);
				if (HAS_JSON_FIELD(sec, JSON_KEY_JWTAlgorithm))
					SET_COMPARE(this->m_rest->m_jwt->m_jwtAlgorithm, newConfig->m_rest->m_jwt->m_jwtAlgorithm);
				if (HAS_JSON_FIELD(sec, JSON_KEY_JWTIssuer))
					SET_COMPARE(this->m_rest->m_jwt->m_jwtIssuer, newConfig->m_rest->m_jwt->m_jwtIssuer);
				if (HAS_JSON_FIELD(sec, JSON_KEY_JWTAudience))
					SET_COMPARE(this->m_rest->m_jwt->m_jwtAudience, newConfig->m_rest->m_jwt->m_jwtAudience);
				if (HAS_JSON_FIELD(sec, JSON_KEY_SECURITY_Interface))
					SET_COMPARE(this->m_rest->m_jwt->m_jwtInterface, newConfig->m_rest->m_jwt->m_jwtInterface);
			}
		}

		// Labels
		if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Labels))
			SET_COMPARE(this->m_label, newConfig->m_label);
	}

	ResourceCollection::instance()->getHostName(true);

	this->dump();
	ResourceCollection::instance()->dump();
}

bool Configuration::overrideConfigWithEnv(nlohmann::json &jsonConfig)
{
	const static char fname[] = "Configuration::overrideConfigWithEnv() ";
	LOG_INF << fname;
	// environment "APPMESH_LogLevel=INFO" can override main configuration
	// environment "APPMESH_Security_JWTEnabled=false" can override Security configuration
	bool applyConfig = false;
	for (char **var = environ; *var != nullptr; var++)
	{
		std::string env = *var;
		auto pos = env.find('=');
		if (Utility::startWith(env, ENV_APPMESH_PREFIX) && (pos != std::string::npos))
		{
			auto envKey = env.substr(0, pos);
			auto envVal = env.substr(pos + 1);
			auto keys = Utility::splitString(envKey, "_");
			nlohmann::json *json = &jsonConfig;
			for (size_t i = 1; i < keys.size(); i++)
			{
				auto jsonKey = keys[i];
				if (json->contains(jsonKey))
				{
					// find the last level
					if (i == (keys.size() - 1))
					{
						// override json value
						if (applyEnvConfig(json->at(jsonKey), envVal))
						{
							applyConfig = true;
							LOG_INF << fname << "Configuration: " << envKey << " apply environment value " << Utility::maskSecret(envVal);
						}
						else
						{
							LOG_WAR << fname << "Configuration: " << envKey << " apply environment value failed";
						}
					}
					else
					{
						// switch to next level
						json = &(json->at(jsonKey));
					}
				}
			}
		}
	}
	return applyConfig;
}
bool Configuration::applyEnvConfig(nlohmann::json &jsonValue, std::string envValue)
{
	const static char fname[] = "Configuration::applyEnvConfig() ";

	if (jsonValue.is_string())
	{
		jsonValue = std::string(envValue);
		return true;
	}
	else if (jsonValue.is_number())
	{
		jsonValue = (std::stoi(envValue));
		return true;
	}
	else if (jsonValue.is_boolean())
	{
		if (Utility::isNumber(envValue))
		{
			jsonValue = (std::stoi(envValue) > 0);
			return true;
		}
		else
		{
			jsonValue = (envValue == "true");
			return true;
		}
	}
	else
	{
		LOG_WAR << fname << "JSON value type not supported: " << jsonValue.dump();
	}
	return false;
}

void Configuration::registerPrometheus()
{
	auto allApp = getApps();
	for (const auto &app : allApp)
		app->initMetrics();
}

bool Configuration::prometheusEnabled() const
{
	return getRestEnabled() && getPromListenPort() > 1024;
}

std::shared_ptr<Application> Configuration::parseApp(const nlohmann::json &jsonApp)
{
	auto app = std::make_shared<Application>();
	Application::FromJson(app, jsonApp);
	return app;
}

std::shared_ptr<Application> Configuration::getApp(const std::string &appName, bool throwOnNotFound) const
{
	const static char fname[] = "Configuration::getApp() ";
	std::shared_ptr<Application> app;
	if (m_apps.find(appName, app) == 0 && app)
		return app;

	if (throwOnNotFound)
	{
		LOG_WAR << fname << "No such application: " << appName;
		throw NotFoundException("No such application");
	}
	return nullptr;
}

std::shared_ptr<Application> Configuration::getApp(const void *app) const
{
	ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_apps.mutex());
	for (const auto &entry : m_apps)
	{
		if (app == entry.int_id_.get())
			return entry.int_id_;
	}
	return nullptr;
}

bool Configuration::isAppExist(const std::string &appName)
{
	return (m_apps.find(appName) == 0);
}

std::string Configuration::generateRunAppName(const std::string &provideAppName)
{
	if (provideAppName.empty())
	{
		return Utility::createUUID();
	}
	else
	{
		int appIndex = 1;
		ACE_Guard<ACE_Recursive_Thread_Mutex> guard(m_appNameIndexMap.mutex());
		if (m_appNameIndexMap.find(provideAppName, appIndex) == 0)
		{
			appIndex++;
		}
		while (true)
		{
			auto newName = provideAppName + "_" + std::to_string(appIndex);
			if (isAppExist(newName))
				appIndex++;
			else
				break;
		}
		m_appNameIndexMap.rebind(provideAppName, appIndex);
		return provideAppName + "_" + std::to_string(appIndex);
	}
}

const nlohmann::json Configuration::getAgentAppJson(const std::string &shmName) const
{
	const static char fname[] = "Configuration::getAgentAppJson() ";

#if defined(WIN32)
	auto cmd = (fs::path(Utility::getBinDir()) / "agent.exe").string();
#else
	auto cmd = (fs::path(Utility::getBinDir()) / "agent").string();
#endif

	LOG_INF << fname << " agent start command <" << cmd << ">";

	nlohmann::json restApp;
	restApp[JSON_KEY_APP_name] = std::string(SEPARATE_AGENT_APP_NAME);
	restApp[JSON_KEY_APP_command] = std::move(cmd);
	restApp[JSON_KEY_APP_description] = std::string("REST agent for App Mesh");
	restApp[JSON_KEY_APP_owner_permission] = (11);
	restApp[JSON_KEY_APP_owner] = std::string(JWT_ADMIN_NAME);
	restApp[JSON_KEY_APP_stdout_cache_num] = (3);

	auto objBehavior = nlohmann::json::object();
	objBehavior[JSON_KEY_APP_behavior_exit] = std::string(AppBehavior::action2str(AppBehavior::Action::RESTART));
	restApp[JSON_KEY_APP_behavior] = std::move(objBehavior);

	nlohmann::json objEnvs = nlohmann::json::object();
	objEnvs[ENV_PSK_SHM] = shmName;
	restApp[JSON_KEY_APP_env] = std::move(objEnvs);

	return restApp;
}

std::shared_ptr<Configuration::JsonRest> Configuration::JsonRest::FromJson(const nlohmann::json &jsonValue)
{
	const static char fname[] = "Configuration::JsonRest::FromJson() ";

	auto rest = std::make_shared<JsonRest>();
	rest->m_restListenPort = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_RestListenPort);
	rest->m_restListenAddress = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_RestListenAddress);
	rest->m_restTcpPort = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_RestTcpPort);
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
		LOG_DBG << fname << "Default value <" << rest->m_restListenPort << "> will by used for RestListenPort";
	}
	if (!Utility::isFileExist("/var/run/docker.sock"))
	{
		LOG_INF << fname << "Docker not installed or started, will not start docker agent.";
	}
	// SSL
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_SSL))
	{
		rest->m_ssl = JsonSsl::FromJson(jsonValue.at(JSON_KEY_SSL));
	}
	// JWT
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_JWT))
	{
		rest->m_jwt = JsonJwt::FromJson(jsonValue.at(JSON_KEY_JWT));
	}
	return rest;
}

Configuration::BaseConfig::BaseConfig()
	: m_scheduleInterval(DEFAULT_SCHEDULE_INTERVAL), m_disableExecUser(false)
{
}

std::shared_ptr<Configuration::BaseConfig> Configuration::BaseConfig::FromJson(const nlohmann::json &jsonValue)
{
	auto config = std::make_shared<BaseConfig>();
	config->m_hostDescription = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_Description);
	config->m_defaultExecUser = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_DefaultExecUser);
	config->m_disableExecUser = GET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_DisableExecUser);
	config->m_defaultWorkDir = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_WorkingDirectory);
	config->m_scheduleInterval = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_ScheduleIntervalSeconds);
	config->m_logLevel = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_LogLevel);
	config->m_posixTimezone = GET_JSON_STR_INT_TEXT(jsonValue, JSON_KEY_PosixTimezone);

#if !defined(WIN32)
	unsigned int gid, uid;
	if (!config->m_defaultExecUser.empty() && !Utility::getUid(config->m_defaultExecUser, uid, gid))
	{
		LOG_ERR << "No such OS user: " << config->m_defaultExecUser;
		throw std::invalid_argument("No such OS user for default execution");
	}
#endif
	if (config->m_scheduleInterval < 1 || config->m_scheduleInterval > 100)
	{
		// Use default value instead
		config->m_scheduleInterval = DEFAULT_SCHEDULE_INTERVAL;
		LOG_INF << "Default value <" << config->m_scheduleInterval << "> will by used for ScheduleIntervalSec";
	}
	return config;
}

nlohmann::json Configuration::BaseConfig::AsJson() const
{
	auto result = nlohmann::json::object();
	result[JSON_KEY_Description] = std::string(m_hostDescription);
	result[JSON_KEY_DefaultExecUser] = std::string(m_defaultExecUser);
	result[JSON_KEY_DisableExecUser] = (m_disableExecUser);
	result[JSON_KEY_WorkingDirectory] = std::string(m_defaultWorkDir);
	result[JSON_KEY_ScheduleIntervalSeconds] = (m_scheduleInterval);
	result[JSON_KEY_LogLevel] = std::string(m_logLevel);
	result[JSON_KEY_PosixTimezone] = std::string(m_posixTimezone);
	return result;
}

nlohmann::json Configuration::JsonRest::AsJson() const
{
	auto result = nlohmann::json::object();
	result[JSON_KEY_RestEnabled] = (m_restEnabled);
	result[JSON_KEY_HttpThreadPoolSize] = ((uint32_t)m_httpThreadPoolSize);
	result[JSON_KEY_RestListenPort] = (m_restListenPort);
	result[JSON_KEY_PrometheusExporterListenPort] = (m_promListenPort);
	result[JSON_KEY_RestListenAddress] = std::string(m_restListenAddress);
	result[JSON_KEY_RestTcpPort] = (m_restTcpPort);
	// SSL
	result[JSON_KEY_SSL] = m_ssl->AsJson();

	// JWT
	result[JSON_KEY_JWT] = m_jwt->AsJson();
	return result;
}

Configuration::JsonRest::JsonRest()
	: m_restEnabled(false), m_httpThreadPoolSize(DEFAULT_HTTP_THREAD_POOL_SIZE),
	  m_restListenPort(DEFAULT_REST_LISTEN_PORT), m_promListenPort(DEFAULT_PROM_LISTEN_PORT),
	  m_restTcpPort(DEFAULT_TCP_REST_LISTEN_PORT)
{
	m_ssl = std::make_shared<JsonSsl>();
	m_jwt = std::make_shared<JsonJwt>();
}

std::shared_ptr<Configuration::JsonSsl> Configuration::JsonSsl::FromJson(const nlohmann::json &jsonValue)
{
	auto ssl = std::make_shared<JsonSsl>();
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_SSLVerifyServer, ssl->m_sslVerifyServer);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_SSLVerifyServerDelegate, ssl->m_sslVerifyServerDelegate);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_SSLVerifyClient, ssl->m_sslVerifyClient);
	ssl->m_certFile = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLCertificateFile);
	ssl->m_certKeyFile = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLCertificateKeyFile);
	ssl->m_clientCertFile = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLClientCertificateFile);
	ssl->m_clientCertKeyFile = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLClientCertificateKeyFile);
	ssl->m_sslCaPath = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_SSLCaPath);
	return ssl;
}

nlohmann::json Configuration::JsonSsl::AsJson() const
{
	auto result = nlohmann::json::object();
	result[JSON_KEY_SSLVerifyServer] = (m_sslVerifyServer);
	result[JSON_KEY_SSLVerifyServerDelegate] = (m_sslVerifyServerDelegate);
	result[JSON_KEY_SSLVerifyClient] = (m_sslVerifyClient);
	result[JSON_KEY_SSLCertificateFile] = std::string(m_certFile);
	result[JSON_KEY_SSLCertificateKeyFile] = std::string(m_certKeyFile);
	result[JSON_KEY_SSLClientCertificateFile] = std::string(m_clientCertFile);
	result[JSON_KEY_SSLClientCertificateKeyFile] = std::string(m_clientCertKeyFile);
	result[JSON_KEY_SSLCaPath] = std::string(m_sslCaPath);
	return result;
}

Configuration::JsonSsl::JsonSsl()
	: m_sslVerifyServer(false), m_sslVerifyServerDelegate(false), m_sslVerifyClient(false)
{
}

Configuration::JsonJwt::JsonJwt()
{
}

std::shared_ptr<Configuration::JsonJwt> Configuration::JsonJwt::FromJson(const nlohmann::json &jsonObj)
{
	auto security = std::make_shared<Configuration::JsonJwt>();
	security->m_jwtSalt = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWTSalt);
	security->m_jwtAlgorithm = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWTAlgorithm);
	if (security->m_jwtAlgorithm.empty())
	{
		security->m_jwtAlgorithm = APPMESH_JWT_ALGORITHM_HS256;
	}
	else if (security->m_jwtAlgorithm != APPMESH_JWT_ALGORITHM_HS256 && security->m_jwtAlgorithm != APPMESH_JWT_ALGORITHM_RS256 && security->m_jwtAlgorithm != APPMESH_JWT_ALGORITHM_ES256)
	{
		throw std::invalid_argument("Invalid JWT Algorithm");
	}
	security->m_jwtIssuer = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_JWTIssuer);
	if (HAS_JSON_FIELD(jsonObj, JSON_KEY_JWTAudience))
	{
		for (const auto &value : jsonObj[JSON_KEY_JWTAudience])
		{
			if (!value.is_string())
				throw std::invalid_argument("Invalid JWT Audience type");
			security->m_jwtAudience.insert(value.get<std::string>());
		}
	}

	// Add default audience
	if (security->m_jwtAudience.empty())
	{
		security->m_jwtAudience.insert(HTTP_HEADER_JWT_Audience_appmesh);
	}

	security->m_jwtInterface = GET_JSON_STR_VALUE(jsonObj, JSON_KEY_SECURITY_Interface);
	return security;
}

nlohmann::json Configuration::JsonJwt::AsJson() const
{
	auto result = nlohmann::json::object();
	result[JSON_KEY_JWTSalt] = std::string(m_jwtSalt);
	result[JSON_KEY_JWTAlgorithm] = std::string(m_jwtAlgorithm);
	result[JSON_KEY_JWTIssuer] = Configuration::instance()->getRestJwtIssuer();
	result[JSON_KEY_JWTAudience] = m_jwtAudience;
	result[JSON_KEY_SECURITY_Interface] = std::string(m_jwtInterface);
	return result;
}

std::string Configuration::JsonJwt::getJwtInterface() const
{
	return m_jwtInterface;
}
