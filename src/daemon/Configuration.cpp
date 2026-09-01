// src/daemon/Configuration.cpp
#include <exception>
#include <set>
#if !defined(_WIN32)
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
#include "rest/EventDispatcher.h"
#include "rest/PrometheusRest.h"
#include "rest/RestHandler.h"
#include "security/HMACVerifier.h"
#include "security/Security.h"

#include "../common/DateTime.h"
#include "../common/DurationParse.h"
#include "../common/Utility.h"
#include "../common/os/filesystem.h"
#include "../common/os/pstree.h"

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
	if (config)
	{
		std::lock_guard<std::recursive_mutex> guard(config->m_hotupdateMutex);
		config->m_runtimePrometheusEnabled = config->m_rest->m_restEnabled && config->m_rest->m_promListenPort > 1024;
	}
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
		LOG_ERR << "Failed to apply environment overrides to configuration with error <" << e.what() << ">";
		throw std::invalid_argument("Failed to parse configuration file, please check json configuration file format");
	}
	catch (...)
	{
		LOG_ERR << "Failed to apply environment overrides to configuration with error <unknown exception>";
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

	LOG_INF << fname << "Received signal <" << signo << ">, reloading configuration";
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
			LOG_ERR << fname << "Failed to reload configuration: " << e.what();
		}
		catch (...)
		{
			LOG_ERR << fname << "Failed to reload configuration with unknown exception";
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
		LOG_ERR << fname << "Application <" << app->getName() << "> already exists";
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

int Configuration::getRestTcpPort()
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_restTcpPort;
}

int Configuration::getWebSocketPort()
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_webSocketPort;
}

nlohmann::json Configuration::serializeApplication(bool returnRuntimeInfo, const std::string &user, bool returnUnPersistApp) const
{
	auto allApp = getApps();
	std::vector<std::shared_ptr<Application>> apps;
	std::copy_if(allApp.begin(), allApp.end(), std::back_inserter(apps),
				 [this, &user, returnUnPersistApp](std::shared_ptr<Application> app)
				 {
					 return (checkOwnerPermission(user, app->getOwnerPrincipalId(), app->getOwnerPermission(), false) && // access permission check
							 ((returnUnPersistApp) || (!returnUnPersistApp && app->isPersistAble())) &&		  // status filter
							 (app->getName() != SEPARATE_AGENT_APP_NAME));									  // not expose rest process
				 });

	auto result = nlohmann::json::array();
	// Build Json
	if (returnRuntimeInfo)
	{
		std::vector<pid_t> roots;
		for (const auto &app : apps)
		{
			const auto pid = app->getpid();
			if (pid > 1)
				roots.push_back(pid);
		}
		std::list<os::Process> ptree;
		if (!roots.empty())
			ptree = os::processes(roots);
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
	std::vector<std::string> failedDefinitions;

	if (fs::exists(appDir) && fs::is_directory(appDir))
	{
		// parse YAML format
		for (const auto &jsonFile : fs::directory_iterator(appDir))
		{
			auto path = jsonFile.path().string();
			if (Utility::isFileExist(path) && (Utility::endWith(path, ".yml") || Utility::endWith(path, ".yaml")))
			{
				LOG_INF << fname << "Loading application file <" << path << ">";
				try
				{
					auto jsonObj = Utility::yamlToJson(YAML::LoadFile(path));
					jsonObj[JSON_KEY_APP_from_recover] = true;
					auto app = this->parseApp(jsonObj);
					this->addApp2Map(app);
				}
				catch (const std::exception &e)
				{
					LOG_ERR << fname << "Failed to load application file <" << path << ">, error: " << e.what();
					failedDefinitions.push_back(path);
				}
			}
		}
		// parse JSON format
		for (const auto &jsonFile : fs::directory_iterator(appDir))
		{
			auto path = jsonFile.path().string();
			if (Utility::isFileExist(path) && Utility::endWith(path, ".json"))
			{
				LOG_INF << fname << "Loading application file <" << path << ">";
				try
				{
					auto jsonObj = nlohmann::json::parse(std::ifstream(path));
					jsonObj[JSON_KEY_APP_from_recover] = true;
					auto app = this->parseApp(jsonObj);
					this->addApp2Map(app);
				}
				catch (const std::exception &e)
				{
					LOG_ERR << fname << "Failed to load application file <" << path << ">, error: " << e.what();
					failedDefinitions.push_back(path);
				}
			}
		}
		if (!failedDefinitions.empty())
		{
			throw std::runtime_error(Utility::stringFormat(
				"refusing partial application recovery: %zu definition(s) failed validation; "
				"correct or explicitly migrate the files reported above before restarting",
				failedDefinitions.size()));
		}
	}
	else
	{
		Utility::createDirectory(appDir.string());
	}
}

void Configuration::disableApp(const std::string &appName)
{
	std::lock_guard<std::recursive_mutex> mutationGuard(m_appMutationMutex);
	auto app = getApp(appName);
	if (app->isSystemProtected())
		throw AuthorizationException("system applications cannot be disabled through the application API");
	app->disable();
	app->save();
}
void Configuration::enableApp(const std::string &appName)
{
	std::lock_guard<std::recursive_mutex> mutationGuard(m_appMutationMutex);
	auto app = getApp(appName);
	if (app->isSystemProtected())
		throw AuthorizationException("system applications cannot be changed through the application API");
	app->enable();
	app->save();
}

std::unique_lock<std::recursive_mutex> Configuration::lockAppMutation() const
{
	return std::unique_lock<std::recursive_mutex>(m_appMutationMutex);
}

bool Configuration::isCurrentApp(const std::string &appName, const std::shared_ptr<Application> &expected) const
{
	return getApp(appName, false) == expected;
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
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
#if !defined(_WIN32)
	return m_baseConfig->m_disableExecUser || os::get_uid() != 0;
#else
	return m_baseConfig->m_disableExecUser;
#endif
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

bool Configuration::getSslVerifyServer() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_ssl->m_sslVerifyServer;
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

bool Configuration::getCorsDisabled() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_corsDisabled;
}

std::set<std::string> Configuration::getCsrfAllowedOrigins() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_csrfAllowedOrigins;
}

std::string Configuration::getFileAllowedBaseDir() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_fileAllowedBaseDir;
}

std::size_t Configuration::getWorkerThreadPoolSize() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_workerThreadPoolSize;
}

std::size_t Configuration::getIOThreadPoolSize() const
{
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	return m_rest->m_IOThreadPoolSize;
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

bool Configuration::checkOwnerPermission(const std::string &principalId, const std::string &ownerPrincipalId,
	int appPermission, bool requestWrite) const
{
	if (principalId.empty() || ownerPrincipalId.empty() || principalId == ownerPrincipalId || appPermission == 0)
	{
		return true;
	}

	// Explicit management permissions bypass the owner/other share bits:
	// <app-manage-all> covers every operation, <app-view-all> only read access.
	// Principals that are not provisioned (e.g. the synthetic workflow controller
	// identity) get no bypass and fall through to the share bits below.
	try
	{
		const auto granted = Security::instance()->permissions(principalId);
		if (granted.count(PERMISSION_KEY_app_manage_all) != 0)
			return true;
		if (!requestWrite && granted.count(PERMISSION_KEY_view_all_app) != 0)
			return true;
	}
	catch (const std::exception &)
	{
	}

	const auto otherPerm = 10 * (appPermission / 10 % 10);
	if (otherPerm <= static_cast<int>(PERMISSION::OTHER_DENY))
		return false;
	if (!requestWrite &&
		(otherPerm == static_cast<int>(PERMISSION::OTHER_READ) ||
		 otherPerm == static_cast<int>(PERMISSION::OTHER_WRITE)))
	{
		return true;
	}
	return requestWrite && otherPerm == static_cast<int>(PERMISSION::OTHER_WRITE);
}

void Configuration::dump()
{
	const static char fname[] = "Configuration::dump() ";

	auto configJson = this->AsJson();
	LOG_DBG << fname << '\n'
			<< configJson.dump(2);

	auto apps = getApps();
	for (auto &app : apps)
	{
		app->dump();
	}
}

std::shared_ptr<Application> Configuration::addApp(const nlohmann::json &jsonApp, bool persistable)
{
	std::lock_guard<std::recursive_mutex> mutationGuard(m_appMutationMutex);
	auto app = parseApp(jsonApp);
	// Re-check the immutable owner binding while holding the same mutation lock
	// used by Principal deletion. A request authenticated just before an
	// administrator tombstones that Principal must not create a newly orphaned
	// application after the deletion commits.
	Security::instance()->principal(app->getOwnerPrincipalId());
	std::shared_ptr<Application> oldApp = getApp(app->getName(), false);
	if (persistable && app->isSystemProtected())
		throw AuthorizationException("system applications can only be loaded from the installed apps directory");
	if (oldApp && oldApp->isSystemProtected())
		throw AuthorizationException("system applications cannot be replaced through the application API");
	if (oldApp)
	{
		if (!persistable)
			throw std::invalid_argument("on-demand application name is already in use");
		if (app->getName() == SEPARATE_AGENT_APP_NAME)
		{
			throw std::invalid_argument("not permited");
		}
	}

	if (!persistable)
	{
		app->setUnPersistable();
	}
	else
	{
		// Persist the candidate first so a write failure does not destroy the current app.
		app->save();
	}
	if (oldApp)
	{
		oldApp->destroy();
		app->initMetrics(oldApp);
	}
	else
	{
		app->initMetrics();
	}
	m_apps.rebind(app->getName(), app, oldApp);

	// invoke immediately
	app->execute();
	app->dump();
	return app;
}

void Configuration::removeApp(const std::string &appName, const Application *expected)
{
	const static char fname[] = "Configuration::removeApp() ";
	std::lock_guard<std::recursive_mutex> mutationGuard(m_appMutationMutex);
	if (expected != nullptr && getApp(appName, false).get() != expected)
	{
		LOG_DBG << fname << "Ignoring stale remove for application <" << appName << ">";
		return;
	}
	auto current = getApp(appName, false);
	if (current && current->isSystemProtected())
		throw AuthorizationException("system applications cannot be removed through the application API");

	EventDispatcher::instance()->dispatch(appName, AppEventType::APP_REMOVED, {});

	LOG_DBG << fname << "Removing application <" << appName << ">";
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
		app->clearMetrics();
		app->remove();
		LOG_DBG << fname << "Removed application <" << appName << ">";
	}
	m_appNameIndexMap.unbind(appName);
	EventDispatcher::instance()->removeByApp(appName);
}

void Configuration::saveConfigToDisk()
{
	const static char fname[] = "Configuration::saveConfigToDisk() ";

	// Hold the lock around AsJson() too, so concurrent hotUpdate() can't
	// snapshot a torn config mid-write.
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	auto content = this->AsJson();
	// Atomic replacement also supports readable root-owned files in a writable directory.
	const auto yamlContent = Utility::jsonToYaml(content);
	const auto configFilePath = Utility::getConfigFilePath(APPMESH_CONFIG_YAML_FILE, true);
	uint16_t mode = 0644;
#if !defined(_WIN32)
	if (Utility::isFileExist(configFilePath))
	{
		const int existingMode = std::get<0>(os::fileStat(configFilePath));
		if (existingMode >= 0)
			mode = static_cast<uint16_t>(existingMode);
	}
#endif
	const auto tmpFile = os::createTmpFile(configFilePath, yamlContent, mode);
	if (tmpFile.empty())
	{
		const auto error = Utility::stringFormat(
			"Failed to create temporary configuration file beside <%s>",
			configFilePath.c_str());
		LOG_ERR << fname << error;
		throw std::runtime_error(error);
	}

	if (ACE_OS::rename(tmpFile.c_str(), configFilePath.c_str()) != 0)
	{
		const auto error = Utility::stringFormat(
			"Failed to replace configuration file <%s>: %s",
			configFilePath.c_str(), last_error_msg());
		Utility::removeFile(tmpFile);
		LOG_ERR << fname << error;
		throw std::runtime_error(error);
	}

	LOG_INF << fname << "Saved configuration file to disk <" << configFilePath << ">";
}

void Configuration::hotUpdateAndSave(nlohmann::json &jsonValue)
{
	const static char fname[] = "Configuration::hotUpdateAndSave() ";
	std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);
	const auto previousConfig = this->AsJson();

	this->hotUpdate(jsonValue);
	try
	{
		this->saveConfigToDisk();
	}
	catch (...)
	{
		const auto writeFailure = std::current_exception();
		try
		{
			auto rollbackConfig = previousConfig;
			this->hotUpdate(rollbackConfig);
			LOG_WAR << fname << "Rolled back runtime configuration after persistence failure";
		}
		catch (const std::exception &e)
		{
			LOG_ERR << fname << "Failed to roll back runtime configuration: " << e.what();
		}
		catch (...)
		{
			LOG_ERR << fname << "Failed to roll back runtime configuration with unknown error";
		}
		std::rethrow_exception(writeFailure);
	}
}

void Configuration::hotUpdate(nlohmann::json &jsonValue)
{
	const static char fname[] = "Configuration::hotUpdate() ";

	LOG_DBG << fname << "Applying configuration hot-update";
	{
		std::lock_guard<std::recursive_mutex> guard(m_hotupdateMutex);

		// Reapply environment overrides after merging the patch.
		auto effectiveJson = this->AsJson();
		effectiveJson.merge_patch(jsonValue);
		auto newConfig = Configuration::FromJson(effectiveJson, true);
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
			if (HAS_JSON_FIELD(rest, JSON_KEY_CorsDisabled))
				SET_COMPARE(this->m_rest->m_corsDisabled, newConfig->m_rest->m_corsDisabled);
			if (HAS_JSON_FIELD(rest, JSON_KEY_CsrfAllowedOrigins))
				SET_COMPARE(this->m_rest->m_csrfAllowedOrigins, newConfig->m_rest->m_csrfAllowedOrigins);
			if (HAS_JSON_FIELD(rest, JSON_KEY_FileAllowedBaseDir))
				SET_COMPARE(this->m_rest->m_fileAllowedBaseDir, newConfig->m_rest->m_fileAllowedBaseDir);
			if (HAS_JSON_FIELD(rest, JSON_KEY_RestListenPort))
				SET_COMPARE(this->m_rest->m_restListenPort, newConfig->m_rest->m_restListenPort);
			if (HAS_JSON_FIELD(rest, JSON_KEY_PrometheusExporterListenPort))
				SET_COMPARE(this->m_rest->m_promListenPort, newConfig->m_rest->m_promListenPort);
			if (HAS_JSON_FIELD(rest, JSON_KEY_RestTcpPort))
				SET_COMPARE(this->m_rest->m_restTcpPort, newConfig->m_rest->m_restTcpPort);
			if (HAS_JSON_FIELD(rest, JSON_KEY_WebSocketPort))
				SET_COMPARE(this->m_rest->m_webSocketPort, newConfig->m_rest->m_webSocketPort);
			if (HAS_JSON_FIELD(rest, JSON_KEY_RestListenAddress))
				SET_COMPARE(this->m_rest->m_restListenAddress, newConfig->m_rest->m_restListenAddress);
			if (HAS_JSON_FIELD(rest, JSON_KEY_WorkerThreadPoolSize))
				SET_COMPARE(this->m_rest->m_workerThreadPoolSize, newConfig->m_rest->m_workerThreadPoolSize);
			if (HAS_JSON_FIELD(rest, JSON_KEY_IOThreadPoolSize))
				SET_COMPARE(this->m_rest->m_IOThreadPoolSize, newConfig->m_rest->m_IOThreadPoolSize);
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

		}

		// Labels
		if (HAS_JSON_FIELD(jsonValue, JSON_KEY_Labels))
			SET_COMPARE(this->m_label, newConfig->m_label);
	}

	this->dump();
}

bool Configuration::overrideConfigWithEnv(nlohmann::json &jsonConfig)
{
	const static char fname[] = "Configuration::overrideConfigWithEnv() ";
	LOG_INF << fname << "Applying environment variable overrides to configuration";
	// environment "APPMESH_LogLevel=INFO" can override main configuration
	// Nested keys in config.yaml can be overridden with APPMESH_<section>_<key>.
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
							LOG_INF << fname << "Configuration <" << envKey << "> overridden with environment value <" << Utility::maskSecret(envVal) << ">";
						}
						else
						{
							LOG_WAR << fname << "Failed to apply environment value for configuration <" << envKey << ">";
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
	else if (jsonValue.is_array())
	{
		// Comma-separated env value maps to a string array (e.g. APPMESH_REST_CsrfAllowedOrigins="a,b").
		auto arr = nlohmann::json::array();
		for (const auto &item : Utility::splitString(envValue, ","))
			arr.push_back(item);
		jsonValue = std::move(arr);
		return true;
	}
	else
	{
		LOG_WAR << fname << "JSON value type not supported: " << jsonValue.type_name();
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
	return m_runtimePrometheusEnabled;
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
		LOG_WAR << fname << "No such application <" << appName << ">";
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
		return Utility::shortID();
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

#if defined(_WIN32)
	auto cmd = (fs::path(Utility::getBinDir()) / "agent.exe").string();
#else
	auto cmd = (fs::path(Utility::getBinDir()) / "agent").string();
#endif

	LOG_INF << fname << "Agent start command <" << cmd << ">";

	nlohmann::json restApp;
	restApp[JSON_KEY_APP_name] = std::string(SEPARATE_AGENT_APP_NAME);
	restApp[JSON_KEY_APP_command] = std::move(cmd);
	restApp[JSON_KEY_APP_description] = std::string("REST agent for App Mesh");
	restApp[JSON_KEY_APP_owner_permission] = (11);
	restApp[JSON_KEY_APP_owner_principal_id] = AuthorizationStore::systemPrincipalId();
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
	rest->m_webSocketPort = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_WebSocketPort);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_RestEnabled, rest->m_restEnabled);
	SET_JSON_BOOL_VALUE(jsonValue, JSON_KEY_CorsDisabled, rest->m_corsDisabled);
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_CsrfAllowedOrigins) && jsonValue.at(JSON_KEY_CsrfAllowedOrigins).is_array())
	{
		for (const auto &origin : jsonValue.at(JSON_KEY_CsrfAllowedOrigins))
		{
			if (origin.is_string() && !origin.get<std::string>().empty())
				rest->m_csrfAllowedOrigins.insert(origin.get<std::string>());
		}
	}
	rest->m_fileAllowedBaseDir = GET_JSON_STR_VALUE(jsonValue, JSON_KEY_FileAllowedBaseDir);
	SET_JSON_INT_VALUE(jsonValue, JSON_KEY_PrometheusExporterListenPort, rest->m_promListenPort);
	auto threadpool = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_WorkerThreadPoolSize);
	if (threadpool > 0 && threadpool < 100)
	{
		rest->m_workerThreadPoolSize = threadpool;
	}
	auto iotThreadpool = GET_JSON_INT_VALUE(jsonValue, JSON_KEY_IOThreadPoolSize);
	if (iotThreadpool > 0 && iotThreadpool < 100)
	{
		rest->m_IOThreadPoolSize = iotThreadpool;
	}
	if (rest->m_restListenPort < 1000 || rest->m_restListenPort > 65534)
	{
		rest->m_restListenPort = DEFAULT_REST_LISTEN_PORT;
		LOG_DBG << fname << "Default value <" << rest->m_restListenPort << "> will be used for RestListenPort";
	}
	if (!Utility::isFileExist("/var/run/docker.sock"))
	{
		LOG_INF << fname << "Docker not installed or not running, will not start docker agent";
	}
	// SSL
	if (HAS_JSON_FIELD(jsonValue, JSON_KEY_SSL))
	{
		rest->m_ssl = JsonSsl::FromJson(jsonValue.at(JSON_KEY_SSL));
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

#if !defined(_WIN32)
	if (!config->m_disableExecUser && os::get_uid() == 0 && !config->m_defaultExecUser.empty())
	{
		unsigned int gid, uid;
		if (!os::getUidByName(config->m_defaultExecUser, uid, gid))
		{
			LOG_ERR << "No such OS user <" << config->m_defaultExecUser << ">";
			throw std::invalid_argument("No such OS user for default execution");
		}
	}
	if (!config->m_disableExecUser && os::get_uid() != 0)
	{
		LOG_WAR << "Daemon is not running as root, user switching (exec_user/DefaultExecUser) is disabled at runtime";
	}
#endif
	if (config->m_scheduleInterval < 1 || config->m_scheduleInterval > 100)
	{
		// Use default value instead
		config->m_scheduleInterval = DEFAULT_SCHEDULE_INTERVAL;
		LOG_INF << "Default value <" << config->m_scheduleInterval << "> will be used for ScheduleIntervalSeconds";
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
	result[JSON_KEY_WorkerThreadPoolSize] = ((uint32_t)m_workerThreadPoolSize);
	result[JSON_KEY_IOThreadPoolSize] = ((uint32_t)m_IOThreadPoolSize);
	result[JSON_KEY_RestListenPort] = (m_restListenPort);
	result[JSON_KEY_PrometheusExporterListenPort] = (m_promListenPort);
	result[JSON_KEY_RestListenAddress] = std::string(m_restListenAddress);
	result[JSON_KEY_RestTcpPort] = (m_restTcpPort);
	result[JSON_KEY_WebSocketPort] = (m_webSocketPort);
	result[JSON_KEY_CorsDisabled] = (m_corsDisabled);
	result[JSON_KEY_CsrfAllowedOrigins] = m_csrfAllowedOrigins;
	result[JSON_KEY_FileAllowedBaseDir] = std::string(m_fileAllowedBaseDir);
	// SSL
	result[JSON_KEY_SSL] = m_ssl->AsJson();

	return result;
}

Configuration::JsonRest::JsonRest()
	: m_restEnabled(false), m_corsDisabled(false), m_workerThreadPoolSize(DEFAULT_WORKER_THREAD_POOL_SIZE),
	  m_IOThreadPoolSize(DEFAULT_IO_THREAD_POOL_SIZE),
	  m_restListenPort(DEFAULT_REST_LISTEN_PORT), m_promListenPort(DEFAULT_PROM_LISTEN_PORT),
	  m_restTcpPort(DEFAULT_TCP_REST_LISTEN_PORT), m_webSocketPort(0)
{
	m_ssl = std::make_shared<JsonSsl>();
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
