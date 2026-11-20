// src/daemon/rest/RestHandler.cpp
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <set>

#include <boost/algorithm/string_regex.hpp>

#include "../../common/DurationParse.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.h"
#include "../Configuration.h"
#include "../Label.h"
#include "../ResourceCollection.h"
#include "../application/Application.h"
#include "../process/DockerApiProcess.h"
#include "../security/AuthReplicationTokens.h"
#include "../security/HMACVerifier.h"
#include "../security/InternalCapability.h"
#include "../security/SecretProtector.h"
#include "../security/Security.h"
#include "../security/VaultClient.h"
#include "EventDispatcher.h"
#include "HttpRequest.h"
#include "PrometheusRest.h"
#include "ReplyContext.h"
#include "RestHandler.h"
#include "SseSink.h"
#include "drogon/FileTransferHandler.h"

// Content-type constants
constexpr auto CONTENT_TYPE_HTML = "text/html; charset=utf-8";
constexpr auto CONTENT_TYPE_YAML = "application/x-yaml";
constexpr auto CONTENT_TYPE_SVG = "image/svg+xml";
constexpr auto CONTENT_TYPE_PNG = "image/png";

namespace
{

	// Shared path gate for both file endpoints; the jail and the daemon-tree
	// exclusion live in Utility::validateFilePath so every transport applies them.
	bool rejectFilePath(const std::shared_ptr<HttpRequest> &message, const std::string &file)
	{
		if (!Utility::validateFilePath(file, Configuration::instance()->getFileAllowedBaseDir()))
		{
			message->reply(web::http::status_codes::Forbidden, Utility::text2json("File path is not allowed"));
			return true;
		}
		return false;
	}

	// Serialize a permission set as a JSON string array
	Json::Value toJsonArray(const std::set<std::string> &values)
	{
		Json::Value array(Json::arrayValue);
		for (const auto &value : values)
			array.append(value);
		return array;
	}

	// Keep immutable ownership and mutable presentation separate. This field is
	// added only to API responses; persistence and authorization continue to use
	// owner_principal_id exclusively.
	void addOwnerDisplayName(Json::Value &application)
	{
		if (!application.isObject())
			return;
		const auto ownerPrincipalId = GET_JSON_STR_VALUE(application, JSON_KEY_APP_owner_principal_id);
		if (ownerPrincipalId.empty())
			return;
		if (ownerPrincipalId == AuthorizationStore::systemPrincipalId())
		{
			application[JSON_KEY_APP_owner_display_name] = "system";
			return;
		}

		try
		{
			const auto principal = Security::instance()->principal(ownerPrincipalId)->asJson();
			const auto displayName = GET_JSON_STR_VALUE(principal, "display_name");
			if (!displayName.empty())
				application[JSON_KEY_APP_owner_display_name] = displayName;
		}
		catch (const std::exception &)
		{
			// Presentation data must not make an otherwise valid App response fail.
			// Clients fall back to the stable owner_principal_id.
		}
	}

	void addOwnerDisplayNames(Json::Value &applications)
	{
		if (!applications.isArray())
			return;
		for (auto &application : applications)
			addOwnerDisplayName(application);
	}

	// Accepted application JSON keys; anything else is rejected instead of silently
	// dropped. Read-only view keys are ignored so get-modify-put round trips work.
	const std::set<std::string> &applicationInputKeys()
	{
		static const std::set<std::string> keys = {
			// writable definition
			JSON_KEY_APP_name,
			JSON_KEY_APP_command,
			JSON_KEY_APP_docker_image,
			JSON_KEY_APP_docker_ports,
			JSON_KEY_APP_docker_volumes,
			JSON_KEY_APP_docker_network,
			JSON_KEY_APP_description,
			JSON_KEY_APP_working_dir,
			JSON_KEY_APP_health_check_cmd,
			JSON_KEY_APP_env,
			JSON_KEY_APP_secret_env,
			JSON_KEY_APP_metadata,
			JSON_KEY_APP_stdin,
			JSON_KEY_APP_behavior,
			JSON_KEY_APP_permission,
			JSON_KEY_APP_enabled,
			JSON_KEY_APP_system,
			JSON_KEY_APP_startup_phase,
			JSON_KEY_APP_depends_on,
			JSON_KEY_APP_shell,
			JSON_KEY_APP_session_login,
			JSON_KEY_APP_owner_principal_id,
			JSON_KEY_APP_owner, // legacy: rejected with its own message in FromJson
			JSON_KEY_APP_from_recover,
			JSON_KEY_APP_execution_user,
			JSON_KEY_APP_daily_limitation,
			JSON_KEY_APP_resource_limit,
			JSON_KEY_APP_stdout_backup_count,
			JSON_KEY_APP_stop_grace_period,
			JSON_KEY_APP_cron_schedule,
			JSON_KEY_APP_interval,
			JSON_KEY_APP_start_time,
			JSON_KEY_APP_end_time,
			// read-only echoes from the application view
			JSON_KEY_APP_owner_display_name,
			JSON_KEY_APP_pid,
			JSON_KEY_APP_pid_user,
			JSON_KEY_APP_return_code,
			JSON_KEY_APP_memory,
			JSON_KEY_APP_cpu,
			JSON_KEY_APP_fd,
			JSON_KEY_APP_pstree,
			JSON_KEY_APP_container_id,
			JSON_KEY_APP_health,
			JSON_KEY_APP_starts,
			JSON_KEY_APP_register_time,
			JSON_KEY_APP_last_start,
			JSON_KEY_APP_last_exit,
			JSON_KEY_APP_next_start_time,
			JSON_KEY_APP_last_error,
			JSON_KEY_APP_waiting_for,
			JSON_KEY_APP_task_id,
			JSON_KEY_APP_task_status,
			JSON_KEY_APP_stdout_file_count,
			"subscription_id",
		};
		return keys;
	}

	// Unknown keys of jsonApp, comma-joined; empty when all are known.
	std::string unknownApplicationFields(const Json::Value &jsonApp)
	{
		std::string unknown;
		for (const auto &key : jsonApp.getMemberNames())
		{
			if (applicationInputKeys().count(key) != 0)
				continue;
			if (!unknown.empty())
				unknown += ", ";
			unknown += key;
		}
		return unknown;
	}

	// Config unknown-key walk: every incoming object key must exist in the current
	// configuration view at the same depth; Labels are free-form.
	void collectUnknownConfigKeys(const Json::Value &incoming, const Json::Value &schema, const std::string &prefix,
								  std::string &unknown)
	{
		if (!incoming.isObject())
			return;
		for (const auto &key : incoming.getMemberNames())
		{
			if (!schema.isObject() || !schema.isMember(key))
			{
				if (!unknown.empty())
					unknown += " ";
				unknown += prefix + key;
				continue;
			}
			if (key == JSON_KEY_Labels)
				continue;
			collectUnknownConfigKeys(incoming[key], schema[key], prefix + key + ".", unknown);
		}
	}
}

// 1. Authentication
constexpr auto REST_PATH_AUTH_CONFIG = "/appmesh/auth/config";
constexpr auto REST_PATH_LOGO = "/appmesh/logo.svg";
constexpr auto REST_PATH_FAVICON = "/appmesh/favicon.png";
constexpr auto REST_PATH_OAUTH_CALLBACK = "/oauth/callback";
constexpr auto REST_PATH_PROTECTED_RESOURCE_METADATA = "/.well-known/oauth-protected-resource";
constexpr auto REST_PATH_INTERNAL_WORKFLOW_CAPABILITY = "/appmesh/internal/workflow/capability";
constexpr auto REST_PATH_INTERNAL_WORKFLOW_CLEANUP_ORPHANS = "/appmesh/internal/workflow/cleanup-orphans";
constexpr auto REST_PATH_INTERNAL_WORKFLOW_REGISTRY = "/appmesh/internal/workflow/registry";
constexpr auto REST_PATH_INTERNAL_AGENT_CONTAINER_EVENT = "/appmesh/internal/container-event";
constexpr auto REST_PATH_ENROLL_FIRST_ADMIN = "/appmesh/auth/enroll-first-admin";

// 2. View Application
constexpr auto REST_PATH_APP_VIEW = R"(/appmesh/app/([^/\*]+))";
constexpr auto REST_PATH_APP_OUT_VIEW = R"(/appmesh/app/([^/\*]+)/output)";
constexpr auto REST_PATH_APP_ALL_VIEW = "/appmesh/applications";
constexpr auto REST_PATH_APP_HEALTH = R"(/appmesh/app/([^/\*]+)/health)";

// 3. Cloud Application
constexpr auto REST_PATH_CLOUD_RESOURCES_VIEW = "/appmesh/cloud/resources";

// 4. Manage Application
constexpr auto REST_PATH_APP_ADD = R"(/appmesh/app/([^/\*]+))";
constexpr auto REST_PATH_APP_ENABLE = R"(/appmesh/app/([^/\*]+)/enable)";
constexpr auto REST_PATH_APP_DISABLE = R"(/appmesh/app/([^/\*]+)/disable)";
constexpr auto REST_PATH_APP_DELETE = R"(/appmesh/app/([^/\*]+))";

// 5. Operate Application
constexpr auto REST_PATH_APP_RUN_ASYNC = "/appmesh/app/run";
constexpr auto REST_PATH_APP_RUN_SYNC = "/appmesh/app/syncrun";
constexpr auto REST_PATH_APP_TASK = R"(/appmesh/app/([^/\*]+)/task)";
// Streaming task RPC (SSE): partials ride the same parking as /task.
constexpr auto REST_PATH_APP_TASK_STREAM = R"(/appmesh/app/([^/\*]+)/task/stream)";
constexpr auto REST_PATH_APP_TASK_PARTIAL = R"(/appmesh/app/([^/\*]+)/task/partial)";
// Interactive stdin injection for pipe-stdin apps.
constexpr auto REST_PATH_APP_INPUT = R"(/appmesh/app/([^/\*]+)/input)";

// 6. File Management
constexpr auto REST_PATH_FILE_DOWNLOAD = "/appmesh/file/download";
constexpr auto REST_PATH_FILE_UPLOAD = "/appmesh/file/upload";
constexpr auto REST_PATH_FILE_DELETE = "/appmesh/file/delete";

// 7. Label Management
constexpr auto REST_PATH_LABEL_VIEW_ALL = "/appmesh/labels";
// Anchored: a key holding a decoded '/' or '*' must fail the route instead of
// silently truncating to the segment before it.
constexpr auto REST_PATH_LABEL_ADD = R"(/appmesh/label/([^/\*]+)$)";
constexpr auto REST_PATH_LABEL_DELETE = R"(/appmesh/label/([^/\*]+)$)";

// 8. Config
constexpr auto REST_PATH_CONFIG_VIEW = "/appmesh/config";
constexpr auto REST_PATH_CONFIG_SET = "/appmesh/config";

// 9. Security
constexpr auto REST_PATH_PRINCIPAL_SELF = "/appmesh/principal/self";
constexpr auto REST_PATH_SEC_ROLE_VIEW_ALL = "/appmesh/roles";
constexpr auto REST_PATH_SEC_ROLE_UPDATE = R"(/appmesh/role/([^/\*]+))";
constexpr auto REST_PATH_SEC_ROLE_DELETE = R"(/appmesh/role/([^/\*]+))";
constexpr auto REST_PATH_PRINCIPAL_PERMISSIONS = "/appmesh/principal/self/permissions";
constexpr auto REST_PATH_SEC_PERM_VIEW_ALL = "/appmesh/permissions";
constexpr auto REST_PATH_PRINCIPALS = "/appmesh/principals";
constexpr auto REST_PATH_PRINCIPAL = R"(/appmesh/principal/([^/\*]+))";
constexpr auto REST_PATH_SEC_API_KEYS = "/appmesh/security/apikeys";
constexpr auto REST_PATH_SEC_API_KEY = R"(/appmesh/security/apikey/([^/\*]+))";
// Cluster authorization replication: the owner serves its policy snapshot to
// followers authenticated by the shared replication token (no principal).
constexpr auto REST_PATH_AUTH_REPLICATION_POLICY = "/appmesh/auth/replication/policy";

// 10. resources
constexpr auto REST_PATH_PROMETHEUS_METRICS = "/appmesh/metrics";
constexpr auto REST_PATH_RESOURCE_VIEW = "/appmesh/resources";

// 11. Subscribe
constexpr auto REST_PATH_APP_SUBSCRIBE = R"(/appmesh/app/([^/\*]+)/subscribe)";
constexpr auto REST_PATH_APP_SUBSCRIBE_ALL = "/appmesh/subscribe";

RestHandler::RestHandler() : m_metrics(std::make_shared<PrometheusRest>())
{
	// Static content handlers
	bindRestMethod(web::http::methods::GET, "/swagger/", std::bind(&RestHandler::apiSwagger, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/openapi.yaml",
				   std::bind(&RestHandler::apiOpenApi, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/index.html", std::bind(&RestHandler::apiIndex, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/", std::bind(&RestHandler::apiIndex, this, std::placeholders::_1));

	// 1. Authentication
	bindRestMethod(web::http::methods::GET, REST_PATH_AUTH_CONFIG,
				   std::bind(&RestHandler::apiAuthConfig, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_LOGO, std::bind(&RestHandler::apiLogo, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_FAVICON,
				   std::bind(&RestHandler::apiFavicon, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_OAUTH_CALLBACK,
				   std::bind(&RestHandler::apiOauthCallback, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_PROTECTED_RESOURCE_METADATA,
				   std::bind(&RestHandler::apiProtectedResourceMetadata, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_INTERNAL_WORKFLOW_CAPABILITY,
				   std::bind(&RestHandler::apiWorkflowCapability, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_INTERNAL_WORKFLOW_CLEANUP_ORPHANS,
				   std::bind(&RestHandler::apiWorkflowCleanupOrphans, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_INTERNAL_WORKFLOW_REGISTRY,
				   std::bind(&RestHandler::apiWorkflowRegistry, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_INTERNAL_AGENT_CONTAINER_EVENT,
				   std::bind(&RestHandler::apiAgentContainerEvent, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_ENROLL_FIRST_ADMIN,
				   std::bind(&RestHandler::apiEnrollFirstAdmin, this, std::placeholders::_1));

	// 2. View Application
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_VIEW,
				   std::bind(&RestHandler::apiAppView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_OUT_VIEW,
				   std::bind(&RestHandler::apiAppOutputView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_ALL_VIEW,
				   std::bind(&RestHandler::apiAppsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_HEALTH,
				   std::bind(&RestHandler::apiHealth, this, std::placeholders::_1));

	// 3. Cloud Application
	bindRestMethod(web::http::methods::GET, REST_PATH_CLOUD_RESOURCES_VIEW,
				   std::bind(&RestHandler::apiCloudResourceView, this, std::placeholders::_1));

	// 4. Manage Application
	bindRestMethod(web::http::methods::PUT, REST_PATH_APP_ADD,
				   std::bind(&RestHandler::apiAppAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_ENABLE,
				   std::bind(&RestHandler::apiAppEnable, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_DISABLE,
				   std::bind(&RestHandler::apiAppDisable, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_DELETE,
				   std::bind(&RestHandler::apiAppDelete, this, std::placeholders::_1));

	// 5. Operate Application
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_RUN_ASYNC,
				   std::bind(&RestHandler::apiRunAsync, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_RUN_SYNC,
				   std::bind(&RestHandler::apiRunSync, this, std::placeholders::_1));
	// The /task regex is a strict full match, but keep the longer paths bound
	// first so the dispatch table reads most-specific-first.
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_TASK_STREAM,
				   std::bind(&RestHandler::apiSendTaskStream, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_TASK_PARTIAL,
				   std::bind(&RestHandler::apiSendTaskPartial, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_INPUT,
				   std::bind(&RestHandler::apiAppInput, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_TASK,
				   std::bind(&RestHandler::apiSendTask, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_TASK,
				   std::bind(&RestHandler::apiDeleteTask, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_TASK,
				   std::bind(&RestHandler::apiFetchTask, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, REST_PATH_APP_TASK,
				   std::bind(&RestHandler::apiReplyTask, this, std::placeholders::_1));

	// 6. File Management
	bindRestMethod(web::http::methods::GET, REST_PATH_FILE_DOWNLOAD,
				   std::bind(&RestHandler::apiFileDownload, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_FILE_UPLOAD,
				   std::bind(&RestHandler::apiFileUpload, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_FILE_DELETE,
				   std::bind(&RestHandler::apiFileDelete, this, std::placeholders::_1));

	// 7. Label Management
	bindRestMethod(web::http::methods::GET, REST_PATH_LABEL_VIEW_ALL,
				   std::bind(&RestHandler::apiLabelsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, REST_PATH_LABEL_ADD,
				   std::bind(&RestHandler::apiLabelAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_LABEL_DELETE,
				   std::bind(&RestHandler::apiLabelDelete, this, std::placeholders::_1));

	// 8. Config
	bindRestMethod(web::http::methods::GET, REST_PATH_CONFIG_VIEW,
				   std::bind(&RestHandler::apiBasicConfigView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_CONFIG_SET,
				   std::bind(&RestHandler::apiBasicConfigSet, this, std::placeholders::_1));

	// 9. Security
	bindRestMethod(web::http::methods::GET, REST_PATH_PRINCIPAL_SELF,
				   std::bind(&RestHandler::apiPrincipalSelf, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_PRINCIPALS,
				   std::bind(&RestHandler::apiPrincipalsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_PRINCIPAL,
				   std::bind(&RestHandler::apiPrincipalUpdate, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_PRINCIPAL,
				   std::bind(&RestHandler::apiPrincipalDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_ROLE_VIEW_ALL,
				   std::bind(&RestHandler::apiRolesView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_AUTH_REPLICATION_POLICY,
				   std::bind(&RestHandler::apiAuthReplicationPolicy, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_ROLE_UPDATE,
				   std::bind(&RestHandler::apiRoleUpdate, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_SEC_ROLE_DELETE,
				   std::bind(&RestHandler::apiRoleDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_PRINCIPAL_PERMISSIONS,
				   std::bind(&RestHandler::apiPrincipalPermissionsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_API_KEYS,
				   std::bind(&RestHandler::apiApiKeysView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_API_KEYS,
				   std::bind(&RestHandler::apiApiKeyIssue, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_SEC_API_KEY,
				   std::bind(&RestHandler::apiApiKeyDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_PERM_VIEW_ALL,
				   std::bind(&RestHandler::apiPermissionsView, this, std::placeholders::_1));

	// 10. metrics
	bindRestMethod(web::http::methods::GET, METRIC_PATH,
				   std::bind(&RestHandler::apiRestMetrics, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_PROMETHEUS_METRICS,
				   std::bind(&RestHandler::apiRestMetrics, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_RESOURCE_VIEW,
				   std::bind(&RestHandler::apiResourceView, this, std::placeholders::_1));

	// 11. Subscribe
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_SUBSCRIBE,
				   std::bind(&RestHandler::apiAppSubscribe, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_SUBSCRIBE_ALL,
				   std::bind(&RestHandler::apiAppSubscribe, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_SUBSCRIBE,
				   std::bind(&RestHandler::apiAppUnsubscribe, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_SUBSCRIBE_ALL,
				   std::bind(&RestHandler::apiAppUnsubscribe, this, std::placeholders::_1));
}

RestHandler::~RestHandler()
{
	const static char fname[] = "RestHandler::~RestHandler() ";
	LOG_INF << fname << "RestHandler destroyed";
}

RestHandler *RestHandler::instance()
{
	static RestHandler inst;
	return &inst;
}

std::string RestHandler::normalizedHttpRoute(
	const std::string &path,
	const std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> *preferredFunctions) const
{
	typedef std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> RestFunctions;
	auto findPattern = [&](const RestFunctions &functions) -> std::string
	{
		for (const auto &entry : functions)
		{
			if (path == entry.first || boost::regex_match(path, m_restRegexCache.at(entry.first)))
				return entry.first;
		}
		return {};
	};

	std::string pattern;
	if (preferredFunctions)
		pattern = findPattern(*preferredFunctions);
	else
	{
		for (const auto *functions : {&m_restGetFunctions, &m_restPutFunctions, &m_restPostFunctions, &m_restDelFunctions})
		{
			pattern = findPattern(*functions);
			if (!pattern.empty())
				break;
		}
	}
	if (pattern.empty())
		return "unmatched";

	const std::string capture = "([^/\\*]+)";
	std::string normalized = pattern;
	std::size_t position = 0;
	while ((position = normalized.find(capture, position)) != std::string::npos)
	{
		normalized.replace(position, capture.size(), ":param");
		position += 6;
	}
	// Anchors are regex syntax, not route text; keep them out of the metric label.
	if (!normalized.empty() && normalized.front() == '^')
		normalized.erase(normalized.begin());
	if (!normalized.empty() && normalized.back() == '$')
		normalized.pop_back();
	return normalized;
}

void RestHandler::observeHttpRequest(const std::shared_ptr<HttpRequest> &message)
{
	const auto queryPosition = message->m_relative_uri.find('?');
	auto path = message->m_relative_uri.substr(0, queryPosition);
	for (auto pos = path.find("//"); pos != std::string::npos; pos = path.find("//", pos))
		path.erase(pos, 1);
	if (path == METRIC_PATH || path == METRIC_APP_PATH)
		return;

	const auto *routes = &m_restGetFunctions;
	bool matchRoute = true;
	std::string method = "OTHER";
	if (message->m_method == web::http::methods::GET || message->m_method == web::http::methods::HEAD)
	{
		routes = &m_restGetFunctions;
		method = message->m_method;
	}
	else if (message->m_method == web::http::methods::PUT)
	{
		routes = &m_restPutFunctions;
		method = message->m_method;
	}
	else if (message->m_method == web::http::methods::POST)
	{
		routes = &m_restPostFunctions;
		method = message->m_method;
	}
	else if (message->m_method == web::http::methods::DEL)
	{
		routes = &m_restDelFunctions;
		method = message->m_method;
	}
	else if (message->m_method == web::http::methods::OPTIONS)
	{
		routes = nullptr;
		method = message->m_method;
	}
	else
	{
		matchRoute = false;
	}

	auto route = matchRoute ? normalizedHttpRoute(path, routes) : std::string("unmatched");
	const auto started = std::chrono::steady_clock::now();
	const auto metrics = m_metrics;
	m_metrics->httpRequestStarted(method, route);
	message->setReplyMetricCallback(
		[metrics, method, route = std::move(route), started](int status)
		{
			const auto duration = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
			metrics->httpRequestFinished(method, route, status, duration);
		});
}

std::shared_ptr<CounterMetric> RestHandler::createPromCounter(const std::string &metricName, const std::string &metricHelp,
															  const std::map<std::string, std::string> &labels)
{
	return m_metrics->createPromCounter(metricName, metricHelp, labels);
}

std::shared_ptr<GaugeMetric> RestHandler::createPromGauge(const std::string &metricName, const std::string &metricHelp,
														  const std::map<std::string, std::string> &labels)
{
	return m_metrics->createPromGauge(metricName, metricHelp, labels);
}

uint64_t RestHandler::prometheusScrapeGeneration() const { return m_metrics->scrapeGeneration(); }

void RestHandler::refreshPrometheusProcessMetrics(void *processSnapshot)
{
	m_metrics->refreshProcessMetrics(processSnapshot);
}

// Static content serving utilities
const std::string &RestHandler::getOpenApiContent()
{
	static const std::string content =
		Utility::readFileCpp((fs::path(Utility::getHomeDir()) / "script" / "openapi.yaml").string());
	return content;
}

const std::string &RestHandler::getLogoContent()
{
	static const std::string content =
		Utility::readFileCpp((fs::path(Utility::getHomeDir()) / "script" / "logo.svg").string());
	return content;
}

const std::string &RestHandler::getFaviconContent()
{
	static const std::string content =
		Utility::readFileCpp((fs::path(Utility::getHomeDir()) / "script" / "favicon.png").string());
	return content;
}

const std::string &RestHandler::getIndexHtmlContent()
{
	static const std::string content =
		Utility::readFileCpp((fs::path(Utility::getHomeDir()) / "script" / "index.html").string());
	return content;
}

// Static content handlers
void RestHandler::apiOpenApi(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiOpenApi() ";
	LOG_DBG << fname << "Serving OpenAPI specification";

	std::string content = getOpenApiContent();
	message->reply(web::http::status_codes::OK, content, CONTENT_TYPE_YAML);
}

// Branding asset for the authentication-service login page: frontend.logoURL
// in dex.yaml is issuer-path relative, and public entries proxy it here, so
// the asset follows whatever host and port the browser used. Public like the
// login page itself.
void RestHandler::apiLogo(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiLogo() ";
	LOG_DBG << fname << "Serving logo";

	std::string content = getLogoContent();
	message->reply(web::http::status_codes::OK, content, CONTENT_TYPE_SVG);
}

void RestHandler::apiFavicon(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiFavicon() ";
	LOG_DBG << fname << "Serving favicon";

	std::string content = getFaviconContent();
	message->reply(web::http::status_codes::OK, content, CONTENT_TYPE_PNG);
}

// Static relay page for the browser OAuth callback. Byte-identical copy in the
// Go agent (auth_relay.go); change both together.
constexpr auto OAUTH_CALLBACK_RELAY_HTML = R"HTML(<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="robots" content="noindex">
<title>App Mesh sign-in</title>
</head>
<body>
<p id="message">Completing the sign-in.</p>
<script>
(function () {
  "use strict";
  var fail = function () {
    document.getElementById("message").textContent =
      "The sign-in link is not valid. Start the sign-in again from the App Mesh page.";
  };
  var query = new URLSearchParams(window.location.search);
  var state = query.get("state");
  var code = query.get("code");
  if (!state || !code) {
    fail();
    return;
  }
  var decoded = state.replace(/-/g, "+").replace(/_/g, "/");
  while (decoded.length % 4 !== 0) {
    decoded += "=";
  }
  var payload;
  try {
    payload = JSON.parse(atob(decoded));
  } catch (error) {
    fail();
    return;
  }
  var target;
  try {
    target = new URL(payload && typeof payload.o === "string" ? payload.o : "");
  } catch (error) {
    target = null;
  }
  if (!target || (target.protocol !== "https:" && target.protocol !== "http:") || !target.host) {
    fail();
    return;
  }
  window.location.replace(target.origin + "/oauth/callback" + window.location.search);
})();
</script>
</body>
</html>)HTML";

// The relay page runs one pinned inline script; the daemon-wide
// "default-src 'none'" CSP would block it, so this response overrides the
// policy with the script's SHA-256 hash (base64 of the exact bytes between
// <script> and </script>, leading and trailing newlines included). Byte-identical
// copy in the Go agent (auth_relay.go); the hash must match on both sides.
constexpr auto OAUTH_CALLBACK_RELAY_CSP =
	"default-src 'none'; script-src 'sha256-WJHBkicVdWDq2OxtXiYCx4BCaK7EV2KyjwBP8/UzM6Q='; frame-ancestors 'none'";

// The browser lands on <browser_entry-origin>/oauth/callback after the
// authorization-code flow. The static page hands the unchanged query string to
// the web UI origin carried in the state parameter, and only to the fixed
// /oauth/callback path on that origin. PKCE keeps a relayed code useless to any
// other origin. Public like the login page itself.
void RestHandler::apiOauthCallback(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiOauthCallback() ";
	LOG_DBG << fname << "Serving the OAuth callback relay page";

	std::string content(OAUTH_CALLBACK_RELAY_HTML);
	std::map<std::string, std::string> headers;
	headers[web::http::header_names::content_security_policy] = OAUTH_CALLBACK_RELAY_CSP;
	message->reply(web::http::status_codes::OK, content, headers, CONTENT_TYPE_HTML);
}

void RestHandler::apiSwagger(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiSwagger() ";
	LOG_DBG << fname << "Redirecting to Swagger UI";

	auto host = message->m_headers.get(web::http::header_names::host);

	// The openapi URL must use the scheme this daemon actually serves.
	const std::string scheme = Configuration::instance()->getSslEnabled() ? "https" : "http";
	std::string swaggerUrl = "https://petstore.swagger.io/?url=" + scheme + "://" + host + "/openapi.yaml";
	std::map<std::string, std::string> headers;
	headers[web::http::header_names::location] = std::move(swaggerUrl);

	std::string emptyBody;
	message->reply(web::http::status_codes::TemporaryRedirect, emptyBody, headers, CONTENT_TYPE_HTML);
}

void RestHandler::apiIndex(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiIndex() ";
	LOG_DBG << fname << "Serving index.html";

	std::string content = getIndexHtmlContent();
	std::map<std::string, std::string> headers;
	// The page is a static installed file (no reflection, operators may customize
	// it), so inline style/script is allowed here only; everything else stays denied.
	headers[web::http::header_names::content_security_policy] =
		"default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; frame-ancestors 'none'";
	message->reply(web::http::status_codes::OK, content, headers, CONTENT_TYPE_HTML);
}

void RestHandler::checkAppAccessPermission(const std::shared_ptr<HttpRequest> &message,
										   const std::shared_ptr<Application> &app, bool requestWrite)
{
	const auto tokenUser = permissionCheck(message, "");
	const auto &appName = app->getName();
	if (!Configuration::instance()->checkOwnerPermission(tokenUser, app->getOwnerPrincipalId(), app->getOwnerPermission(),
														 requestWrite))
	{
		throw AuthorizationException(Utility::stringFormat("Principal <%s> is not allowed to <%s> app <%s>",
														   tokenUser.c_str(), (requestWrite ? "EDIT" : "VIEW"),
														   appName.c_str()));
	}
	if (requestWrite && appName == SEPARATE_AGENT_APP_NAME)
	{
		throw std::invalid_argument("REST service application is not allowed to <EDIT>");
	}
}

long RestHandler::getHttpQueryValue(const HttpRequest &message, const std::string &key, long defaultValue, long min,
									long max)
{
	long rt = defaultValue;
	if (auto it = message.m_query.find(key); it != message.m_query.end())
	{
		rt = DurationParse::parse(it->second);
		// Negative is never valid for these params; fall back to default so it can't wrap
		// into size_t or drive negative offsets/overflowing timers downstream.
		if (rt < 0)
			rt = defaultValue;
		else if (min < max && (rt < min || rt > max))
			rt = defaultValue;
	}
	return rt;
}

long RestHandler::getHttpQueryPosition(const HttpRequest &message, const std::string &key, long defaultValue, long min,
									   long max)
{
	// Positions and indices are plain integers (byte offsets, nanosecond log
	// cursors), not durations: the duration parser rejects values beyond int
	// range, which a cursor legitimately exceeds.
	long rt = defaultValue;
	if (auto it = message.m_query.find(key); it != message.m_query.end())
	{
		try
		{
			rt = std::stoll(it->second);
		}
		catch (const std::exception &)
		{
			rt = defaultValue;
		}
		if (rt < 0)
			rt = defaultValue;
		else if (min < max && (rt < min || rt > max))
			rt = defaultValue;
	}
	return rt;
}

std::string RestHandler::getHttpQueryString(const HttpRequest &message, const std::string &key)
{
	const static char fname[] = "RestHandler::getHttpQueryString() ";

	std::string rt;
	if (auto it = message.m_query.find(key); it != message.m_query.end())
	{
		rt = it->second;
	}
	LOG_DBG << fname << "Query parameter <" << key << "> = <" << rt << ">";
	return rt;
}

std::string RestHandler::regexSearch(const std::string &value, const char *expr, const char *clientError)
{
	const static char fname[] = "RestHandler::regexSearch() ";

	std::string result;
	boost::regex expression(expr);
	boost::smatch what;
	if (boost::regex_search(value, what, expression) && what.size() > 1)
	{
		// NOTE: start from position 1, skip the REST patch prefix
		for (size_t i = 1; i < what.size(); ++i)
		{
			if (what[i].matched)
			{
				result = Utility::stdStringTrim(what[i].str());
				if (result.length())
				{
					return result;
				}
				LOG_WAR << fname << "Found empty data from path <" << value << "> for regex expression: <" << expr << ">";
				throw std::invalid_argument("No data found from path for regex search");
			}
		}
	}
	// The regex details stay in the log; the client sees a neutral message.
	LOG_WAR << fname << "Failed to parse data from path <" << value << "> for regex expression: <" << expr << ">";
	throw std::invalid_argument(clientError);
}

std::tuple<std::string, std::string> RestHandler::regexSearch2(const std::string &value, const char *expr,
															   const char *clientError)
{
	const static char fname[] = "RestHandler::regexSearch2() ";

	std::string first, second;
	boost::regex expression(expr);
	boost::smatch what;
	if (boost::regex_search(value, what, expression) && what.size() > 1)
	{
		// NOTE: start from position 1, skip the REST patch prefix
		for (size_t i = 1; i < what.size(); ++i)
		{
			if (what[i].matched)
			{
				if (first.empty())
				{
					first = Utility::stdStringTrim(what[i].str());
				}
				else if (second.empty())
				{
					second = Utility::stdStringTrim(what[i].str());
					return std::make_tuple(first, second);
				}
			}
		}
	}
	// The regex details stay in the log; the client sees a neutral message.
	LOG_WAR << fname << "Failed to parse data pair from path <" << value << "> for regex expression: <" << expr << ">";
	throw std::invalid_argument(clientError);
}

void RestHandler::apiAppEnable(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_ENABLE);
	auto config = Configuration::instance();
	const auto app = config->getApp(appName);
	checkAppAccessPermission(message, app, true);
	bool stale = false;
	{
		const auto mutation = config->lockAppMutation();
		if (!config->isCurrentApp(appName, app))
			stale = true;
		else
			config->enableApp(appName);
	}
	if (stale)
	{
		message->reply(web::http::status_codes::Conflict);
		return;
	}
	message->reply(web::http::status_codes::OK, Utility::text2json(std::string("Enable <") + appName + "> success."));
}

void RestHandler::apiAppDisable(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_DISABLE);
	auto config = Configuration::instance();
	const auto app = config->getApp(appName);
	checkAppAccessPermission(message, app, true);
	// Termination runs outside the mutation lock; a slow Docker backend
	// cannot stall other management.
	if (!config->disableApp(appName, app.get()))
	{
		message->reply(web::http::status_codes::Conflict);
		return;
	}
	message->reply(web::http::status_codes::OK, Utility::text2json(std::string("Disable <") + appName + "> success."));
}

void RestHandler::apiAppDelete(const std::shared_ptr<HttpRequest> &message)
{
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_DELETE);

	auto config = Configuration::instance();
	auto app = config->getApp(appName, false);
	if (!app)
	{
		message->reply(web::http::status_codes::NotFound);
	}
	else
	{
		// Establish a verified Dex principal before applying the owner shortcut.
		const auto tokenUser = permissionCheck(message, "");
		if (app->getOwnerPrincipalId() != tokenUser)
		{
			// only check delete permission for none-self app
			permissionCheck(message, PERMISSION_KEY_app_delete);
		}

		// Deleting a dependency would silently release its dependents (a missing
		// dependency counts as satisfied); refuse and name them instead.
		std::string dependents;
		for (const auto &other : config->getApps())
		{
			if (other && other->getName() != appName)
			{
				for (const auto &dependency : other->dependsOn())
				{
					if (dependency == appName)
					{
						if (!dependents.empty())
							dependents += ", ";
						dependents += other->getName();
						break;
					}
				}
			}
		}
		if (!dependents.empty())
		{
			throw std::invalid_argument("application <" + appName + "> is a depends_on target of: " + dependents +
										"; remove or update those applications first");
		}

		checkAppAccessPermission(message, app, true);
		// The map update inside removeApp is atomic and the expected pointer
		// makes the snapshot race-safe; a replacement with the same name is not
		// removed. Destruction runs outside the mutation lock, so a slow Docker
		// backend cannot stall other application management.
		if (!config->removeApp(appName, app.get()))
		{
			message->reply(web::http::status_codes::Conflict);
			return;
		}
		// Cascade deletes base run instances; the base's delete permission governs it.
		// -1 means instances re-registered faster than the resweep could drain them.
		LOG_INF << "RestHandler::apiAppDelete() Principal <" << tokenUser << "> cascading run instances of <" << appName
				<< ">";
		const auto removedInstances = config->removeRunInstances(appName);
		if (removedInstances < 0)
		{
			message->reply(web::http::status_codes::Conflict,
						   Utility::text2json(Utility::stringFormat("Application <%s> removed, but its run instances kept "
																	"re-registering; retry the delete",
																	appName.c_str())));
			return;
		}
		message->reply(web::http::status_codes::OK,
					   Utility::text2json(Utility::stringFormat("Application <%s> removed.", appName.c_str())));
	}
}

void RestHandler::apiFileDownload(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiFileDownload() ";

	permissionCheck(message, PERMISSION_KEY_file_download);
	if (0 == message->m_headers.count(HTTP_HEADER_KEY_file_path))
	{
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("header 'X-File-Path' not found"));
		return;
	}
	const auto file = Utility::decodeHeaderFilePath(message->m_headers.find(HTTP_HEADER_KEY_file_path)->second);
	if (rejectFilePath(message, file))
		return;

	if (!Utility::isFileExist(file))
	{
		message->reply(web::http::status_codes::NotFound, Utility::text2json("file not found"));
		return;
	}

	LOG_DBG << fname << "Downloading file <" << file << ">";

	auto headers = Utility::fileAttributeHeaders(file);
	auto body = HttpRequest::emptyJsonMessage();
	if (message->m_headers.count(HTTP_HEADER_KEY_X_Recv_File_Socket) &&
		message->m_headers.find(HTTP_HEADER_KEY_X_Recv_File_Socket)->second == "true")
	{
		LOG_DBG << fname << "Download file from socket";
		headers[HTTP_HEADER_KEY_X_Recv_File_Socket] = Utility::encode64(file);
		body = Utility::text2json("Please recieve file from socket");
		message->reply(web::http::status_codes::OK, body, headers);
		return;
	}

	// A forwarded request has no socket to stream on: the file content is the
	// response body (bounded; larger files need a streaming surface).
	if (0 == message->m_headers.count(HTTP_HEADER_KEY_APPMESH_FORWARDED))
	{
		message->reply(web::http::status_codes::OK, body, headers);
		return;
	}
	// Open-then-verify: the fd pins the inode that passed the jail check, so the
	// body can only come from the validated file, never a swapped symlink component.
	std::string resolvedPath;
	bool jailRejected = false;
	const int fd = Utility::openFileWithinJail(file, false, Configuration::instance()->getFileAllowedBaseDir(), resolvedPath,
											   &jailRejected);
	if (fd < 0)
	{
		if (jailRejected)
		{
			LOG_ERR << fname << "Resolved file path is not allowed | FilePath=" << file;
			message->reply(web::http::status_codes::Forbidden, Utility::text2json("File path is not allowed"));
			return;
		}
		message->reply(web::http::status_codes::InternalError, Utility::text2json("failed to read file"));
		return;
	}
	std::vector<std::uint8_t> content;
	{
		FdFileStream input(fd); // owns the descriptor
		char buf[64 * 1024];
		for (;;)
		{
			const auto n = input.read(buf, sizeof(buf));
			if (n <= 0)
				break;
			content.insert(content.end(), buf, buf + n);
			if (content.size() > MAX_HTTP_BODY_SIZE)
			{
				message->reply(web::http::status_codes::RequestEntityTooLarge,
							   Utility::text2json("file is too large for the buffered download surface"));
				return;
			}
		}
		if (!input.good())
		{
			message->reply(web::http::status_codes::InternalError, Utility::text2json("failed to read file"));
			return;
		}
	}
	message->reply(message->m_relative_uri, message->m_uuid, content, headers, web::http::status_codes::OK,
				   web::http::mime_types::application_octetstream);
}

void RestHandler::apiFileUpload(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiFileUpload() ";
	permissionCheck(message, PERMISSION_KEY_file_upload);
	if (0 == message->m_headers.count(HTTP_HEADER_KEY_file_path))
	{
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("header 'X-File-Path' not found"));
		return;
	}
	const auto file = Utility::decodeHeaderFilePath(message->m_headers.find(HTTP_HEADER_KEY_file_path)->second);
	if (rejectFilePath(message, file))
		return;

	std::error_code pathEc;
	// Same leaf rule as the drogon face: a symlink leaf answers a misleading 409 or silently swaps the link.
	if (std::filesystem::is_symlink(file, pathEc))
	{
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("Symlinks not allowed"));
		return;
	}
	if (std::filesystem::is_directory(file, pathEc))
	{
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("destination is a directory"));
		return;
	}

	const auto overwrite = message->m_headers.count(HTTP_HEADER_KEY_file_overwrite) != 0 &&
						   message->m_headers.find(HTTP_HEADER_KEY_file_overwrite)->second == "true";
	if (!overwrite && Utility::isFileExist(file))
	{
		message->reply(web::http::status_codes::Conflict, Utility::text2json("file already exist"));
		return;
	}

	LOG_DBG << fname << "Uploading file <" << file << ">";

	std::map<std::string, std::string> headers;
	auto body = HttpRequest::emptyJsonMessage();
	if (message->m_headers.count(HTTP_HEADER_KEY_X_Send_File_Socket) &&
		message->m_headers.find(HTTP_HEADER_KEY_X_Send_File_Socket)->second == "true")
	{
		LOG_DBG << fname << "Upload file from socket";
		headers[HTTP_HEADER_KEY_X_Send_File_Socket] = Utility::encode64(file);
		body = Utility::text2json("Please send file from socket");
		message->reply(web::http::status_codes::OK, body, headers);
	}
	else if (message->m_body && !message->m_body->empty())
	{
		// The payload rides in the request body (a forwarded or envelope upload);
		// the socket arm above is the agent/TCP-SDK streaming path.
		if (message->m_body->size() > MAX_UPLOAD_SIZE)
			throw std::invalid_argument("upload exceeds the size limit");
		FileUploadInfo upload(file, file + "." + Utility::shortID() + ".part", message->m_headers, overwrite,
							  Configuration::instance()->getFileAllowedBaseDir());
		if (upload.m_rejected)
		{
			// The fd check saw the resolved temp location leave the jail: a
			// component was swapped between validation and open.
			LOG_ERR << fname << "Resolved upload path is not allowed | FilePath=" << file;
			message->reply(web::http::status_codes::Forbidden, Utility::text2json("File path is not allowed"));
			return;
		}
		if (!upload.m_file.is_open())
			throw std::runtime_error("failed to create the upload file");
		upload.m_file.write(reinterpret_cast<const char *>(message->m_body->data()),
							static_cast<std::streamsize>(message->m_body->size()));
		const auto commitResult = upload.commit();
		if (!upload.m_file.good() || commitResult == FileUploadInfo::CommitResult::Failed)
			throw std::runtime_error("failed to write the upload file");
		if (commitResult == FileUploadInfo::CommitResult::AlreadyExists)
		{
			// A concurrent upload won the non-overwrite race after the precheck.
			message->reply(web::http::status_codes::Conflict, Utility::text2json("file already exist"));
			return;
		}
		Utility::applyFilePermission(file, message->m_headers, upload.fd());
		LOG_INF << fname << "File uploaded successfully: " << file << " (" << message->m_body->size() << " bytes)";
		Json::Value respJson;
		respJson["status"] = "success";
		respJson["file"] = std::filesystem::path(file).filename().string();
		respJson["size"] = static_cast<Json::UInt64>(message->m_body->size());
		message->reply(web::http::status_codes::OK, respJson);
		return;
	}
	else
	{
		message->reply(web::http::status_codes::OK, body, headers);
	}
	// Attribute headers ride the committed fd on every face; no path-based apply remains.
}

void RestHandler::apiFileDelete(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiFileDelete() ";
	permissionCheck(message, PERMISSION_KEY_file_delete);
	if (0 == message->m_headers.count(HTTP_HEADER_KEY_file_path))
	{
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("header 'X-File-Path' not found"));
		return;
	}
	const auto file = Utility::decodeHeaderFilePath(message->m_headers.find(HTTP_HEADER_KEY_file_path)->second);
	if (rejectFilePath(message, file))
		return;

	// Pin-then-verify delete: unlinkat targets the dirfd-pinned parent re-verified
	// against the jail, so a symlink swap cannot steer the delete outside the jail.
	std::string resolvedPath;
	switch (Utility::unlinkFileWithinJail(file, Configuration::instance()->getFileAllowedBaseDir(), resolvedPath))
	{
	case Utility::JailUnlinkStatus::Removed:
		break;
	case Utility::JailUnlinkStatus::Rejected:
		message->reply(web::http::status_codes::Forbidden, Utility::text2json("File path is not allowed"));
		return;
	case Utility::JailUnlinkStatus::NotFound:
		// Missing leaf or a (never-deletable) directory; a symlink leaf lands in Rejected.
		message->reply(web::http::status_codes::NotFound, Utility::text2json("file not found"));
		return;
	case Utility::JailUnlinkStatus::Failed:
	default:
		message->reply(web::http::status_codes::InternalError, Utility::text2json("failed to remove the file"));
		return;
	}
	LOG_INF << fname << "File deleted: " << (resolvedPath.empty() ? file : resolvedPath);
	message->reply(web::http::status_codes::OK, Utility::text2json("success"));
}

void RestHandler::apiLabelsView(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_label_view);
	message->reply(web::http::status_codes::OK, Configuration::instance()->getLabel()->AsJson());
}

void RestHandler::apiLabelAdd(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiLabelAdd() ";
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_label_set);

	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto labelKey = regexSearch(path, REST_PATH_LABEL_ADD, "Invalid label key");

	if (auto it = message->m_query.find(HTTP_QUERY_KEY_label_value); it != message->m_query.end())
	{
		const auto &value = it->second;

		Configuration::instance()->getLabel()->addLabel(labelKey, value);
		Configuration::instance()->saveConfigToDisk();

		LOG_INF << fname << "User <" << tokenUser << "> added label <" << labelKey << ":" << value << ">";
		message->reply(web::http::status_codes::OK, Utility::text2json("Add label success"));
	}
	else
	{
		LOG_WAR << fname << "User <" << tokenUser << "> attempted to add label without value";
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("query value required"));
	}
}

void RestHandler::apiLabelDelete(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiLabelDelete() ";
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_label_delete);

	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto labelKey = regexSearch(path, REST_PATH_LABEL_DELETE, "Invalid label key");

	Configuration::instance()->getLabel()->delLabel(labelKey);
	Configuration::instance()->saveConfigToDisk();

	LOG_INF << fname << "User <" << tokenUser << "> deleted label <" << labelKey << ">";
	message->reply(web::http::status_codes::OK, Utility::text2json("Label delete success"));
}

void RestHandler::apiPrincipalPermissionsView(const std::shared_ptr<HttpRequest> &message)
{
	const auto principalId = permissionCheck(message, "");
	const auto permissions = Security::instance()->permissions(principalId);
	auto json = Json::Value(Json::arrayValue);
	for (auto &perm : permissions)
	{
		json.append(std::string(perm));
	}
	message->reply(web::http::status_codes::OK, json);
}

void RestHandler::apiBasicConfigView(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiBasicConfigView() ";
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_config_view);
	LOG_DBG << fname << "User <" << tokenUser << "> viewing configuration";

	auto config = Configuration::instance()->AsJson();
	message->reply(web::http::status_codes::OK, config);
}

void RestHandler::apiBasicConfigSet(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiBasicConfigSet() ";
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_config_set);

	auto json = message->extractJson();
	// Reject keys the configuration view does not carry, at any depth; typos were
	// silently dropped. Labels stay free-form; read-only keys (Version) are accepted.
	if (!json.isObject())
		throw std::invalid_argument("configuration body must be a JSON object");
	{
		const auto current = Configuration::instance()->AsJson();
		std::string unknown;
		collectUnknownConfigKeys(json, current, "", unknown);
		if (!unknown.empty())
			throw std::invalid_argument("unknown configuration field(s): " + unknown);
		// A hot update never rebinds a listener; an unchanged value is the
		// idempotent no-op of posting the GET document back.
		if (json.get(JSON_KEY_REST, Json::Value()).get(JSON_KEY_SSL, Json::Value()).isMember(JSON_KEY_SSLEnabled))
		{
			const auto &requested = json[JSON_KEY_REST][JSON_KEY_SSL][JSON_KEY_SSLEnabled];
			if (!(requested.isBool() && requested.asBool() == Configuration::instance()->getSslEnabled()))
				throw std::invalid_argument(
					"REST.SSL.SSLEnabled is startup-only: set it in config.yaml and restart the daemon");
		}
	}
	Configuration::instance()->hotUpdateAndSave(json);

	LOG_INF << fname << "User <" << tokenUser << "> updated configuration";
	message->reply(web::http::status_codes::OK, Configuration::instance()->AsJson());
}

void RestHandler::apiAuthConfig(const std::shared_ptr<HttpRequest> &message)
{
	message->reply(web::http::status_codes::OK, Security::instance()->authConfig());
}

void RestHandler::apiProtectedResourceMetadata(const std::shared_ptr<HttpRequest> &message)
{
	message->reply(web::http::status_codes::OK, Security::instance()->protectedResourceMetadata());
}

void RestHandler::apiWorkflowCapability(const std::shared_ptr<HttpRequest> &message)
{
	// This route is intentionally absent from OpenAPI. The peer address comes
	// from the accepted socket, not from request headers/body.
	if (!message->isManagedPrivateTransport())
		throw AuthorizationException("workflow capabilities are available only over local loopback transports");

	const auto workflowProcess = Configuration::instance()->getApp(WORKFLOW_APP_NAME, false);
	if (!workflowProcess || !workflowProcess->isSystemProtected())
		throw AuthorizationException("managed Workflow system application is unavailable");
	// A bad or superseded proof is an authentication failure (401), not an
	// authorization denial (403).
	const auto processUuid =
		workflowProcess->currentProcessUuidForProof(message->m_uuid, message->m_headers.get(HMAC_HTTP_HEADER));
	if (processUuid.empty())
		throw std::domain_error("workflow process proof is invalid or superseded");

	const auto request = message->extractJson();
	if (!request.isObject())
		throw std::invalid_argument("workflow capability request must be an object");
	const auto audience = GET_JSON_STR_VALUE(request, "audience");
	const auto ttlSeconds = request.isMember("expires_in") ? request["expires_in"].asInt64() : 300;
	if (ttlSeconds < 60 || ttlSeconds > 300)
		throw std::invalid_argument("workflow capability expires_in must be between 60 and 300 seconds");
	if (!request.isMember("operations") || !request["operations"].isArray())
		throw std::invalid_argument("workflow capability operations must be an array");

	std::set<std::string> operations;
	for (const auto &entry : request["operations"])
	{
		if (!entry.isString() || entry.asString().empty())
			throw std::invalid_argument("workflow capability operation must be a non-empty string");
		operations.insert(entry.asString());
	}
	if (operations.empty())
		throw std::invalid_argument("workflow capability requires at least one operation");

	InternalCapability::Audience capabilityAudience;
	std::string workflowId;
	std::string runId;
	std::string ownerPrincipalId;
	std::set<std::string> allowedOperations;
	if (audience == InternalCapability::audienceName(InternalCapability::Audience::WorkflowControl))
	{
		capabilityAudience = InternalCapability::Audience::WorkflowControl;
		workflowId = "__control__";
		runId = processUuid;
		ownerPrincipalId = "internal:workflow-controller:" + processUuid;
		allowedOperations = {PERMISSION_KEY_view_all_app, PERMISSION_KEY_app_subscribe};
	}
	else if (audience == InternalCapability::audienceName(InternalCapability::Audience::WorkflowRun))
	{
		capabilityAudience = InternalCapability::Audience::WorkflowRun;
		workflowId = GET_JSON_STR_VALUE(request, "workflow_id");
		runId = GET_JSON_STR_VALUE(request, "run_id");
		auto validIdentifier = [](const std::string &value)
		{
			return !value.empty() && value.size() <= 128 &&
				   std::all_of(value.begin(), value.end(),
							   [](unsigned char c) { return std::isalnum(c) || c == '-' || c == '_'; });
		};
		if (!validIdentifier(workflowId) || !validIdentifier(runId))
			throw std::invalid_argument("workflow_id and run_id must be safe identifiers");

		const auto workflow = Configuration::instance()->getApp(WORKFLOW_DEFINITION_PREFIX + workflowId, false);
		if (!workflow)
			throw NotFoundException("registered workflow was not found");
		const auto definition = workflow->AsJson(false);
		if (!definition.isMember(JSON_KEY_APP_metadata) || !definition[JSON_KEY_APP_metadata].isObject() ||
			GET_JSON_STR_VALUE(definition[JSON_KEY_APP_metadata], "type") != "workflow")
			throw AuthorizationException("capability target is not an Engine-managed workflow definition");
		ownerPrincipalId = workflow->getOwnerPrincipalId();
		if (ownerPrincipalId.empty())
			throw AuthorizationException("registered workflow has no owner Principal");
		allowedOperations = {
			PERMISSION_KEY_run_app_async, PERMISSION_KEY_view_app, PERMISSION_KEY_view_app_output,
			PERMISSION_KEY_app_delete,    PERMISSION_KEY_run_task, PERMISSION_KEY_app_subscribe,
			PERMISSION_KEY_label_view,
		};
		const auto currentPermissions = Security::instance()->permissions(ownerPrincipalId);
		// Name every missing operation so the caller can grant them all at once.
		std::string missing;
		for (const auto &operation : operations)
			if (currentPermissions.count(operation) == 0)
				missing += (missing.empty() ? "" : ", ") + operation;
		if (!missing.empty())
			throw AuthorizationException("workflow owner is missing permission(s): " + missing);
	}
	else
	{
		throw std::invalid_argument("workflow capability audience is invalid");
	}

	for (const auto &operation : operations)
		if (allowedOperations.count(operation) == 0)
			throw AuthorizationException("operation is outside the workflow capability allow-list: " + operation);

	const auto capability = InternalCapability::instance().issue(capabilityAudience, workflowId, runId, ownerPrincipalId,
																 processUuid, operations, ttlSeconds);
	const auto expiresAt =
		std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count() +
		ttlSeconds;
	Json::Value response;
	response["capability"] = capability;
	response["expires_at"] = expiresAt;
	response["owner_principal_id"] = ownerPrincipalId;
	response["process_uuid"] = processUuid;
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiWorkflowCleanupOrphans(const std::shared_ptr<HttpRequest> &message)
{
	// This is a private startup reconciliation operation, not an app-delete
	// permission. Forwarded and non-loopback requests are denied.
	if (!message->isManagedPrivateTransport())
		throw AuthorizationException("workflow orphan cleanup is available only over local loopback transports");

	const auto workflowProcess = Configuration::instance()->getApp(WORKFLOW_APP_NAME, false);
	if (!workflowProcess || !workflowProcess->isSystemProtected())
		throw AuthorizationException("managed Workflow system application is unavailable");
	const auto processUuid =
		workflowProcess->currentProcessUuidForProof(message->m_uuid, message->m_headers.get(HMAC_HTTP_HEADER));
	if (processUuid.empty())
		throw std::domain_error("workflow process proof is invalid or superseded");

	constexpr const char *stepPrefix = WORKFLOW_STEP_PREFIX;
	const auto prefixLength = std::char_traits<char>::length(stepPrefix);
	auto validIdentifier = [](const std::string &value)
	{
		return !value.empty() && value.size() <= 128 &&
			   std::all_of(value.begin(), value.end(),
						   [](unsigned char c) { return std::isalnum(c) || c == '-' || c == '_'; });
	};

	std::size_t removed = 0;
	auto config = Configuration::instance();
	for (const auto &app : config->getApps())
	{
		if (!app || app->isSystemProtected())
			continue;
		const auto &name = app->getName();
		if (name.size() <= prefixLength || name.compare(0, prefixLength, stepPrefix) != 0)
			continue;

		const auto definition = app->AsJson(false);
		if (!definition.isMember(JSON_KEY_APP_metadata) || !definition[JSON_KEY_APP_metadata].isObject())
			continue;
		const auto &metadata = definition[JSON_KEY_APP_metadata];
		if (!metadata.isMember("type") || !metadata["type"].isString() || metadata["type"].asString() != "workflow-step" ||
			!metadata.isMember("workflow_id") || !metadata["workflow_id"].isString() || !metadata.isMember("run_id") ||
			!metadata["run_id"].isString() || !metadata.isMember("process_uuid") || !metadata["process_uuid"].isString())
			continue;
		const auto workflowId = metadata["workflow_id"].asString();
		const auto runId = metadata["run_id"].asString();
		const auto creatorProcessUuid = metadata["process_uuid"].asString();
		if (!validIdentifier(workflowId) || !validIdentifier(runId) || creatorProcessUuid.empty() ||
			creatorProcessUuid == processUuid)
			continue;

		// removeApp's expected pointer makes the snapshot race-safe. A replacement
		// with the same name is not removed. Destruction runs inside removeApp
		// but outside the mutation lock, so a slow Docker backend cannot stall
		// other application management.
		if (config->removeApp(name, app.get()))
			++removed;
	}

	Json::Value response;
	response["removed"] = (Json::UInt64)removed;
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiWorkflowRegistry(const std::shared_ptr<HttpRequest> &message)
{
	// This private endpoint is the control capability's only registry view. It
	// deliberately does not expose arbitrary applications or bypass their owner
	// permissions through the synthetic Workflow controller principal.
	const auto principalId = permissionCheck(message, PERMISSION_KEY_view_all_app);
	if (principalId.compare(0, std::char_traits<char>::length("internal:workflow-controller:"),
							"internal:workflow-controller:") != 0)
	{
		throw AuthorizationException("workflow registry is available only to the managed Workflow controller");
	}

	Json::Value result = Json::Value(Json::arrayValue);
	for (const auto &app : Configuration::instance()->getApps())
	{
		if (!app || app->getName().compare(0, std::char_traits<char>::length(WORKFLOW_DEFINITION_PREFIX),
										   WORKFLOW_DEFINITION_PREFIX) != 0)
			continue;
		auto definition = app->AsJson(true);
		if (!definition.isMember(JSON_KEY_APP_metadata) || !definition[JSON_KEY_APP_metadata].isObject())
			continue;
		const auto &metadata = definition[JSON_KEY_APP_metadata];
		if (!metadata.isMember("type") || !metadata["type"].isString() || metadata["type"].asString() != "workflow")
			continue;
		addOwnerDisplayName(definition);
		result.append(definition);
	}
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiEnrollFirstAdmin(const std::shared_ptr<HttpRequest> &message)
{
	// The Agent proxies remote clients as loopback peers, so their requests carry
	// x-forwarded-host; enrollment must not be reachable through that hop.
	if (message->m_headers.contains(HTTP_HEADER_KEY_APPMESH_FORWARDED) ||
		message->m_headers.contains(HTTP_HEADER_KEY_X_Forwarded_Host) ||
		!HttpRequest::isLoopbackPeer(message->m_remote_address))
		throw AuthorizationException("first-admin enrollment requires a direct loopback client");

	// A WebSocket client presents its bearer only during the upgrade, which pins
	// the verified principal on the session (same dual path as permissionCheck).
	// HTTP/TCP callers still prove identity with the per-request Authorization header.
	std::shared_ptr<AuthorizationPrincipal> enrolled;
	if (!message->transportPrincipalId().empty())
		enrolled = Security::instance()->enrollFirstAdminPinned(message->transportPrincipalId());
	else
		enrolled = Security::instance()->enrollFirstAdmin(getBearerToken(message));
	auto response = enrolled->asJson();
	response["permissions"] = toJsonArray(Security::instance()->permissions(enrolled->id()));
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiPrincipalSelf(const std::shared_ptr<HttpRequest> &message)
{
	const auto principalId = permissionCheck(message, "");
	auto response = Security::instance()->principal(principalId)->asJson();
	response["permissions"] = toJsonArray(Security::instance()->permissions(principalId));
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiPrincipalsView(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_principal_list);
	message->reply(web::http::status_codes::OK, Security::instance()->principalsJson());
}

void RestHandler::apiPrincipalUpdate(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_principal_update);
	const auto path = Utility::decodeURIComponent(message->m_relative_uri);
	const auto principalId = regexSearch(path, REST_PATH_PRINCIPAL);
	Security::instance()->updatePrincipal(principalId, message->extractJson());
	message->reply(web::http::status_codes::OK, Security::instance()->principal(principalId)->asJson());
}

void RestHandler::apiPrincipalDelete(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_principal_delete);
	const auto path = Utility::decodeURIComponent(message->m_relative_uri);
	const auto principalId = regexSearch(path, REST_PATH_PRINCIPAL);
	Security::instance()->deletePrincipal(principalId);
	message->reply(web::http::status_codes::NoContent);
}

void RestHandler::apiRolesView(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_role_view);

	message->reply(web::http::status_codes::OK, Security::instance()->rolesJson());
}

void RestHandler::apiApiKeysView(const std::shared_ptr<HttpRequest> &message)
{
	const auto principalId = permissionCheck(message, "");
	bool all = false;
	if (message->m_query.count("all") != 0)
	{
		// Listing every principal's keys is the admin view of the policy.
		permissionCheck(message, PERMISSION_KEY_principal_list);
		all = true;
	}
	message->reply(web::http::status_codes::OK, Security::instance()->apiKeysJson(principalId, all));
}

void RestHandler::apiApiKeyIssue(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiApiKeyIssue() ";
	auto principalId = permissionCheck(message, "");
	// An admin may issue a key for another principal; everyone else issues
	// for themselves. The secret is returned exactly once, in this response.
	auto target = principalId;
	const auto &body = *message->m_body;
	if (!body.empty())
	{
		const auto json = message->extractJson();
		const auto requested = json.isObject() ? json.get("principal", "").asString() : "";
		if (!requested.empty() && requested != principalId)
		{
			permissionCheck(message, PERMISSION_KEY_principal_update);
			target = requested;
		}
	}
	const auto issued = Security::instance()->issueApiKey(target);
	LOG_INF << fname << "API key <" << issued["key_id"].asString() << "> issued to <" << target << "> by <" << principalId
			<< ">";
	// The secret is shown exactly once; no intermediary may retain it.
	message->reply(web::http::status_codes::OK, issued, {{"Cache-Control", "no-store"}});
}

void RestHandler::apiApiKeyDelete(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiApiKeyDelete() ";
	const auto principalId = permissionCheck(message, "");
	const auto path = Utility::decodeURIComponent(message->m_relative_uri);
	const auto keyId = regexSearch(path, REST_PATH_SEC_API_KEY);
	const bool manageAll = Security::instance()->permissions(principalId).count(PERMISSION_KEY_principal_update) != 0;
	if (!Security::instance()->deleteApiKey(keyId, principalId, manageAll))
		throw NotFoundException("API key not found");
	LOG_INF << fname << "API key <" << keyId << "> revoked by <" << principalId << ">";
	message->reply(web::http::status_codes::NoContent);
}

void RestHandler::apiAuthReplicationPolicy(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiAuthReplicationPolicy() ";
	// The token source is a deployment choice: the accept file (default) or a
	// secrets service (Vault). One selector, one seam; absent configuration
	// keeps the local file behavior with no external dependency.
	const auto source = Utility::stdStringTrim(Utility::getenv("APPMESH_AUTH_REPLICATION_TOKEN_SOURCE"));
	const auto vaultAddress = source == "vault"
								  ? Utility::stdStringTrim(Utility::getenv("APPMESH_AUTH_REPLICATION_TOKEN_VAULT_ADDR"))
								  : std::string();
	const auto tokenFile = Utility::stdStringTrim(Utility::getenv("APPMESH_AUTH_REPLICATION_TOKEN_FILE"));
	if (tokenFile.empty() && vaultAddress.empty())
	{
		// Feature off: answer as an unknown route so the endpoint's existence
		// does not depend on the deployment.
		LOG_DBG << fname << "replication policy requested but no replication token source is configured";
		throw NotFoundException("Path not found");
	}
	// The bearer is checked against the accepted set on every request (a short
	// TTL for a Vault source), so revocation lands on the next pull.
	const auto authorization = Utility::stdStringTrim(message->m_headers.get(HTTP_HEADER_JWT_Authorization));
	constexpr char scheme[] = "Bearer ";
	std::string presented;
	if (authorization.size() > sizeof(scheme) - 1 && authorization.compare(0, sizeof(scheme) - 1, scheme) == 0)
		presented = Utility::stdStringTrim(authorization.substr(sizeof(scheme) - 1));
	std::string matchedLabel;
	if (!vaultAddress.empty())
	{
		// Vault is the single source of truth: issuing and revoking are KV
		// operations through the operator tooling, and a Vault outage fails
		// the pull closed (the follower retries next cycle).
		const auto vaultTokenFile = Utility::stdStringTrim(Utility::getenv("APPMESH_AUTH_REPLICATION_TOKEN_VAULT_TOKEN_FILE"));
		VaultClient::Config config{vaultAddress, vaultTokenFile};
		// A Vault list is N+1 requests; the TTL cache stops a flood from holding
		// this worker. Only a successful list refreshes; an empty set is a result.
		constexpr auto TOKEN_CACHE_TTL = std::chrono::seconds(3);
		std::vector<AuthReplication::AcceptedToken> tokens;
		bool cached = false;
		{
			std::lock_guard<std::mutex> lock(m_vaultTokenCache.mutex);
			cached = m_vaultTokenCache.valid && m_vaultTokenCache.address == vaultAddress &&
					 m_vaultTokenCache.tokenFile == vaultTokenFile &&
					 std::chrono::steady_clock::now() - m_vaultTokenCache.refreshedAt < TOKEN_CACHE_TTL;
			if (cached)
				tokens = m_vaultTokenCache.tokens;
		}
		if (!cached)
		{
			try
			{
				tokens = VaultClient::listReplicationTokens(config);
			}
			catch (const std::exception &e)
			{
				LOG_WAR << fname << "replication token source unavailable: " << e.what();
				message->reply(web::http::status_codes::ServiceUnavailable,
							   Utility::text2json("replication token source unavailable"));
				return;
			}
			std::lock_guard<std::mutex> lock(m_vaultTokenCache.mutex);
			m_vaultTokenCache.address = vaultAddress;
			m_vaultTokenCache.tokenFile = vaultTokenFile;
			m_vaultTokenCache.tokens = tokens;
			m_vaultTokenCache.refreshedAt = std::chrono::steady_clock::now();
			m_vaultTokenCache.valid = true;
		}
		matchedLabel = AuthReplication::matchToken(tokens, presented);
	}
	else
	{
		std::ifstream tokenStream(tokenFile, std::ios::binary);
		if (!tokenStream)
		{
			LOG_WAR << fname << "replication token file <" << tokenFile << "> is not readable";
			throw NotFoundException("Path not found");
		}
		std::string expected((std::istreambuf_iterator<char>(tokenStream)), std::istreambuf_iterator<char>());
		matchedLabel = AuthReplication::matchToken(expected, presented);
	}
	if (matchedLabel.empty())
	{
		LOG_WAR << fname << "replication policy request rejected: invalid token from <" << message->m_remote_address << ">";
		message->reply(web::http::status_codes::Unauthorized, Utility::text2json("invalid replication token"));
		return;
	}
	LOG_INF << fname << "served the replication policy snapshot to <" << matchedLabel << "> from <"
			<< message->m_remote_address << ">";
	message->reply(web::http::status_codes::OK, Security::instance()->replicationPolicySnapshot());
}

void RestHandler::apiRoleUpdate(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiRoleUpdate() ";

	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_role_update);
	auto pathRoleName = regexSearch(path, REST_PATH_SEC_ROLE_UPDATE);

	Security::instance()->updateRole(pathRoleName, message->extractJson());

	LOG_INF << fname << "Role <" << pathRoleName << "> updated by <" << tokenUser << ">";
	message->reply(web::http::status_codes::OK, Utility::text2json("Role update success"));
}

void RestHandler::apiRoleDelete(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiRoleDelete() ";

	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_role_delete);

	auto pathRoleName = regexSearch(path, REST_PATH_SEC_ROLE_DELETE);

	Security::instance()->deleteRole(pathRoleName);

	LOG_INF << fname << "Role <" << pathRoleName << "> deleted by <" << tokenUser << ">";
	message->reply(web::http::status_codes::OK, Utility::text2json("Role delete success"));
}

void RestHandler::apiPermissionsView(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_permission_list);

	auto permissions = Security::instance()->allPermissions();
	auto json = Json::Value(Json::arrayValue);
	for (auto &perm : permissions)
	{
		json.append(std::string(perm));
	}
	message->reply(web::http::status_codes::OK, json);
}

void RestHandler::apiHealth(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_view_app);
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_HEALTH);
	const auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, false);
	auto health = app->health();
	auto body = std::to_string(health);
	message->reply(web::http::status_codes::OK, body);
}

void RestHandler::apiRestMetrics(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiRestMetrics() ";
	LOG_DBG << fname << "Entered";
	// Metrics expose host/runtime internals (host name, PID, fd counts, per-route
	// counters) like the config view, so require the same permission by default;
	// REST.MetricsRequireAuth=false is the trusted-network scraper escape hatch.
	if (Configuration::instance()->metricsRequireAuth())
	{
		const auto tokenUser = permissionCheck(message, PERMISSION_KEY_config_view);
		LOG_DBG << fname << "Metrics scraped by principal <" << tokenUser << ">";
	}

	auto body = m_metrics->collectData();
	message->reply(web::http::status_codes::OK, body, METRIC_CONTENT_TYPE);
}

void RestHandler::apiAppView(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_view_app);
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_VIEW);
	const auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, false);
	auto response = app->AsJson(true);
	addOwnerDisplayName(response);
	message->reply(web::http::status_codes::OK, response);
}

std::shared_ptr<Application> RestHandler::parseAndRegRunApp(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::parseAndRegRunApp() ";

	const auto callerPrincipalId = permissionCheck(message, "");
	auto jsonApp = message->extractJson();
	if (const auto unknown = unknownApplicationFields(jsonApp); !unknown.empty())
	{
		throw std::invalid_argument("unknown application field(s): " + unknown +
									"; see the Application schema in the REST API documentation");
	}
	// from_recover is a server-internal flag; never trust it from REST input.
	jsonApp.removeMember(JSON_KEY_APP_from_recover);
	if (GET_JSON_BOOL_VALUE(jsonApp, JSON_KEY_APP_system))
		throw AuthorizationException("system applications cannot be registered through the application API");
	auto clientProvideAppName = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name);
	std::shared_ptr<Application> fromApp;
	if (clientProvideAppName.length() > 0)
	{
		clientProvideAppName = normalizeAppName(clientProvideAppName);
		jsonApp[JSON_KEY_APP_name] = clientProvideAppName;
		fromApp = Configuration::instance()->getApp(clientProvideAppName, false);
		if (fromApp)
		{
			if (fromApp->isSystemProtected())
				throw AuthorizationException("system applications cannot be used as on-demand run templates");
			// COPY from existing application
			// require app read permission
			checkAppAccessPermission(message, fromApp, false);
			auto existApp = fromApp->AsJson(false);
			// CASE: copy existing application and run
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_command))
			{
				throw std::invalid_argument(Utility::stringFormat(
					"Should not specify command for an existing application <%s>", clientProvideAppName.c_str()));
			}
			// for run an existing app, only support re-define metadata and env
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_metadata))
			{
				existApp[JSON_KEY_APP_metadata] = jsonApp[JSON_KEY_APP_metadata];
			}
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_env))
			{
				existApp[JSON_KEY_APP_env] = jsonApp[JSON_KEY_APP_env];
			}
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_secret_env))
			{
				// Client provided fresh plaintext secret_env — leave as plaintext, no recover flag.
				existApp[JSON_KEY_APP_secret_env] = jsonApp[JSON_KEY_APP_secret_env];
			}
			else if (HAS_JSON_FIELD(existApp, JSON_KEY_APP_secret_env))
			{
				// Inherited secret_env is protected with a context containing the source app name.
				Json::Value decrypted = Json::Value(Json::objectValue);
				const auto &secretEnvs = existApp[JSON_KEY_APP_secret_env];
				for (const auto &envName : secretEnvs.getMemberNames())
				{
					const std::string context = fromApp->getName() + '\0' + envName;
					decrypted[envName] = SecretProtector::instance().unprotect(secretEnvs[envName].asString(), context);
				}
				existApp[JSON_KEY_APP_secret_env] = std::move(decrypted);
			}
			existApp[JSON_KEY_APP_name] = Configuration::instance()->generateRunAppName(clientProvideAppName);
			// Engine-injected run_base marker: identifies the registration as a run
			// instance of this base for cascade delete and exit GC (name-pattern
			// matching would be ambiguous once base names contain '_').
			existApp[JSON_KEY_APP_run_base] = clientProvideAppName;
			existApp[JSON_KEY_APP_owner_principal_id] = callerPrincipalId;
			// On-demand runs are explicit user actions and bypass the dependency gate.
			existApp.removeMember(JSON_KEY_APP_depends_on);
			jsonApp = std::move(existApp);
		}
		else
		{
			// CASE: new a application and run, client provide command
			if (!HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_command) && !HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_docker_image))
			{
				LOG_WAR << fname << "Missing required command to run application <" << clientProvideAppName << ">";
				throw std::invalid_argument("Should specify command to run application");
			}
		}
	}
	else
	{
		// CASE: new a application and run, client did not provide app name
		jsonApp[JSON_KEY_APP_name] = Utility::shortID(); // specify a UUID app name
		if (!HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_command))
		{
			throw std::invalid_argument("Should specify command run application");
		}
	}

	int timeout =
		getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
	int lifecycle = getHttpQueryValue(*message, HTTP_QUERY_KEY_lifecycle, DEFAULT_RUN_APP_LIFECYCLE_SECONDS, timeout,
									  MAX_RUN_APP_TIMEOUT_SECONDS);
	if (lifecycle == 0)
		throw std::invalid_argument("Zero timeout and lifecycle speficied");

	jsonApp[JSON_KEY_APP_enabled] = (static_cast<int>(STATUS::NOTAVAILABLE));
	jsonApp[JSON_KEY_APP_owner_principal_id] = callerPrincipalId;
	jsonApp.removeMember(JSON_KEY_APP_execution_user);
	const auto executionUser = Security::instance()->principal(callerPrincipalId)->executionUser();
	if (!executionUser.empty())
		jsonApp[JSON_KEY_APP_execution_user] = executionUser;
	auto app = Configuration::instance()->addApp(jsonApp, false);
	if (fromApp)
		LOG_INF << fname << "Run application <" << app->getName() << "> from <" << fromApp->getName() << ">";
	else
		LOG_INF << fname << "Run application <" << app->getName() << ">";

	app->scheduleRemoval(lifecycle);
	app->dump();
	return app;
}

void RestHandler::apiRunAsync(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiRunAsync() ";

	permissionCheck(message, PERMISSION_KEY_run_app_async);

	int timeout =
		getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
	auto appObj = parseAndRegRunApp(message);

	std::string processUuid;
	try
	{
		processUuid = appObj->runAsync(timeout);
	}
	catch (...)
	{
		// Remove the one-shot app when its start is rejected.
		LOG_WAR << fname << "removing rejected on-demand application <" << appObj->getName() << ">";
		Configuration::instance()->removeApp(appObj->getName(), appObj.get());
		throw;
	}
	auto result = Json::Value(Json::objectValue);
	result[JSON_KEY_APP_name] = appObj->getName();
	result[HTTP_QUERY_KEY_process_uuid] = std::move(processUuid);
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiRunSync(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_sync);

	int timeout =
		getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
	auto appObj = parseAndRegRunApp(message);

	// Use async reply here
	auto asyncRequest = std::make_shared<HttpRequestAutoCleanup>(message, appObj);
	// If the waiting client drops its connection, stop the one-shot run instead
	// of leaving it for the full lifecycle (no-op on multiplexed transports,
	// whose connection id does not map to one HTTP connection).
	HttpRequestAutoCleanup::holdForDisconnect(asyncRequest);
	appObj->runSync(timeout, asyncRequest);
}

void RestHandler::apiSendTask(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_run_task);

	// Short default so a stuck target can't hold the app's active slot for days; override via ?timeout=.
	int timeout = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_TASK_TIMEOUT_SECONDS, 0,
									MAX_RUN_APP_TIMEOUT_SECONDS);
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);

	auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, true);
	auto asyncRequest = std::make_shared<HttpRequestWithTimeout>(message);
	asyncRequest->initTimer(timeout);
	app->sendTask(asyncRequest);
}

void RestHandler::apiDeleteTask(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_run_task);

	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);

	auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, true);
	bool removed = app->deleteTask();
	message->reply(removed ? web::http::status_codes::OK : web::http::status_codes::AlreadyReported);
}

void RestHandler::apiFetchTask(const std::shared_ptr<HttpRequest> &message)
{
	if (!message->isManagedPrivateTransport() || !message->transportPrincipalId().empty())
		throw AuthorizationException("worker task RPC is available only to a managed local process");
	if (message->m_query.count("process_key") != 0)
		throw std::invalid_argument("process_key query authentication is not supported");
	const std::string processKey = Utility::stdStringTrim(message->m_headers.get(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY));
	if (processKey.empty())
		throw AuthorizationException("managed process proof is required");
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);
	auto app = Configuration::instance()->getApp(appName);

	// no need setup timer for service side request, process terminate will take care cleanup
	auto asyncRequest = std::make_shared<HttpRequestWithTimeout>(message);
	app->fetchTask(processKey, asyncRequest);
}

void RestHandler::apiReplyTask(const std::shared_ptr<HttpRequest> &message)
{
	if (!message->isManagedPrivateTransport() || !message->transportPrincipalId().empty())
		throw AuthorizationException("worker task RPC is available only to a managed local process");
	if (message->m_query.count("process_key") != 0)
		throw std::invalid_argument("process_key query authentication is not supported");
	const std::string processKey = Utility::stdStringTrim(message->m_headers.get(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY));
	if (processKey.empty())
		throw AuthorizationException("managed process proof is required");
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);

	auto app = Configuration::instance()->getApp(appName);
	// no need setup timer for service side request, process terminate will take care cleanup
	auto asyncRequest = std::make_shared<HttpRequestWithTimeout>(message);
	app->replyTask(processKey, asyncRequest);
}

void RestHandler::apiSendTaskStream(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_run_task);

	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK_STREAM);

	auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, true);

	// Only the plain-HTTP entry (DrogonAdaptor::handleTaskStream) attaches the
	// sink marker; framed transports cannot receive an SSE response.
	const auto marker = message->m_headers.get(HTTP_HEADER_KEY_X_AppMesh_Sse_Stream);
	auto sink = marker.empty() ? nullptr : SseStreamRegistry::instance()->take(marker);
	if (!sink)
	{
		message->reply(web::http::status_codes::MethodNotAllowed,
					   Utility::text2json("Task streaming requires a plain HTTP connection"));
		return;
	}

	// Short default so a stuck target can't hold the app's active slot for days; override via ?timeout=.
	int timeout = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_TASK_TIMEOUT_SECONDS, 0,
									MAX_RUN_APP_TIMEOUT_SECONDS);
	auto asyncRequest = std::make_shared<HttpRequestTaskStream>(message, std::move(sink));
	asyncRequest->initTimer(timeout);
	app->sendTask(asyncRequest);
}

void RestHandler::apiSendTaskPartial(const std::shared_ptr<HttpRequest> &message)
{
	if (!message->isManagedPrivateTransport() || !message->transportPrincipalId().empty())
		throw AuthorizationException("worker task RPC is available only to a managed local process");
	if (message->m_query.count("process_key") != 0)
		throw std::invalid_argument("process_key query authentication is not supported");
	const std::string processKey = Utility::stdStringTrim(message->m_headers.get(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY));
	if (processKey.empty())
		throw AuthorizationException("managed process proof is required");
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK_PARTIAL);

	auto app = Configuration::instance()->getApp(appName);
	const std::string payload(message->m_body->begin(), message->m_body->end());
	bool delivered = false;
	app->partialTask(processKey, payload, delivered);
	Json::Value result;
	result["delivered"] = delivered;
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiAppInput(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);

	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_INPUT);

	auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, true);
	const bool closePipe = Utility::stdStringTrim(message->m_headers.get(HTTP_HEADER_KEY_X_Input_Close)) == "true";
	const auto processUuid = message->m_query.count(HTTP_QUERY_KEY_process_uuid) != 0
								 ? message->m_query.at(HTTP_QUERY_KEY_process_uuid)
								 : std::string();
	const auto written = app->writeStdin(*message->m_body, closePipe, processUuid);
	Json::Value result;
	result["bytes_written"] = (Json::Int64)written;
	if (closePipe)
		result["closed"] = true;
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiAppOutputView(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_view_app_output);
	const auto path = (Utility::decodeURIComponent(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_OUT_VIEW);

	const auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, false);
	auto delayRequest = std::make_shared<HttpRequestOutputView>(message, app);
	delayRequest->init();
}

void RestHandler::apiAppsView(const std::shared_ptr<HttpRequest> &message)
{
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_view_all_app);
	auto response = Configuration::instance()->serializeApplication(true, tokenUser, true);
	addOwnerDisplayNames(response);
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiResourceView(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_view_host_resource);
	message->reply(web::http::status_codes::OK, ResourceCollection::instance()->AsJson());
}

void RestHandler::apiCloudResourceView(const std::shared_ptr<HttpRequest> &message)
{
	message->verifyHMAC();
	message->reply(web::http::status_codes::OK, ResourceCollection::instance()->AsJson());
}
void RestHandler::apiAgentContainerEvent(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiAgentContainerEvent() ";
	// Absent from OpenAPI: the agent's signed pushes are the only caller.
	if (!message->isManagedPrivateTransport())
		throw AuthorizationException("container events are available only over local loopback transports");

	const auto agentProcess = Configuration::instance()->getApp(SEPARATE_AGENT_APP_NAME, false);
	if (!agentProcess || !agentProcess->isSystemProtected())
		throw AuthorizationException("managed agent system application is unavailable");
	// A bad or superseded proof is an authentication failure (401), not a 403.
	if (agentProcess->currentProcessUuidForProof(message->m_uuid, message->m_headers.get(HMAC_HTTP_HEADER)).empty())
		throw std::domain_error("agent process proof is invalid or superseded");

	const auto event = message->extractJson();
	if (!event.isObject())
		throw std::invalid_argument("container event must be an object");
	const auto type = GET_JSON_STR_VALUE(event, "type");
	if (type != "die" && type != "sync")
		throw std::invalid_argument("unknown container event type <" + type + ">");

	// Every accepted push refreshes the liveness marker; die events route to the owning app.
	DockerApiProcess::noteContainerEventsAlive();
	if (type == "die")
	{
		const auto appName = GET_JSON_STR_VALUE(event, "app");
		const auto containerId = GET_JSON_STR_VALUE(event, "containerId");
		if (appName.empty() || containerId.empty())
			throw std::invalid_argument("a container die event must carry app and containerId");
		LOG_DBG << fname << "die event for container <" << containerId << "> of application <" << appName << ">";
		if (const auto app = Configuration::instance()->getApp(appName, false))
			app->reportContainerEvent(containerId);
	}
	message->reply(web::http::status_codes::OK);
}

void RestHandler::apiAppAdd(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiAppAdd() ";

	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_app_reg);
	auto jsonApp = message->extractJson();
	if (jsonApp.isNull())
	{
		throw std::invalid_argument("Empty json input");
	}
	if (const auto unknown = unknownApplicationFields(jsonApp); !unknown.empty())
	{
		throw std::invalid_argument("unknown application field(s): " + unknown +
									"; see the Application schema in the REST API documentation");
	}
	// from_recover is a server-internal flag; never trust it from REST input.
	jsonApp.removeMember(JSON_KEY_APP_from_recover);

	// The body name is authoritative; a URL/body mismatch is a client bug that
	// must not silently register a different application than the one addressed.
	const auto urlName = regexSearch(Utility::decodeURIComponent(message->m_relative_uri), REST_PATH_APP_ADD);
	const auto bodyName = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name);
	if (bodyName.empty())
		throw std::invalid_argument("application name is required in the request body");
	// regexSearch throws instead of returning empty, so urlName is always populated here.
	if (urlName != bodyName)
		throw std::invalid_argument("application name in the URL and the request body must match");

	auto appName = normalizeAppName(bodyName);
	jsonApp[JSON_KEY_APP_name] = appName;
	LOG_DBG << fname << "Registering application <" << appName << ">";
	auto config = Configuration::instance();
	const auto observed = config->getApp(appName, false);
	if (observed)
	{
		checkAppAccessPermission(message, observed, true);
		// Overwriting another principal's application is an ownership transfer:
		// it requires <app-manage-all>, never happens silently through the share
		// bits, and keeps the current owner unless one is explicitly requested.
		const bool manageAll = Security::instance()->permissions(tokenUser).count(PERMISSION_KEY_app_manage_all) != 0;
		if (!observed->getOwnerPrincipalId().empty() && observed->getOwnerPrincipalId() != tokenUser && !manageAll)
		{
			throw AuthorizationException(
				Utility::stringFormat("Principal <%s> is not allowed to EDIT app <%s>: "
									  "overwriting another owner's application requires the %s permission",
									  tokenUser.c_str(), appName.c_str(), PERMISSION_KEY_app_manage_all));
		}
	}

	// Case-variant names collide on case-insensitive filesystems. The conflicting
	// name is logged server-side; the reply stays generic (no name enumeration).
	if (!config->caseInsensitiveNameConflict(appName).empty())
	{
		message->reply(
			web::http::status_codes::Conflict,
			Utility::text2json("application name conflicts with an existing application that differs only by letter case"));
		return;
	}

	auto subscribeEvents = getHttpQueryString(*message, "subscribe_events");
	uint32_t eventMask = 0;
	if (!subscribeEvents.empty())
	{
		eventMask = parseEventMask(subscribeEvents);
		if (eventMask == 0)
		{
			message->reply(web::http::status_codes::BadRequest,
						   Utility::text2json("No valid event types in subscribe_events: " + subscribeEvents));
			return;
		}
	}

	// The registering principal owns the application. A principal holding
	// <app-manage-all> may register it on behalf of another active principal by
	// setting owner_principal_id (administrative takeover or ownership transfer);
	// any other caller is always forced to itself.
	auto ownerPrincipalId = tokenUser;
	const auto requestedOwner = GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_owner_principal_id);
	if (!requestedOwner.empty() && Security::instance()->permissions(tokenUser).count(PERMISSION_KEY_app_manage_all) != 0)
	{
		// NotFoundException maps to 404 when the target principal does not exist.
		const auto target = Security::instance()->principal(requestedOwner);
		if (!target->active())
			throw std::invalid_argument("owner_principal_id must reference an active principal: " + requestedOwner);
		ownerPrincipalId = target->id();
		LOG_INF << fname << "Application <" << appName << "> owner set to <" << ownerPrincipalId << "> by <" << tokenUser
				<< ">";
	}
	else if (observed && requestedOwner.empty() && !observed->getOwnerPrincipalId().empty() &&
			 observed->getOwnerPrincipalId() != tokenUser)
	{
		// A manage-all overwrite without an explicit transfer keeps the owner.
		ownerPrincipalId = observed->getOwnerPrincipalId();
	}
	jsonApp[JSON_KEY_APP_owner_principal_id] = ownerPrincipalId;
	jsonApp.removeMember(JSON_KEY_APP_execution_user);
	const auto executionUser = Security::instance()->principal(ownerPrincipalId)->executionUser();
	if (!executionUser.empty())
		jsonApp[JSON_KEY_APP_execution_user] = executionUser;
	std::string subId;
	Json::Value result;
	bool stale = false;
	try
	{
		{
			// Keep same-name validation and subscription atomic. addApp performs
			// its own atomic map replacement and runs its slow replacement and
			// start-up work outside the mutation lock.
			const auto mutation = config->lockAppMutation();
			if (!config->isCurrentApp(appName, observed))
				stale = true;
			else if (eventMask != 0)
			{
				ConnectionKey connKey;
				DeliveryCallback deliveryCb;
				if (buildDeliveryCallback(message, connKey, deliveryCb))
					subId = EventDispatcher::instance()->subscribe(appName, eventMask, tokenUser, std::move(deliveryCb),
																   connKey);
			}
		}
		if (stale)
		{
			message->reply(web::http::status_codes::Conflict);
			return;
		}
		else
		{
			// addApp re-checks under its own lock; a racer past the check above still gets 409.
			auto app = config->addApp(jsonApp, true, observed, true);
			if (!app)
			{
				if (!subId.empty())
					EventDispatcher::instance()->unsubscribe(subId);
				message->reply(web::http::status_codes::Conflict);
				return;
			}
			// Use returnRuntimeInfo=true so the response strips encrypted secret_env.
			result = app->AsJson(true);
		}
		if (!subId.empty())
		{
			result["subscription_id"] = subId;
		}
		addOwnerDisplayName(result);
		message->reply(web::http::status_codes::OK, result);
	}
	catch (...)
	{
		if (!subId.empty())
		{
			EventDispatcher::instance()->unsubscribe(subId);
		}
		throw;
	}
}

bool RestHandler::buildDeliveryCallback(const std::shared_ptr<HttpRequest> &message, ConnectionKey &connKey,
										DeliveryCallback &deliveryCb)
{
	auto forwardRoute = message->m_headers.contains(HTTP_HEADER_KEY_APPMESH_FORWARDED) &&
								message->m_headers.contains(HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE)
							? message->m_headers.get(HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE)
							: std::string();
	if (message->wsReplyContext() && message->wsReplyContext()->getProtocolType() == WSS::ReplyContext::ProtocolType::Framed)
	{
		auto wsCtx = message->wsReplyContext();
		connKey = ConnectionKey::wss(wsCtx->getNumericId());
		deliveryCb = [wsCtx, forwardRoute = std::move(forwardRoute)](const EventEnvelope &envelope) -> bool
		{
			if (wsCtx->isAborted())
				return false;
			try
			{
				auto resp = std::make_unique<Response>();
				resp->uuid = Utility::shortID();
				resp->request_uri = "/appmesh/event";
				resp->http_status = web::http::status_codes::OK;
				resp->body_msg_type = web::http::mime_types::application_json;
				auto bodyStr = envelope.toJson();
				resp->body = std::vector<std::uint8_t>(bodyStr.begin(), bodyStr.end());
				resp->headers[HTTP_HEADER_KEY_X_Subscription_Id] = envelope.subscriptionId;
				resp->headers[HTTP_HEADER_KEY_X_Event_Type] = envelope.eventType;
				resp->headers[HTTP_HEADER_KEY_X_App_Name] = envelope.appName;
				if (!forwardRoute.empty())
					resp->headers[HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE] = forwardRoute;

				wsCtx->replyWebSocket(resp->serialize(), false, true);
				return true;
			}
			catch (...)
			{
				return false;
			}
		};
		return true;
	}
	return false;
}

void RestHandler::apiAppSubscribe(const std::shared_ptr<HttpRequest> &message)
{
	REST_INFO_PRINT;
	const auto userName = permissionCheck(message, PERMISSION_KEY_app_subscribe);
	const auto path = Utility::decodeURIComponent(message->m_relative_uri);

	std::string appName = "*";
	auto config = Configuration::instance();
	std::shared_ptr<Application> observed;
	if (path != REST_PATH_APP_SUBSCRIBE_ALL)
	{
		appName = regexSearch(path, REST_PATH_APP_SUBSCRIBE);
		observed = config->getApp(appName);
		checkAppAccessPermission(message, observed, false);
	}
	else
	{
		// Wildcard subscribe requires view-all-app permission
		permissionCheck(message, PERMISSION_KEY_view_all_app);
	}

	auto events = getHttpQueryString(*message, "events");
	uint32_t eventMask = parseEventMask(events);
	if (eventMask == 0)
	{
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("No valid event types in: " + events));
		return;
	}

	ConnectionKey connKey;
	DeliveryCallback deliveryCb;
	if (!buildDeliveryCallback(message, connKey, deliveryCb))
	{
		message->reply(web::http::status_codes::MethodNotAllowed,
					   Utility::text2json("Subscribe requires a persistent connection (TCP or WebSocket)"));
		return;
	}

	std::unique_lock<std::recursive_mutex> mutation;
	if (observed)
	{
		mutation = config->lockAppMutation();
		if (!config->isCurrentApp(appName, observed))
		{
			mutation.unlock();
			message->reply(web::http::status_codes::Conflict);
			return;
		}
	}
	auto subId = EventDispatcher::instance()->subscribe(appName, eventMask, userName, std::move(deliveryCb), connKey);
	if (mutation.owns_lock())
		mutation.unlock();

	Json::Value result;
	result["subscription_id"] = subId;
	result["app_name"] = appName;
	Json::Value eventList = Json::Value(Json::arrayValue);
	for (uint32_t bit = 0x01; bit <= static_cast<uint32_t>(AppEventType::APP_REMOVED); bit <<= 1)
	{
		if (eventMask & bit)
			eventList.append(eventTypeToString(static_cast<AppEventType>(bit)));
	}
	result["events"] = eventList;
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiAppUnsubscribe(const std::shared_ptr<HttpRequest> &message)
{
	REST_INFO_PRINT;
	const auto userName = permissionCheck(message, PERMISSION_KEY_app_subscribe);

	auto subId = getHttpQueryString(*message, "subscription_id");
	if (subId.empty())
	{
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("Missing query parameter: subscription_id"));
		return;
	}

	if (EventDispatcher::instance()->unsubscribe(subId, userName))
	{
		message->reply(web::http::status_codes::OK, Utility::text2json("unsubscribed"));
	}
	else
	{
		message->reply(web::http::status_codes::NotFound,
					   Utility::text2json(std::string("Subscription not found: ") + subId));
	}
}
