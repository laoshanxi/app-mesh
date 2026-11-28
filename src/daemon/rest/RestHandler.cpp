// src/daemon/rest/RestHandler.cpp
#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <mutex>
#include <set>
#include <tuple>

#include <boost/algorithm/string_regex.hpp>

#include "../../common/DurationParse.h"
#include "../../common/json.h"
#include "../../common/RestClient.h"
#include "../../common/TimerHandler.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.h"
#include "../Configuration.h"
#include "../Label.h"
#include "../ResourceCollection.h"
#include "../application/Application.h"
#include "../process/DockerApiProcess.h"
#include "../security/HMACVerifier.h"
#include "../security/InternalCapability.h"
#include "../security/SecretProtector.h"
#include "../security/Security.h"
#include "../../common/lwsservice/WebSocketService.h"
#include "EventDispatcher.h"
#include "FileTransferHandler.h"
#include "HttpRequest.h"
#include "PrometheusRest.h"
#include "RestHandler.h"
#include "SseSink.h"
#include "SocketServer.h"

// Content-type constants
constexpr auto CONTENT_TYPE_HTML = "text/html; charset=utf-8";
constexpr auto CONTENT_TYPE_YAML = "application/x-yaml";
constexpr auto CONTENT_TYPE_SVG = "image/svg+xml";
constexpr auto CONTENT_TYPE_PNG = "image/png";

namespace
{

	// Some transports render IPv6 without '::' compression and a dual-stack 127.0.0.1
	// peer as v4-mapped "0000:...:ffff:7fxx:xxxx", so parse the 8-group form explicitly.
	bool isUncompressedIpv6Loopback(const std::string &peer)
	{
		if (peer.empty() || peer.size() >= 64 || peer.find("::") != std::string::npos)
			return false;
		unsigned int g[8];
		if (sscanf(peer.c_str(), "%x:%x:%x:%x:%x:%x:%x:%x",
				&g[0], &g[1], &g[2], &g[3], &g[4], &g[5], &g[6], &g[7]) != 8)
			return false;
		const bool leadingZero = !g[0] && !g[1] && !g[2] && !g[3] && !g[4];
		return (leadingZero && !g[5] && !g[6] && g[7] == 1) ||			 // ::1
			   (leadingZero && g[5] == 0xffff && (g[6] >> 8) == 0x7f); // ::ffff:127.x.x.x
	}

	bool isLoopbackPeer(std::string peer)
	{
		peer = Utility::stdStringTrim(peer);
		if (peer.empty())
			return false;

		// Agent uses net/http RemoteAddr (host:port); direct listeners record only the
		// socket address. Never consult Forwarded or X-Forwarded-* for this decision.
		if (peer.front() == '[')
		{
			const auto end = peer.find(']');
			if (end == std::string::npos)
				return false;
			const auto suffix = peer.substr(end + 1);
			if (!suffix.empty() && suffix.front() != ':')
				return false;
			peer = peer.substr(1, end - 1);
		}
		else if (peer.rfind("127.0.0.1:", 0) == 0)
		{
			peer = "127.0.0.1";
		}

		return peer == "127.0.0.1" || peer == "::1" || isUncompressedIpv6Loopback(peer);
	}

	// Keep immutable ownership and mutable presentation separate. This field is
	// added only to API responses; persistence and authorization continue to use
	// owner_principal_id exclusively.
	void addOwnerDisplayName(nlohmann::json &application)
	{
		if (!application.is_object())
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

	void addOwnerDisplayNames(nlohmann::json &applications)
	{
		if (!applications.is_array())
			return;
		for (auto &application : applications)
			addOwnerDisplayName(application);
	}

	// Workflow identifiers and secret_env keys share the schema's safe patterns.
	bool validWorkflowSecretIdentifier(const std::string &value)
	{
		return !value.empty() && value.size() <= 128 &&
			   std::all_of(value.begin(), value.end(),
						   [](unsigned char c) { return std::isalnum(c) || c == '-' || c == '_'; });
	}

	bool validWorkflowSecretKey(const std::string &value)
	{
		if (value.empty() || value.size() > 255)
			return false;
		if (!(std::isalpha(static_cast<unsigned char>(value[0])) || value[0] == '_'))
			return false;
		return std::all_of(value.begin(), value.end(),
						   [](unsigned char c) { return std::isalnum(c) || c == '_'; });
	}

	// Broker call bounds.
	constexpr std::size_t MAX_WORKFLOW_SECRET_ENTRIES = 128;
	constexpr std::size_t MAX_WORKFLOW_SECRET_VALUE_SIZE = 1024 * 1024;
	constexpr std::size_t MAX_WORKFLOW_SECRET_TOTAL_SIZE = 4 * 1024 * 1024;

	// Sync-run held request: HttpRequestAutoCleanup's post-reply app cleanup,
	// plus the task RPC's explicit 408 at the requested timeout. The run's own
	// completion reply must not beat the timeout past it: a container teardown
	// (stop/kill/delete/log archive) trails the timeout kill by seconds, and
	// today's completion then answers a success-shaped 200-empty long after the
	// caller asked to wait.
	constexpr std::int64_t SYNC_RUN_REPLY_GRACE_MS = 1500;
	// TimerHandler must stay public: the timer registry binds this object through
	// its enable_shared_from_this base, which private inheritance would break.
	class HttpRequestSyncRun final : public HttpRequestAutoCleanup, public TimerHandler
	{
	public:
		HttpRequestSyncRun(const std::shared_ptr<HttpRequest> &message, const std::shared_ptr<Application> &appObj)
			: HttpRequestAutoCleanup(message, appObj), m_timerResponseId(INVALID_TIMER_ID), m_httpRequestReplyFlag(false)
		{
		}

		~HttpRequestSyncRun() override
		{
			// Same leak guard as HttpRequestWithTimeout: the gate makes this a no-op once any reply went out.
			HttpRequest::reply(web::http::status_codes::ServiceUnavailable);
		}

		void initTimeout(int timeoutSeconds)
		{
			if (timeoutSeconds <= 0)
				return;
			// The grace period lets the engine's own timeout kill land first and reply
			// with the real exit code (process exit is sub-millisecond); only teardowns
			// that keep trailing past it fall through to the 408.
			registerTimer(m_timerResponseId, 1000L * timeoutSeconds + SYNC_RUN_REPLY_GRACE_MS, 0, "HttpRequestSyncRun",
						  std::bind(&HttpRequestSyncRun::onTimerResponse, this));
		}

		// A rejected start owns no run: cancel the timeout and suppress the
		// destructor's bare 503, so handleRest answers the rethrown failure once
		// with its real status and reason.
		void abandonFailedStart()
		{
			cancelTimer(m_timerResponseId);
			m_httpRequestReplyFlag.store(true);
		}

	private:
		bool onTimerResponse()
		{
			HttpRequest::reply(web::http::status_codes::RequestTimeout,
							   Utility::text2json("run timed out: the application did not finish within the requested timeout"));
			return false;
		}

		bool reply(const std::string &requestUri, const std::string &uuid, const std::vector<std::uint8_t> &body,
				   const std::map<std::string, std::string> &headers, const web::http::status_code &status,
				   const std::string &bodyType) const override
		{
			// Same pattern as HttpRequestWithTimeout: cancel the timeout from the reply path (mutable
			// member keeps the id non-const; the const_cast covers the non-const cancelTimer method).
			const_cast<HttpRequestSyncRun *>(this)->cancelTimer(m_timerResponseId);
			if (!m_httpRequestReplyFlag.exchange(true))
				return HttpRequest::reply(requestUri, uuid, body, headers, status, bodyType);
			return false;
		}

		mutable std::atomic_long m_timerResponseId;
		mutable std::atomic<bool> m_httpRequestReplyFlag;
	};

	// Shared X-File-Path prologue of the file endpoints: replies (400/403) and
	// returns false when the header is missing or the path fails the jail.
	bool requiredFilePath(const std::shared_ptr<HttpRequest> &message, std::string &file)
	{
		if (0 == message->m_headers.count(HTTP_HEADER_KEY_file_path))
		{
			message->reply(web::http::status_codes::BadRequest, Utility::text2json("header 'X-File-Path' not found"));
			return false;
		}
		file = Utility::decodeHeaderFilePath(message->m_headers.find(HTTP_HEADER_KEY_file_path)->second);
		if (!Utility::validateFilePath(file, Configuration::instance()->getFileAllowedBaseDir()))
		{
			message->reply(web::http::status_codes::Forbidden, Utility::text2json("File path is not allowed"));
			return false;
		}
		return true;
	}

	// Packaged workflow roles (authorization.yaml) admitted by the run_task gate.
	constexpr auto WORKFLOW_RUNNER_ROLE = "appmesh-workflow-runner";
	constexpr auto PERMISSION_workflow_admin = "workflow-admin";

	// Whether the caller holds a workflow role: the packaged runner role or the
	// workflow-admin permission. Store lookups throw for an unprovisioned
	// principal; such a caller simply falls back to the owner/EDIT gate.
	bool hasWorkflowTaskRole(const std::string &principalId)
	{
		try
		{
			const auto principal = Security::instance()->principal(principalId);
			if (principal && principal->roles().count(WORKFLOW_RUNNER_ROLE) != 0)
				return true;
			return Security::instance()->permissions(principalId).count(PERMISSION_workflow_admin) != 0;
		}
		catch (const std::exception &)
		{
			return false;
		}
	}

	// Synthetic connection key namespace for SSE stream subscriptions: no live
	// transport sits behind them, teardown is explicit (unsubscribe on end).
	std::atomic<uint64_t> g_nextSseConnectionKey{1};

	uint64_t nextSseConnectionKey()
	{
		return g_nextSseConnectionKey.fetch_add(1);
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
constexpr auto REST_PATH_INTERNAL_WORKFLOW_SECRET = "/appmesh/internal/workflow/secret";
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
// SSE stdout replay from a cursor plus live follow until exit/removed/timeout.
constexpr auto REST_PATH_APP_OUTPUT_STREAM = R"(/appmesh/app/([^/\*]+)/output/stream)";

// 6. File Management
constexpr auto REST_PATH_FILE_DOWNLOAD = "/appmesh/file/download";
constexpr auto REST_PATH_FILE_UPLOAD = "/appmesh/file/upload";
constexpr auto REST_PATH_FILE_DELETE = "/appmesh/file/delete";

// 7. Label Management
constexpr auto REST_PATH_LABEL_VIEW_ALL = "/appmesh/labels";
constexpr auto REST_PATH_LABEL_ADD = R"(/appmesh/label/([^/\*]+))";
constexpr auto REST_PATH_LABEL_DELETE = R"(/appmesh/label/([^/\*]+))";

// 8. Config
constexpr auto REST_PATH_CONFIG_VIEW = "/appmesh/config";
constexpr auto REST_PATH_CONFIG_SET = "/appmesh/config";

// 9. Security
constexpr auto REST_PATH_PRINCIPAL_SELF = "/appmesh/principal/self";
constexpr auto REST_PATH_SEC_ROLE_VIEW_ALL = "/appmesh/roles";
constexpr auto REST_PATH_SEC_ROLE_UPDATE = R"(/appmesh/role/([^/\*]+))";
constexpr auto REST_PATH_SEC_ROLE_DELETE = R"(/appmesh/role/([^/\*]+))";
constexpr auto REST_PATH_PRINCIPAL_PERMISSIONS = "/appmesh/principal/self/permissions";
constexpr auto REST_PATH_SEC_API_KEYS = "/appmesh/security/apikeys";
constexpr auto REST_PATH_SEC_API_KEY = R"(/appmesh/security/apikey/([^/\*]+))";
constexpr auto REST_PATH_SEC_PERM_VIEW_ALL = "/appmesh/permissions";
constexpr auto REST_PATH_PRINCIPALS = "/appmesh/principals";
constexpr auto REST_PATH_PRINCIPAL = R"(/appmesh/principal/([^/\*]+))";

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
	bindRestMethod(web::http::methods::GET, "/openapi.yaml", std::bind(&RestHandler::apiOpenApi, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/index.html", std::bind(&RestHandler::apiIndex, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, "/", std::bind(&RestHandler::apiIndex, this, std::placeholders::_1));

	// 1. Authentication
	bindRestMethod(web::http::methods::GET, REST_PATH_AUTH_CONFIG, std::bind(&RestHandler::apiAuthConfig, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_LOGO, std::bind(&RestHandler::apiLogo, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_FAVICON, std::bind(&RestHandler::apiFavicon, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_OAUTH_CALLBACK, std::bind(&RestHandler::apiOauthCallback, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_PROTECTED_RESOURCE_METADATA, std::bind(&RestHandler::apiProtectedResourceMetadata, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_INTERNAL_WORKFLOW_CAPABILITY, std::bind(&RestHandler::apiWorkflowCapability, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_INTERNAL_AGENT_CONTAINER_EVENT, std::bind(&RestHandler::apiAgentContainerEvent, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_INTERNAL_WORKFLOW_CLEANUP_ORPHANS, std::bind(&RestHandler::apiWorkflowCleanupOrphans, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_INTERNAL_WORKFLOW_REGISTRY, std::bind(&RestHandler::apiWorkflowRegistry, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_INTERNAL_WORKFLOW_SECRET,
				   std::bind(&RestHandler::apiWorkflowSecret, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_ENROLL_FIRST_ADMIN, std::bind(&RestHandler::apiEnrollFirstAdmin, this, std::placeholders::_1));

	// 2. View Application
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_VIEW, std::bind(&RestHandler::apiAppView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_OUT_VIEW, std::bind(&RestHandler::apiAppOutputView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_ALL_VIEW, std::bind(&RestHandler::apiAppsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_HEALTH, std::bind(&RestHandler::apiHealth, this, std::placeholders::_1));

	// 3. Cloud Application
	bindRestMethod(web::http::methods::GET, REST_PATH_CLOUD_RESOURCES_VIEW, std::bind(&RestHandler::apiCloudResourceView, this, std::placeholders::_1));

	// 4. Manage Application
	bindRestMethod(web::http::methods::PUT, REST_PATH_APP_ADD, std::bind(&RestHandler::apiAppAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_ENABLE, std::bind(&RestHandler::apiAppEnable, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_DISABLE, std::bind(&RestHandler::apiAppDisable, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_DELETE, std::bind(&RestHandler::apiAppDelete, this, std::placeholders::_1));

	// 5. Operate Application
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_RUN_ASYNC, std::bind(&RestHandler::apiRunAsync, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_RUN_SYNC, std::bind(&RestHandler::apiRunSync, this, std::placeholders::_1));
	// The /task regex is a strict full match, but keep the longer paths bound
	// first so the dispatch table reads most-specific-first.
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_TASK_STREAM, std::bind(&RestHandler::apiSendMessageStream, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_TASK_PARTIAL, std::bind(&RestHandler::apiSendMessagePartial, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_INPUT, std::bind(&RestHandler::apiAppInput, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_OUTPUT_STREAM, std::bind(&RestHandler::apiAppOutputStream, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_TASK, std::bind(&RestHandler::apiSendMessage, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_TASK, std::bind(&RestHandler::apiRemoveMessage, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_TASK, std::bind(&RestHandler::apiGetMessage, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, REST_PATH_APP_TASK, std::bind(&RestHandler::apiSendMessageResponse, this, std::placeholders::_1));

	// 6. File Management
	bindRestMethod(web::http::methods::GET, REST_PATH_FILE_DOWNLOAD, std::bind(&RestHandler::apiFileDownload, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_FILE_UPLOAD, std::bind(&RestHandler::apiFileUpload, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_FILE_DELETE, std::bind(&RestHandler::apiFileDelete, this, std::placeholders::_1));

	// 7. Label Management
	bindRestMethod(web::http::methods::GET, REST_PATH_LABEL_VIEW_ALL, std::bind(&RestHandler::apiLabelsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, REST_PATH_LABEL_ADD, std::bind(&RestHandler::apiLabelAdd, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_LABEL_DELETE, std::bind(&RestHandler::apiLabelDel, this, std::placeholders::_1));

	// 8. Config
	bindRestMethod(web::http::methods::GET, REST_PATH_CONFIG_VIEW, std::bind(&RestHandler::apiBasicConfigView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_CONFIG_SET, std::bind(&RestHandler::apiBasicConfigSet, this, std::placeholders::_1));

	// 9. Security
	bindRestMethod(web::http::methods::GET, REST_PATH_PRINCIPAL_SELF, std::bind(&RestHandler::apiPrincipalSelf, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_PRINCIPALS, std::bind(&RestHandler::apiPrincipalsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_PRINCIPAL, std::bind(&RestHandler::apiPrincipalUpdate, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_PRINCIPAL, std::bind(&RestHandler::apiPrincipalDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_ROLE_VIEW_ALL, std::bind(&RestHandler::apiRolesView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_ROLE_UPDATE, std::bind(&RestHandler::apiRoleUpdate, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_SEC_ROLE_DELETE, std::bind(&RestHandler::apiRoleDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_PRINCIPAL_PERMISSIONS, std::bind(&RestHandler::apiPrincipalPermissionsView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_API_KEYS,
				   std::bind(&RestHandler::apiApiKeysView, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_SEC_API_KEYS,
				   std::bind(&RestHandler::apiApiKeyIssue, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_SEC_API_KEY,
				   std::bind(&RestHandler::apiApiKeyDelete, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_SEC_PERM_VIEW_ALL, std::bind(&RestHandler::apiPermissionsView, this, std::placeholders::_1));

	// 10. metrics
	bindRestMethod(web::http::methods::GET, METRIC_PATH, std::bind(&RestHandler::apiRestMetrics, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_PROMETHEUS_METRICS, std::bind(&RestHandler::apiRestMetrics, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_RESOURCE_VIEW, std::bind(&RestHandler::apiResourceView, this, std::placeholders::_1));

	// 11. Subscribe
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_SUBSCRIBE, std::bind(&RestHandler::apiAppSubscribe, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_SUBSCRIBE_ALL, std::bind(&RestHandler::apiAppSubscribe, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_SUBSCRIBE, std::bind(&RestHandler::apiAppUnsubscribe, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_SUBSCRIBE_ALL, std::bind(&RestHandler::apiAppUnsubscribe, this, std::placeholders::_1));
}

RestHandler::~RestHandler()
{
	const static char fname[] = "RestHandler::~RestHandler() ";
	LOG_INF << fname << "RestHandler destroyed";
}

std::string RestHandler::normalizedHttpRoute(const std::string &path,
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
	message->setReplyMetricCallback([metrics, method = std::move(method), route = std::move(route), started](int status)
									{
		const auto duration = std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count();
		metrics->httpRequestFinished(method, route, status, duration); });
}

std::shared_ptr<CounterMetric> RestHandler::createPromCounter(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels)
{
	return m_metrics->createPromCounter(metricName, metricHelp, labels);
}

std::shared_ptr<GaugeMetric> RestHandler::createPromGauge(const std::string &metricName, const std::string &metricHelp, const std::map<std::string, std::string> &labels)
{
	return m_metrics->createPromGauge(metricName, metricHelp, labels);
}

uint64_t RestHandler::prometheusScrapeGeneration() const
{
	return m_metrics->scrapeGeneration();
}

void RestHandler::refreshPrometheusProcessMetrics(void *processSnapshot)
{
	m_metrics->refreshProcessMetrics(processSnapshot);
}

// Static content serving utilities
const std::string &RestHandler::getOpenApiContent()
{
	static const std::string content = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / "script" / "openapi.yaml").string());
	return content;
}

const std::string &RestHandler::getLogoContent()
{
	static const std::string content = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / "script" / "logo.svg").string());
	return content;
}

const std::string &RestHandler::getFaviconContent()
{
	static const std::string content = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / "script" / "favicon.png").string());
	return content;
}

const std::string &RestHandler::getIndexHtmlContent()
{
	static const std::string content = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / "script" / "index.html").string());
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

// The browser lands on <browser_entry-origin>/oauth/callback after the
// authorization-code flow. The static page hands the unchanged query string to
// the web UI origin carried in the state parameter, and only to the fixed
// /oauth/callback path on that origin. PKCE keeps a relayed code useless to any
// other origin. Public like the login page itself.
// The relay page runs one pinned inline script; the daemon-wide
// "default-src 'none'" CSP would block it, so this response overrides the
// policy with the script's SHA-256 hash (base64 of the exact bytes between
// <script> and </script>, leading and trailing newlines included). Byte-identical
// copy in the Go agent (auth_relay.go); the hash must match on both sides.
constexpr auto OAUTH_CALLBACK_RELAY_CSP =
	"default-src 'none'; script-src 'sha256-WJHBkicVdWDq2OxtXiYCx4BCaK7EV2KyjwBP8/UzM6Q='; frame-ancestors 'none'";

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

	auto host = message->m_headers.get("host");
	if (host.empty())
		host = message->m_headers.get("Host");

	// The openapi URL must use the scheme this daemon actually serves.
	const std::string scheme = Configuration::instance()->getSslEnabled() ? "https" : "http";
	std::string swaggerUrl = "https://petstore.swagger.io/?url=" + scheme + "://" + host + "/openapi.yaml";
	std::map<std::string, std::string> headers;
	headers["Location"] = std::move(swaggerUrl);

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

void RestHandler::checkAppAccessPermission(const std::shared_ptr<HttpRequest> &message, const std::shared_ptr<Application> &app, bool requestWrite)
{
	const auto tokenUser = permissionCheck(message, "");
	const auto &appName = app->getName();
	if (!Configuration::instance()->checkOwnerPermission(tokenUser, app->getOwnerPrincipalId(), app->getOwnerPermission(), requestWrite))
	{
		throw AuthorizationException(Utility::stringFormat("Principal <%s> is not allowed to <%s> app <%s>", tokenUser.c_str(), (requestWrite ? "EDIT" : "VIEW"), appName.c_str()));
	}
	if (requestWrite && appName == SEPARATE_AGENT_APP_NAME)
	{
		throw std::invalid_argument("REST service application is not allowed to <EDIT>");
	}
}

long RestHandler::getHttpQueryValue(const HttpRequest &message, const std::string &key, long defaultValue, long min, long max)
{
	// const static char fname[] = "RestHandler::getHttpQueryValue() ";

	auto querymap = message.m_query;
	long rt = defaultValue;
	if (querymap.find((key)) != querymap.end())
	{
		const auto &value = querymap.find((key))->second;
		rt = DurationParse::parse(value);
		// Negative is never valid for these params; fall back to default so it can't wrap
		// into size_t or drive negative offsets/overflowing timers downstream.
		if (rt < 0)
			rt = defaultValue;
		else if (min < max && (rt < min || rt > max))
			rt = defaultValue;
	}
	// LOG_DBG << fname << key << "=" << rt;
	return rt;
}
long RestHandler::getHttpQueryPosition(const HttpRequest &message, const std::string &key, long defaultValue,
									   long min, long max)
{
	// Positions and indices are plain integers (byte offsets, nanosecond log
	// cursors), not durations: the duration parser rejects values beyond int
	// range, which a cursor legitimately exceeds.
	long rt = defaultValue;
	const auto it = message.m_query.find(key);
	if (it != message.m_query.end())
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

	auto querymap = message.m_query;
	std::string rt;
	if (querymap.find((key)) != querymap.end())
	{
		rt = (querymap.find((key))->second);
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

void RestHandler::apiAppEnable(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	const auto path = (curlpp::unescape(message->m_relative_uri));
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
	// Invoke the scheduler pass immediately like registration does, so the first
	// start (and its failure's last_error) is settled before this response — the
	// caller sees the same state an add would report, not a fixed success text.
	app->execute(nullptr, false);
	auto result = app->AsJson(true);
	addOwnerDisplayName(result);
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiAppDisable(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	const auto path = (curlpp::unescape(message->m_relative_uri));
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
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_DELETE);

	// Authenticate before the existence lookup so an anonymous caller cannot tell 404 from 401.
	const auto tokenUser = permissionCheck(message, "");

	auto config = Configuration::instance();
	auto app = config->getApp(appName, false);
	if (!app)
	{
		message->reply(web::http::status_codes::NotFound);
	}
	else
	{
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
		message->reply(web::http::status_codes::OK, Utility::text2json(Utility::stringFormat("Application <%s> removed.", appName.c_str())));
	}
}

void RestHandler::apiFileDownload(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiFileDownload() ";

	permissionCheck(message, PERMISSION_KEY_file_download);
	std::string file;
	if (!requiredFilePath(message, file))
		return;

	if (!Utility::isFileExist(file))
	{
		message->reply(web::http::status_codes::NotAcceptable, Utility::text2json("file not found"));
		return;
	}

	LOG_DBG << fname << "Downloading file <" << file << ">";

	std::map<std::string, std::string> headers;
	auto fileInfo = os::fileStat(file);
	headers[HTTP_HEADER_KEY_file_mode] = std::to_string(std::get<0>(fileInfo));
	headers[HTTP_HEADER_KEY_file_user] = std::get<1>(fileInfo);
	headers[HTTP_HEADER_KEY_file_group] = std::get<2>(fileInfo);
	auto body = HttpRequest::emptyJsonMessage();
	if (message->m_headers.count(HTTP_HEADER_KEY_X_Recv_File_Socket) && message->m_headers.find(HTTP_HEADER_KEY_X_Recv_File_Socket)->second == "true")
	{
		LOG_DBG << fname << "Download file from socket";
		headers[HTTP_HEADER_KEY_X_Recv_File_Socket] = Utility::encode64(file);
		body = Utility::text2json("Please recieve file from socket");
		message->reply(web::http::status_codes::OK, body, headers);
		return;
	}
	if (0 == message->m_headers.count(HTTP_HEADER_KEY_APPMESH_FORWARDED))
	{
		// WebSocket clients reuse their original Dex bearer; never echo it in a response.
		message->reply(web::http::status_codes::OK, body, headers);
		return;
	}

	// A forwarded request has no socket to stream on: the file content is the
	// response body (bounded; larger files need a streaming surface).
	// Open-then-verify: the fd pins the inode that passed the jail check, so the
	// body can only come from the validated file, never a swapped symlink component.
	std::string resolvedPath;
	bool jailRejected = false;
	const int fd = Utility::openFileWithinJail(file, false, Configuration::instance()->getFileAllowedBaseDir(),
											   resolvedPath, &jailRejected);
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
		// attach(), not the fd ctor, whose good()==false the read check below would misread as failure.
		FdFileStream input;
		input.attach(fd); // owns the descriptor
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
	std::string file;
	if (!requiredFilePath(message, file))
		return;

	boost::system::error_code pathEc;
	// Same leaf rule as the transfer faces: a symlink leaf answers a misleading 409 or silently swaps the link.
	if (fs::is_symlink(file, pathEc))
	{
		message->reply(web::http::status_codes::BadRequest, Utility::text2json("Symlinks not allowed"));
		return;
	}
	if (fs::is_directory(file, pathEc))
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
	if (message->m_headers.count(HTTP_HEADER_KEY_X_Send_File_Socket) && message->m_headers.find(HTTP_HEADER_KEY_X_Send_File_Socket)->second == "true")
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
		const auto tempFile = file + "." + Utility::shortID() + ".part";
		FileUploadInfo upload(file, tempFile, message->m_headers, overwrite,
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
		nlohmann::json respJson;
		respJson["status"] = "success";
		respJson["file"] = fs::path(file).filename().string();
		respJson["size"] = message->m_body->size();
		message->reply(web::http::status_codes::OK, respJson);
		return;
	}
	else
	{
		// WebSocket clients reuse their original Dex bearer; never echo it in a response.
		message->reply(web::http::status_codes::OK, body, headers);
	}
	// set permission
	Utility::applyFilePermission(file, message->m_headers);
}

void RestHandler::apiFileDelete(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiFileDelete() ";
	permissionCheck(message, PERMISSION_KEY_file_delete);
	std::string file;
	if (!requiredFilePath(message, file))
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

	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto labelKey = regexSearch(path, REST_PATH_LABEL_ADD, "Invalid label key");

	auto querymap = message->m_query;
	if (querymap.find((HTTP_QUERY_KEY_label_value)) != querymap.end())
	{
		const auto &value = (querymap.find((HTTP_QUERY_KEY_label_value))->second);

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

void RestHandler::apiLabelDel(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiLabelDel() ";
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_label_delete);

	const auto path = (curlpp::unescape(message->m_relative_uri));
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
	auto json = nlohmann::json::array();
	for (auto &perm : permissions)
	{
		json.push_back(std::string(perm));
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
	// A hot update never rebinds a listener; an unchanged value is the
	// idempotent no-op of posting the GET document back.
	if (json.is_object() && json.contains(JSON_KEY_REST) && json.at(JSON_KEY_REST).is_object() &&
		json.at(JSON_KEY_REST).contains(JSON_KEY_SSL) && json.at(JSON_KEY_REST).at(JSON_KEY_SSL).is_object() &&
		json.at(JSON_KEY_REST).at(JSON_KEY_SSL).contains(JSON_KEY_SSLEnabled))
	{
		const auto &requested = json.at(JSON_KEY_REST).at(JSON_KEY_SSL).at(JSON_KEY_SSLEnabled);
		if (!(requested.is_boolean() && requested.get<bool>() == Configuration::instance()->getSslEnabled()))
			throw std::invalid_argument("REST.SSL.SSLEnabled is startup-only: set it in config.yaml and restart the daemon");
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
	// This route is intentionally absent from OpenAPI.  tcpClientId and the peer
	// address come from the accepted socket, not from request headers/body.
	if (message->tcpClientId() <= 0 || !SocketServer::isLoopbackClient(message->tcpClientId()))
		throw AuthorizationException("workflow capabilities are available only over local TCP");

	const auto workflowProcess = Configuration::instance()->getApp(WORKFLOW_APP_NAME, false);
	if (!workflowProcess || !workflowProcess->isSystemProtected())
		throw AuthorizationException("managed Workflow system application is unavailable");
	// A bad or superseded proof is an authentication failure (401), not an
	// authorization denial (403).
	const auto processUuid = workflowProcess->currentProcessUuidForProof(
		message->m_uuid, message->m_headers.get(HMAC_HTTP_HEADER));
	if (processUuid.empty())
		throw std::domain_error("workflow process proof is invalid or superseded");

	const auto request = message->extractJson();
	if (!request.is_object())
		throw std::invalid_argument("workflow capability request must be an object");
	const auto audience = GET_JSON_STR_VALUE(request, "audience");
	const auto ttlSeconds = request.contains("expires_in") ? request.at("expires_in").get<std::int64_t>() : 300;
	if (ttlSeconds < 60 || ttlSeconds > 300)
		throw std::invalid_argument("workflow capability expires_in must be between 60 and 300 seconds");
	if (!request.contains("operations") || !request.at("operations").is_array())
		throw std::invalid_argument("workflow capability operations must be an array");

	std::set<std::string> operations;
	for (const auto &entry : request.at("operations"))
	{
		if (!entry.is_string() || entry.get<std::string>().empty())
			throw std::invalid_argument("workflow capability operation must be a non-empty string");
		operations.insert(entry.get<std::string>());
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
		ownerPrincipalId = WORKFLOW_CONTROLLER_PRINCIPAL_PREFIX + processUuid;
		allowedOperations = {PERMISSION_KEY_view_all_app, PERMISSION_KEY_app_subscribe, PERMISSION_KEY_workflow_secret};
	}
	else if (audience == InternalCapability::audienceName(InternalCapability::Audience::WorkflowRun))
	{
		capabilityAudience = InternalCapability::Audience::WorkflowRun;
		workflowId = GET_JSON_STR_VALUE(request, "workflow_id");
		runId = GET_JSON_STR_VALUE(request, "run_id");
		auto validIdentifier = [](const std::string &value)
		{
			return !value.empty() && value.size() <= 128 &&
				std::all_of(value.begin(), value.end(), [](unsigned char c)
							{ return std::isalnum(c) || c == '-' || c == '_'; });
		};
		if (!validIdentifier(workflowId) || !validIdentifier(runId))
			throw std::invalid_argument("workflow_id and run_id must be safe identifiers");

		const auto workflow = Configuration::instance()->getApp(WORKFLOW_DEFINITION_PREFIX + workflowId, false);
		if (!workflow)
			throw NotFoundException("registered workflow was not found");
		const auto definition = workflow->AsJson(false);
		if (!definition.contains(JSON_KEY_APP_metadata) ||
			!definition.at(JSON_KEY_APP_metadata).is_object() ||
			GET_JSON_STR_VALUE(definition.at(JSON_KEY_APP_metadata), "type") != "workflow")
			throw AuthorizationException("capability target is not an Engine-managed workflow definition");
		ownerPrincipalId = workflow->getOwnerPrincipalId();
		if (ownerPrincipalId.empty())
			throw AuthorizationException("registered workflow has no owner Principal");
		allowedOperations = {
			PERMISSION_KEY_run_app_async,
			PERMISSION_KEY_view_app,
			PERMISSION_KEY_view_app_output,
			PERMISSION_KEY_app_delete,
			PERMISSION_KEY_run_task,
			PERMISSION_KEY_app_subscribe,
			PERMISSION_KEY_label_view,
		};
		const auto currentPermissions = Security::instance()->permissions(ownerPrincipalId);
		for (const auto &operation : operations)
			if (currentPermissions.count(operation) == 0)
				throw AuthorizationException("workflow owner does not currently allow operation: " + operation);
	}
	else
	{
		throw std::invalid_argument("workflow capability audience is invalid");
	}

	for (const auto &operation : operations)
		if (allowedOperations.count(operation) == 0)
			throw AuthorizationException("operation is outside the workflow capability allow-list: " + operation);

	const auto capability = InternalCapability::instance().issue(
		capabilityAudience, workflowId, runId, ownerPrincipalId, processUuid, operations, ttlSeconds);
	const auto expiresAt = std::chrono::duration_cast<std::chrono::seconds>(
		std::chrono::system_clock::now().time_since_epoch()).count() + ttlSeconds;
	nlohmann::json response;
	response["capability"] = capability;
	response["expires_at"] = expiresAt;
	response["owner_principal_id"] = ownerPrincipalId;
	response[JSON_KEY_process_uuid] = processUuid;
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiWorkflowCleanupOrphans(const std::shared_ptr<HttpRequest> &message)
{
	// This is a private startup reconciliation operation, not an app-delete
	// permission. HTTP, WSS, forwarded, and non-loopback TCP requests are denied.
	if (message->tcpClientId() <= 0 || !SocketServer::isLoopbackClient(message->tcpClientId()))
		throw AuthorizationException("workflow orphan cleanup is available only over local TCP");

	const auto workflowProcess = Configuration::instance()->getApp(WORKFLOW_APP_NAME, false);
	if (!workflowProcess || !workflowProcess->isSystemProtected())
		throw AuthorizationException("managed Workflow system application is unavailable");
	const auto processUuid = workflowProcess->currentProcessUuidForProof(
		message->m_uuid, message->m_headers.get(HMAC_HTTP_HEADER));
	if (processUuid.empty())
		throw std::domain_error("workflow process proof is invalid or superseded");

	constexpr const char *stepPrefix = WORKFLOW_STEP_PREFIX;
	const auto prefixLength = std::char_traits<char>::length(stepPrefix);
	auto validIdentifier = [](const std::string &value)
	{
		return !value.empty() && value.size() <= 128 &&
			std::all_of(value.begin(), value.end(), [](unsigned char c)
						{ return std::isalnum(c) || c == '-' || c == '_'; });
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
		if (!definition.contains(JSON_KEY_APP_metadata) ||
			!definition.at(JSON_KEY_APP_metadata).is_object())
			continue;
		const auto &metadata = definition.at(JSON_KEY_APP_metadata);
		if (!metadata.contains("type") || !metadata.at("type").is_string() ||
			metadata.at("type").get<std::string>() != "workflow-step" ||
			!metadata.contains("workflow_id") || !metadata.at("workflow_id").is_string() ||
			!metadata.contains("run_id") || !metadata.at("run_id").is_string() ||
			!metadata.contains(JSON_KEY_process_uuid) || !metadata.at(JSON_KEY_process_uuid).is_string())
			continue;
		const auto workflowId = metadata.at("workflow_id").get<std::string>();
		const auto runId = metadata.at("run_id").get<std::string>();
		const auto creatorProcessUuid = metadata.at(JSON_KEY_process_uuid).get<std::string>();
		if (!validIdentifier(workflowId) || !validIdentifier(runId) ||
			creatorProcessUuid.empty() || creatorProcessUuid == processUuid)
			continue;

		// removeApp's expected pointer makes the snapshot race-safe. A replacement
		// with the same name is not removed; destruction runs under removeApp's
		// own lock scope, released before the slow work.
		if (config->removeApp(name, app.get()))
			++removed;
	}

	nlohmann::json response;
	response["removed"] = removed;
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiWorkflowRegistry(const std::shared_ptr<HttpRequest> &message)
{
	// This private endpoint is the control capability's only registry view. It
	// deliberately does not expose arbitrary applications or bypass their owner
	// permissions through the synthetic Workflow controller principal.
	const auto principalId = permissionCheck(message, PERMISSION_KEY_view_all_app);
	if (!Utility::startWith(principalId, WORKFLOW_CONTROLLER_PRINCIPAL_PREFIX))
	{
		throw AuthorizationException("workflow registry is available only to the managed Workflow controller");
	}

	nlohmann::json result = nlohmann::json::array();
	for (const auto &app : Configuration::instance()->getApps())
	{
		if (!app || !Utility::startWith(app->getName(), WORKFLOW_DEFINITION_PREFIX))
			continue;
		auto definition = app->AsJson(true);
		if (!definition.contains(JSON_KEY_APP_metadata) ||
			!definition.at(JSON_KEY_APP_metadata).is_object())
			continue;
		const auto &metadata = definition.at(JSON_KEY_APP_metadata);
		if (!metadata.contains("type") || !metadata.at("type").is_string() ||
			metadata.at("type").get<std::string>() != "workflow")
			continue;
		addOwnerDisplayName(definition);
		result.push_back(definition);
	}
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiWorkflowSecret(const std::shared_ptr<HttpRequest> &message)
{
	// Only the Workflow controller may call this broker; it never starts an application.
	const auto principalId = permissionCheck(message, PERMISSION_KEY_workflow_secret);
	if (!Utility::startWith(principalId, WORKFLOW_CONTROLLER_PRINCIPAL_PREFIX))
		throw AuthorizationException("workflow secret broker is available only to the managed Workflow controller");

	const auto request = message->extractJson();
	if (!request.is_object())
		throw std::invalid_argument("workflow secret request must be an object");
	const auto op = GET_JSON_STR_VALUE(request, "op");
	if (op != "protect" && op != "unprotect")
		throw std::invalid_argument("workflow secret op must be protect or unprotect");
	const auto workflow = GET_JSON_STR_VALUE(request, "workflow");
	if (!validWorkflowSecretIdentifier(workflow))
		throw std::invalid_argument("workflow must be a safe identifier");
	if (!request.contains("secrets") || !request["secrets"].is_array())
		throw std::invalid_argument("workflow secret request must carry a secrets array");
	const auto &entries = request["secrets"];
	if (entries.empty() || entries.size() > MAX_WORKFLOW_SECRET_ENTRIES)
		throw std::invalid_argument("workflow secret request must carry between 1 and 128 values");

	nlohmann::json response;
	response["secrets"] = nlohmann::json::array();
	std::size_t totalSize = 0;
	for (const auto &entry : entries)
	{
		if (!entry.is_object() || !entry.contains("key") || !entry.contains("value") || !entry["key"].is_string() ||
			!entry["value"].is_string())
			throw std::invalid_argument("workflow secret entries must be {key, value} strings");
		const auto key = entry["key"].get<std::string>();
		if (!validWorkflowSecretKey(key))
			throw std::invalid_argument(
				Utility::stringFormat("workflow secret key <%s> is not a valid environment name", key.c_str()));
		const auto value = entry["value"].get<std::string>();
		totalSize += value.size();
		if (value.size() > MAX_WORKFLOW_SECRET_VALUE_SIZE || totalSize > MAX_WORKFLOW_SECRET_TOTAL_SIZE)
			throw std::invalid_argument("workflow secret value is too large");

		const auto context = SecretProtector::workflowSecretContext(workflow, key);
		std::string result;
		if (op == "protect")
		{
			result = SecretProtector::instance().protect(value, context);
		}
		else
		{
			try
			{
				result = SecretProtector::instance().unprotect(value, context);
			}
			catch (const std::invalid_argument &)
			{
				throw std::invalid_argument(Utility::stringFormat(
					"workflow secret <%s> is not valid protected ciphertext for workflow <%s>", key.c_str(),
					workflow.c_str()));
			}
			catch (const std::domain_error &)
			{
				throw std::invalid_argument(Utility::stringFormat(
					"workflow secret <%s> cannot be decrypted for workflow <%s>; it belongs to another workflow "
					"name or the master key changed",
					key.c_str(), workflow.c_str()));
			}
		}
		nlohmann::json output;
		output["key"] = key;
		output["value"] = result;
		response["secrets"].push_back(output);
	}
	message->reply(web::http::status_codes::OK, response, {{"Cache-Control", "no-store"}});
}

void RestHandler::apiEnrollFirstAdmin(const std::shared_ptr<HttpRequest> &message)
{
	if (message->m_headers.contains(HTTP_HEADER_KEY_APPMESH_FORWARDED) ||
		!isLoopbackPeer(message->m_remote_address))
		throw AuthorizationException("first-admin enrollment requires a direct loopback client");

	// TCP requests can self-declare client_addr. Trust the Agent-captured socket peer
	// only after verifying the private Agent-to-Engine envelope.
	if (message->tcpClientId() > 0)
	{
		try
		{
			message->verifyHMAC();
		}
		catch (const std::exception &)
		{
			throw AuthorizationException("first-admin enrollment requires a trusted local transport");
		}
	}

	// A WebSocket client presents its bearer only during the upgrade, which pins
	// the verified principal on the session (same dual path as permissionCheck).
	// HTTP/TCP callers still prove identity with the per-request Authorization header.
	std::shared_ptr<AuthorizationPrincipal> enrolled;
	if (!message->transportPrincipalId().empty())
		enrolled = Security::instance()->enrollFirstAdminPinned(
			message->transportPrincipalId());
	else
		enrolled = Security::instance()->enrollFirstAdmin(
			getBearerToken(message));
	auto response = enrolled->asJson();
	response["permissions"] = Security::instance()->permissions(enrolled->id());
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiPrincipalSelf(const std::shared_ptr<HttpRequest> &message)
{
	const auto principalId = permissionCheck(message, "");
	auto response = Security::instance()->principal(principalId)->asJson();
	response["permissions"] = Security::instance()->permissions(principalId);
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
	const auto path = curlpp::unescape(message->m_relative_uri);
	const auto principalId = regexSearch(path, REST_PATH_PRINCIPAL);
	Security::instance()->updatePrincipal(principalId, message->extractJson());
	message->reply(web::http::status_codes::OK, Security::instance()->principal(principalId)->asJson());
}

void RestHandler::apiPrincipalDelete(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_principal_delete);
	const auto path = curlpp::unescape(message->m_relative_uri);
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
	if (message->m_body && !message->m_body->empty())
	{
		const auto json = message->extractJson();
		const auto requested = json.is_object() ? GET_JSON_STR_VALUE(json, "principal") : "";
		if (!requested.empty() && requested != principalId)
		{
			permissionCheck(message, PERMISSION_KEY_principal_update);
			target = requested;
		}
	}
	const auto issued = Security::instance()->issueApiKey(target);
	LOG_INF << fname << "API key <" << GET_JSON_STR_VALUE(issued, "key_id") << "> issued to <" << target << "> by <"
			<< principalId << ">";
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

void RestHandler::apiRoleUpdate(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiRoleUpdate() ";

	const auto path = (curlpp::unescape(message->m_relative_uri));
	const auto tokenUser = permissionCheck(message, PERMISSION_KEY_role_update);
	auto pathRoleName = regexSearch(path, REST_PATH_SEC_ROLE_UPDATE);

	Security::instance()->updateRole(pathRoleName, message->extractJson());

	LOG_INF << fname << "Role <" << pathRoleName << "> updated by <" << tokenUser << ">";
	message->reply(web::http::status_codes::OK, Utility::text2json("Role update success"));
}

void RestHandler::apiRoleDelete(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiRoleDelete() ";

	const auto path = (curlpp::unescape(message->m_relative_uri));
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
	auto json = nlohmann::json::array();
	for (auto &perm : permissions)
	{
		json.push_back(std::string(perm));
	}
	message->reply(web::http::status_codes::OK, json);
}

void RestHandler::apiHealth(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_view_app);
	const auto path = (curlpp::unescape(message->m_relative_uri));
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
	const auto path = (curlpp::unescape(message->m_relative_uri));
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
	// from_recover is a server-internal flag; never trust it from REST input.
	jsonApp.erase(JSON_KEY_APP_from_recover);
	// run_base is an engine-injected marker; never trust a client-provided one.
	jsonApp.erase(JSON_KEY_APP_run_base);
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
				throw std::invalid_argument(Utility::stringFormat("Should not specify command for an existing application <%s>", clientProvideAppName.c_str()));
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
				nlohmann::json decrypted = nlohmann::json::object();
				for (auto &env : existApp[JSON_KEY_APP_secret_env].items())
				{
					const std::string context = fromApp->getName() + '\0' + env.key();
					decrypted[env.key()] = SecretProtector::instance().unprotect(
						env.value().get<std::string>(), context);
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
			existApp.erase(JSON_KEY_APP_depends_on);
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

	int timeout = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
	int lifecycle = getHttpQueryValue(*message, HTTP_QUERY_KEY_lifecycle, DEFAULT_RUN_APP_LIFECYCLE_SECONDS, timeout, MAX_RUN_APP_TIMEOUT_SECONDS);
	if (lifecycle == 0)
		throw std::invalid_argument("Zero timeout and lifecycle speficied");

	jsonApp[JSON_KEY_APP_enabled] = (static_cast<int>(STATUS::NOTAVAILABLE));
	jsonApp[JSON_KEY_APP_owner_principal_id] = callerPrincipalId;
	jsonApp.erase(JSON_KEY_APP_execution_user);
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

	int timeout = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
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
	auto result = nlohmann::json::object();
	result[JSON_KEY_APP_name] = appObj->getName();
	result[HTTP_QUERY_KEY_process_uuid] = std::move(processUuid);
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiRunSync(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_run_app_sync);

	int timeout = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_APP_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
	auto appObj = parseAndRegRunApp(message);

	// Use async reply here
	auto asyncRequest = std::make_shared<HttpRequestSyncRun>(message, appObj);
	asyncRequest->initTimeout(timeout);
	try
	{
		appObj->runSync(timeout, asyncRequest);
	}
	catch (...)
	{
		asyncRequest->abandonFailedStart();
		throw;
	}
}

void RestHandler::apiSendMessage(const std::shared_ptr<HttpRequest> &message)
{
	const auto principalId = permissionCheck(message, PERMISSION_KEY_run_task);

	// Short default so a stuck target can't hold the app's active slot for days; override via ?timeout=.
	int timeout = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_TASK_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);

	auto app = Configuration::instance()->getApp(appName);
	// Workflow actions enforce per-action owner/admin RBAC inside the Engine
	// capability, so the system workflow App admits the workflow roles at this
	// gate; every other App keeps the owner/EDIT gate.
	if (appName != WORKFLOW_APP_NAME || !hasWorkflowTaskRole(principalId))
		checkAppAccessPermission(message, app, true);
	auto asyncRequest = std::make_shared<HttpRequestWithTimeout>(message);
	asyncRequest->initTimer(timeout);
	app->sendTask(asyncRequest);
}

void RestHandler::apiSendMessageStream(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_run_task);

	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK_STREAM);

	auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, true);

	// Only the plain-HTTP lws entry attaches the sink marker; framed transports
	// (TCP, WebSocket) cannot receive an SSE response.
	const bool plainHttp = message->lwsRef() &&
		message->m_headers.get(HTTP_HEADER_KEY_X_LWS_Protocol) == HTTP_HEADER_VALUE_X_LWS_Protocol_HTTP;
	const auto marker = plainHttp ? message->m_headers.get(HTTP_HEADER_KEY_X_AppMesh_Sse_Stream) : std::string();
	auto sink = marker.empty() ? std::shared_ptr<SseSink>() : SseStreamRegistry::instance()->take(marker);
	if (!sink)
	{
		message->reply(web::http::status_codes::MethodNotAllowed,
					   Utility::text2json("Task streaming requires a plain HTTP connection"));
		return;
	}
	// A client that vanishes stops owning the answer: free the app's active
	// task slot instead of letting the parked request (and its sink) sit until
	// the target replies or the app stops. The stream id scopes the cancel to
	// this request: a queued disconnect must not abort another client's
	// in-flight task, and queued requests stay parked under the task timer.
	sink->setOnClosed([appName, streamId = marker]()
	{
		if (auto live = Configuration::instance()->getApp(appName))
			live->deleteTask(streamId);
	});

	// Short default so a stuck target can't hold the app's active slot for days; override via ?timeout=.
	// A stream request always keeps a bounded park: timeout=0 would skip the
	// timer entirely and let a vanished client pin the active slot forever.
	int timeout = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_TASK_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
	if (timeout <= 0)
		timeout = DEFAULT_RUN_TASK_TIMEOUT_SECONDS;
	auto asyncRequest = std::make_shared<HttpRequestTaskStream>(message, sink, marker);
	asyncRequest->initTimer(timeout);
	app->sendTask(asyncRequest);
}

void RestHandler::apiSendMessagePartial(const std::shared_ptr<HttpRequest> &message)
{
	if (!message->isManagedPrivateTransport() || !message->transportPrincipalId().empty())
		throw AuthorizationException("worker task RPC is available only to a managed local process");
	if (message->m_query.count("process_key") != 0)
		throw std::invalid_argument("process_key query authentication is not supported");
	const std::string processKey = Utility::stdStringTrim(
		message->m_headers.get(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY));
	if (processKey.empty())
		throw AuthorizationException("managed process proof is required");
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK_PARTIAL);

	auto app = Configuration::instance()->getApp(appName);
	const std::string payload(message->m_body->begin(), message->m_body->end());
	bool delivered = false;
	app->partialTask(processKey, payload, delivered);
	nlohmann::json result;
	result["delivered"] = delivered;
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiAppInput(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);

	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_INPUT);

	auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, true);
	const bool closePipe = Utility::stdStringTrim(message->m_headers.get(HTTP_HEADER_KEY_X_Input_Close)) == "true";
	const auto processUuid = message->m_query.count(HTTP_QUERY_KEY_process_uuid) != 0
								 ? message->m_query.at(HTTP_QUERY_KEY_process_uuid)
								 : std::string();
	const auto written = app->writeStdin(*message->m_body, closePipe, processUuid);
	nlohmann::json result;
	result["bytes_written"] = written;
	if (closePipe)
		result["closed"] = true;
	message->reply(web::http::status_codes::OK, result);
}

void RestHandler::apiRemoveMessage(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_run_task);

	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);

	auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, true);
	bool removed = app->deleteTask();
	message->reply(removed ? web::http::status_codes::OK : web::http::status_codes::AlreadyReported);
}

void RestHandler::apiGetMessage(const std::shared_ptr<HttpRequest> &message)
{
	if (!message->isManagedPrivateTransport() || !message->transportPrincipalId().empty())
		throw AuthorizationException("worker task RPC is available only to a managed local process");
	if (message->m_query.count("process_key") != 0)
		throw std::invalid_argument("process_key query authentication is not supported");
	const std::string processKey = Utility::stdStringTrim(
		message->m_headers.get(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY));
	if (processKey.empty())
		throw AuthorizationException("managed process proof is required");
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);
	auto app = Configuration::instance()->getApp(appName);

	// no need setup timer for service side request, process terminate will take care cleanup
	auto asyncRequest = std::make_shared<HttpRequestWithTimeout>(message);
	app->fetchTask(processKey, asyncRequest);
}

void RestHandler::apiSendMessageResponse(const std::shared_ptr<HttpRequest> &message)
{
	if (!message->isManagedPrivateTransport() || !message->transportPrincipalId().empty())
		throw AuthorizationException("worker task RPC is available only to a managed local process");
	if (message->m_query.count("process_key") != 0)
		throw std::invalid_argument("process_key query authentication is not supported");
	const std::string processKey = Utility::stdStringTrim(
		message->m_headers.get(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY));
	if (processKey.empty())
		throw AuthorizationException("managed process proof is required");
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);

	auto app = Configuration::instance()->getApp(appName);
	// no need setup timer for service side request, process terminate will take care cleanup
	auto asyncRequest = std::make_shared<HttpRequestWithTimeout>(message);
	app->replyTask(processKey, asyncRequest);
}

void RestHandler::apiAppOutputView(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_view_app_output);
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_OUT_VIEW);

	const auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, false);
	auto delayRequest = std::make_shared<HttpRequestOutputView>(message, app);
	delayRequest->init();
}

void RestHandler::apiAppOutputStream(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiAppOutputStream() ";

	const auto principalId = permissionCheck(message, PERMISSION_KEY_view_app_output);
	(void)principalId;
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_OUTPUT_STREAM);

	const auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, false);

	// Only the plain-HTTP lws entry attaches the sink marker; framed transports
	// (TCP, WebSocket) cannot receive an SSE response.
	const bool plainHttp = message->lwsRef() &&
		message->m_headers.get(HTTP_HEADER_KEY_X_LWS_Protocol) == HTTP_HEADER_VALUE_X_LWS_Protocol_HTTP;
	const auto marker = plainHttp ? message->m_headers.get(HTTP_HEADER_KEY_X_AppMesh_Sse_Stream) : std::string();
	auto sink = marker.empty() ? std::shared_ptr<SseSink>() : SseStreamRegistry::instance()->take(marker);
	if (!sink)
	{
		message->reply(web::http::status_codes::MethodNotAllowed,
					   Utility::text2json("Output streaming requires a plain HTTP connection"));
		return;
	}

	const auto processUuid = getHttpQueryString(*message, HTTP_QUERY_KEY_process_uuid);
	const bool follow = getHttpQueryString(*message, "follow") != "false";
	long position = getHttpQueryPosition(*message, HTTP_QUERY_KEY_stdout_position, 0, 0, 0);

	long timeoutSeconds = DEFAULT_SSE_STREAM_TIMEOUT_SECONDS;
	if (message->m_query.count(HTTP_QUERY_KEY_timeout) != 0)
	{
		timeoutSeconds = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_SSE_STREAM_TIMEOUT_SECONDS, 0,
										   MAX_SSE_STREAM_TIMEOUT_SECONDS);
	}

	// Shared by the delivery callback, the backfill below and the overall
	// timeout. The position cursor de-duplicates pump events against the
	// backfill read (the race the SDKs used to paper over with sleeps).
	struct FollowState
	{
		std::mutex mutex;
		std::shared_ptr<SseSink> sink;
		std::shared_ptr<Application> app;
		std::string subId;
		long cursor{0};
		bool ended{false};
	};
	const auto state = std::make_shared<FollowState>();
	state->sink = sink;
	state->app = app;
	state->cursor = position;
	// Held weakly: the subscription callback and the sink's close hook keep the
	// state alive, so the timeout timer cannot pin the Application.
	const std::weak_ptr<FollowState> weakState = state;

	// Emits the terminal "end" frame exactly once and tears the stream down.
	// The frame is guarded by `ended`, but close and unsubscribe must run
	// unconditionally: a client that vanished during the backfill already set
	// `ended` from deliverStdout, and skipping the teardown here would leave
	// the subscription and its state pinned forever.
	const auto endFollow = [weakState](const std::string &reason, const nlohmann::json &extra)
	{
		const auto state = weakState.lock();
		if (!state)
			return;
		std::string subId;
		{
			std::lock_guard<std::mutex> lock(state->mutex);
			subId = state->subId;
			if (!state->ended)
			{
				state->ended = true;
				nlohmann::json end = extra;
				end["reason"] = reason;
				end["position"] = state->cursor;
				state->sink->sendEvent("end", JSON::dump(end));
			}
		}
		// Outside the state lock: close() fires the sink's onClosed hook, which
		// re-enters endFollow for a disconnect and would deadlock under the lock.
		// Both calls are idempotent.
		state->sink->close();
		if (!subId.empty())
			EventDispatcher::instance()->unsubscribe(subId);
	};

	// Position-cursor delivery shared by live events and backfill chunks.
	const auto deliverStdout = [state](long start, const std::string &output, long rawAdvance) -> bool
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		if (state->ended)
			return true;
		if (rawAdvance <= 0)
			rawAdvance = static_cast<long>(output.size());
		if (start + rawAdvance <= state->cursor)
			return true; // fully covered by an earlier delivery
		auto text = output;
		if (start < state->cursor && rawAdvance == static_cast<long>(output.size()))
		{
			// Exact prefix trim is only sound when the view is byte-identical
			// to the raw span; a re-encoded chunk is delivered untrimmed rather
			// than slicing the text at a raw-byte boundary.
			const long skipped = state->cursor - start;
			text.erase(0, static_cast<std::size_t>(skipped));
			start = state->cursor;
			rawAdvance -= skipped;
		}
		nlohmann::json data;
		data["position"] = start;
		data["output"] = std::move(text);
		if (!state->sink->sendEvent("stdout", JSON::dump(data)))
		{
			state->ended = true;
			return false;
		}
		state->cursor = std::max(state->cursor, start + rawAdvance);
		return true;
	};

	// A silent peer is caught by the heartbeat; its close hook ends the follow
	// instead of idling the subscription to the timeout.
	sink->setOnClosed([endFollow]() { endFollow("disconnected", {}); });

	// Subscribe first so the pump starts dispatching, then replay; overlapping
	// deliveries are reconciled by the cursor above.
	const auto subId = EventDispatcher::instance()->subscribe(
		appName,
		static_cast<uint32_t>(AppEventType::STDOUT_OUTPUT) | static_cast<uint32_t>(AppEventType::PROCESS_EXIT) |
			static_cast<uint32_t>(AppEventType::APP_REMOVED),
		"", // owner policy already checked; subscriptions store the principal for unsubscribe only
		[state, deliverStdout, endFollow](const EventEnvelope &envelope) -> bool
		{
			if (envelope.eventType == "STDOUT")
			{
				try
				{
					const auto payload = nlohmann::json::parse(*envelope.basePayloadDump);
					const auto &data = payload.at("data");
					return deliverStdout(data.at("position").get<long>(), data.at("output").get<std::string>(), 0);
				}
				catch (const std::exception &)
				{
					return true; // a malformed frame must not kill the stream
				}
			}
			if (envelope.eventType == "EXIT")
			{
				// Drain [cursor, EOF] so the final position is exact even if the
				// exit-time flush raced this delivery.
				try
				{
					auto app = state->app;
					for (;;)
					{
						long pos = 0;
						{
							std::lock_guard<std::mutex> lock(state->mutex);
							pos = state->cursor;
							if (state->ended)
								return false;
						}
						// Same raw-delta rule as the replay path: getOutput
						// advances `pos` over the bytes it actually read.
						const auto chunkStart = pos;
						auto output = std::get<0>(app->getOutput(pos, 256 * 1024, "", 0, 0));
						if (output.empty())
							break;
						if (!deliverStdout(chunkStart, output, pos - chunkStart))
							return false;
						if (pos - chunkStart < 256 * 1024)
							break;
					}
				}
				catch (const std::exception &)
				{
				}
				int exitCode = 0;
				try
				{
					const auto payload = nlohmann::json::parse(*envelope.basePayloadDump);
					exitCode = payload.at("data").at("exit_code").get<int>();
				}
				catch (const std::exception &)
				{
				}
				nlohmann::json extra;
				extra["exit_code"] = exitCode;
				endFollow("exit", extra);
				return false;
			}
			if (envelope.eventType == "REMOVED")
			{
				endFollow("removed", {});
				return false;
			}
			return true;
		},
		ConnectionKey::wss(nextSseConnectionKey()));
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		state->subId = subId;
	}

	// Overall lifetime bound; heartbeats inside the sink detect a gone peer.
	if (timeoutSeconds > 0)
	{
		TIMER_MANAGER::instance()->registerTimer(static_cast<std::size_t>(timeoutSeconds) * 1000, 0, "sse-output-timeout",
												 [endFollow]()
												 {
													 endFollow("timeout", {});
													 return false;
												 });
	}

	// Replay [position, EOF]; a finished run ends with its exit code, a live one
	// keeps following (or stops at the tail when follow=false).
	try
	{
		bool finished = false;
		int exitCode = 0;
		for (;;)
		{
			// getOutput advances position to the end of what it read, so the
			// chunk start must be captured first.
			const auto chunkStart = position;
			std::string output;
			std::tie(output, finished, exitCode) = app->getOutput(position, 256 * 1024, processUuid, 0, 0);
			// getOutput returns the sanitized view but advances the cursor over
			// raw bytes; the raw span is the position delta.
			const auto rawAdvance = position - chunkStart;
			if (!output.empty() && !deliverStdout(chunkStart, output, rawAdvance))
			{
				// The sink is gone mid-backfill: end the follow here, because
				// the dispatch path will not strip an already-ended subscription.
				endFollow("disconnected", {});
				return;
			}
			{
				std::lock_guard<std::mutex> lock(state->mutex);
				if (state->ended)
					return;
			}
			if (finished)
			{
				nlohmann::json extra;
				extra["exit_code"] = exitCode;
				endFollow("exit", extra);
				return;
			}
			if (rawAdvance < 256 * 1024)
			{
				if (!follow)
					endFollow("eof", {});
				return;
			}
		}
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "backfill failed for app <" << appName << ">: " << e.what();
		nlohmann::json extra;
		extra["message"] = e.what();
		endFollow("error", extra);
	}
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
	if (!message->isManagedPrivateTransport() || !message->transportPrincipalId().empty())
		throw AuthorizationException("container events are available only over local loopback transports");

	const auto agentProcess = Configuration::instance()->getApp(SEPARATE_AGENT_APP_NAME, false);
	if (!agentProcess || !agentProcess->isSystemProtected())
		throw AuthorizationException("managed agent system application is unavailable");
	// A bad or superseded proof is an authentication failure (401), not a 403.
	if (agentProcess->currentProcessUuidForProof(message->m_uuid, message->m_headers.get(HMAC_HTTP_HEADER)).empty())
		throw std::domain_error("agent process proof is invalid or superseded");

	const auto event = message->extractJson();
	if (!event.is_object())
		throw std::invalid_argument("container event must be an object");
	const auto type = GET_JSON_STR_VALUE(event, "type");
	if (type != "die" && type != "sync")
		throw std::invalid_argument("unknown container event type <" + type + ">");

	// Every accepted push refreshes the liveness marker; die events route to the owning app.
	// The marker has no Windows reader (DockerApiProcess is not built there).
#if !defined(_WIN32)
	DockerApiProcess::noteContainerEventsAlive();
#endif
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
	if (jsonApp.is_null())
	{
		throw std::invalid_argument("Empty json input");
	}
	// from_recover is a server-internal flag; never trust it from REST input.
	jsonApp.erase(JSON_KEY_APP_from_recover);
	// run_base is an engine-injected marker; never trust a client-provided one.
	jsonApp.erase(JSON_KEY_APP_run_base);

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
	if (!requestedOwner.empty() &&
		Security::instance()->permissions(tokenUser).count(PERMISSION_KEY_app_manage_all) != 0)
	{
		// NotFoundException maps to 404 when the target principal does not exist.
		const auto target = Security::instance()->principal(requestedOwner);
		if (!target->active())
			throw std::invalid_argument("owner_principal_id must reference an active principal: " + requestedOwner);
		ownerPrincipalId = target->id();
		LOG_INF << fname << "Application <" << appName << "> owner set to <" << ownerPrincipalId
				<< "> by <" << tokenUser << ">";
	}
	else if (observed && requestedOwner.empty() && !observed->getOwnerPrincipalId().empty() &&
			 observed->getOwnerPrincipalId() != tokenUser)
	{
		// A manage-all overwrite without an explicit transfer keeps the owner.
		ownerPrincipalId = observed->getOwnerPrincipalId();
	}
	jsonApp[JSON_KEY_APP_owner_principal_id] = ownerPrincipalId;
	jsonApp.erase(JSON_KEY_APP_execution_user);
	const auto executionUser = Security::instance()->principal(ownerPrincipalId)->executionUser();
	if (!executionUser.empty())
		jsonApp[JSON_KEY_APP_execution_user] = executionUser;
	std::string subId;
	nlohmann::json result;
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
					subId = EventDispatcher::instance()->subscribe(appName, eventMask, tokenUser, std::move(deliveryCb), connKey);
			}
		}
		if (stale)
		{
			message->reply(web::http::status_codes::Conflict);
			return;
		}
		{
			// addApp re-checks the registration under its own lock; a racer past
			// the check above still gets 409.
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

bool RestHandler::buildDeliveryCallback(const std::shared_ptr<HttpRequest> &message, ConnectionKey &connKey, DeliveryCallback &deliveryCb)
{
	auto forwardRoute = message->m_headers.contains(HTTP_HEADER_KEY_APPMESH_FORWARDED) &&
		message->m_headers.contains(HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE)
		? message->m_headers.get(HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE)
		: std::string();
	if (message->tcpClientId() > 0)
	{
		int clientId = message->tcpClientId();
		connKey = ConnectionKey::tcp(clientId);
		deliveryCb = [clientId, forwardRoute](const EventEnvelope &envelope) -> bool
		{
			auto resp = std::make_unique<Response>();
			resp->uuid = Utility::shortID();
			resp->request_uri = "/appmesh/event";
			resp->http_status = web::http::status_codes::OK;
			resp->body_msg_type = web::http::mime_types::application_json;
			auto bodyStr = envelope.toJson();
			resp->body = std::vector<std::uint8_t>(bodyStr.begin(), bodyStr.end());
			resp->headers["X-Subscription-Id"] = envelope.subscriptionId;
			resp->headers["X-Event-Type"] = envelope.eventType;
			resp->headers["X-App-Name"] = envelope.appName;
			if (!forwardRoute.empty())
				resp->headers[HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE] = forwardRoute;
			return SocketServer::replyTcp(clientId, std::move(resp));
		};
		return true;
	}
	else if (message->lwsRef())
	{
		auto lwsRef = message->lwsRef();
		connKey = ConnectionKey::wss(lwsRef.sessionId);
		deliveryCb = [lwsRef, forwardRoute = std::move(forwardRoute)](const EventEnvelope &envelope) -> bool
		{
			try
			{
				auto resp = std::make_unique<Response>();
				resp->uuid = Utility::shortID();
				resp->request_uri = "/appmesh/event";
				resp->http_status = web::http::status_codes::OK;
				resp->body_msg_type = web::http::mime_types::application_json;
				auto bodyStr = envelope.toJson();
				resp->body = std::vector<std::uint8_t>(bodyStr.begin(), bodyStr.end());
				resp->headers["X-Subscription-Id"] = envelope.subscriptionId;
				resp->headers["X-Event-Type"] = envelope.eventType;
				resp->headers["X-App-Name"] = envelope.appName;
				if (!forwardRoute.empty())
					resp->headers[HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE] = forwardRoute;

				auto wsResp = std::make_unique<WSResponse>();
				wsResp->m_session_ref = const_cast<void *>(lwsRef.wsi);
				wsResp->m_req_id = 0;
				wsResp->m_session_id = lwsRef.sessionId;
				wsResp->m_payload = resp->serialize();
				wsResp->m_is_http = false;
				WebSocketService::instance()->enqueueOutgoingResponse(std::move(wsResp));
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
	const auto path = curlpp::unescape(message->m_relative_uri);

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
		message->reply(web::http::status_codes::BadRequest,
					   Utility::text2json("No valid event types in: " + events));
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

	nlohmann::json result;
	result["subscription_id"] = subId;
	result["app_name"] = appName;
	nlohmann::json eventList = nlohmann::json::array();
	for (uint32_t bit = 0x01; bit <= static_cast<uint32_t>(AppEventType::APP_REMOVED); bit <<= 1)
	{
		if (eventMask & bit)
			eventList.push_back(eventTypeToString(static_cast<AppEventType>(bit)));
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
		message->reply(web::http::status_codes::BadRequest,
					   Utility::text2json("Missing query parameter: subscription_id"));
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
