// src/daemon/rest/RestBase.h
#pragma once

#include <map>
#include <memory>

#include <boost/regex.hpp>

#include "../../common/JwtHelper.h"
#include "../../common/Utility.h"

// Route table of the daemon REST API.
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

class HttpRequest;

/// REST base class: routing, Dex bearer extraction, and permission checking.
class RestBase
{
public:
	explicit RestBase();
	virtual ~RestBase();

protected:
	/// Dispatch REST request to specific functions
	virtual void
	handleRest(const std::shared_ptr<HttpRequest> &message,
			   const std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> &restFunctions);
	/// Bind a REST path to a function (supports regex)
	void bindRestMethod(const web::http::method &method, const std::string &path,
						std::function<void(const std::shared_ptr<HttpRequest> &)> func);

public:
	void handle_get(const std::shared_ptr<HttpRequest> &message);
	void handle_put(const std::shared_ptr<HttpRequest> &message);
	void handle_post(const std::shared_ptr<HttpRequest> &message);
	void handle_delete(const std::shared_ptr<HttpRequest> &message);
	void handle_options(const std::shared_ptr<HttpRequest> &message);
	void handle_head(const std::shared_ptr<HttpRequest> &message);

protected:
	/// Check permission for the request, returns the authenticated principal ID.
	std::string permissionCheck(const std::shared_ptr<HttpRequest> &message, const std::string &permission);
	/// Extract and normalize the Dex bearer token from the Authorization header.
	std::string getBearerToken(const std::shared_ptr<HttpRequest> &message);

protected:
	// API functions
	std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> m_restGetFunctions;
	std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> m_restPutFunctions;
	std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> m_restPostFunctions;
	std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> m_restDelFunctions;
	// Route patterns compiled once at registration; the route tables are immutable after startup
	std::map<std::string, boost::regex> m_restRegexCache;
};

#define REST_INFO_PRINT                                                                                                     \
	LOG_DBG << "Function: " << __FUNCTION__ << " Method: " << message->m_method << " URI: " << message->m_relative_uri      \
			<< " Remote: " << message->m_remote_address;
