// src/daemon/rest/RestHandler.cpp
#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <set>

#include <boost/algorithm/string_regex.hpp>

#include "../../common/DurationParse.h"
#include "../../common/RestClient.h"
#include "../../common/Utility.h"
#include "../../common/os/linux.h"
#include "../Configuration.h"
#include "../Label.h"
#include "../ResourceCollection.h"
#include "../application/Application.h"
#include "../security/InternalCapability.h"
#include "../security/SecretProtector.h"
#include "../security/Security.h"
#if defined(HAVE_UWEBSOCKETS)
#include "uwebsockets/ReplyContext.h"
#else
#include "../../common/lwsservice/WebSocketService.h"
#endif
#include "EventDispatcher.h"
#include "HttpRequest.h"
#include "PrometheusRest.h"
#include "RestHandler.h"
#include "SocketServer.h"

// Content-type constants
constexpr auto CONTENT_TYPE_HTML = "text/html; charset=utf-8";
constexpr auto CONTENT_TYPE_YAML = "application/x-yaml";
constexpr auto CONTENT_TYPE_SVG = "image/svg+xml";
constexpr auto CONTENT_TYPE_PNG = "image/png";

namespace
{

	// uWS renders IPv6 without '::' compression and a dual-stack 127.0.0.1 peer
	// as v4-mapped "0000:...:ffff:7fxx:xxxx", so parse the 8-group form explicitly.
	bool isUwsLoopbackGroups(const std::string &peer)
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

		return peer == "127.0.0.1" || peer == "::1" || isUwsLoopbackGroups(peer);
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

// 6. File Management
constexpr auto REST_PATH_FILE_DOWNLOAD = "/appmesh/file/download";
constexpr auto REST_PATH_FILE_UPLOAD = "/appmesh/file/upload";

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
	bindRestMethod(web::http::methods::POST, REST_PATH_INTERNAL_WORKFLOW_CLEANUP_ORPHANS, std::bind(&RestHandler::apiWorkflowCleanupOrphans, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_INTERNAL_WORKFLOW_REGISTRY, std::bind(&RestHandler::apiWorkflowRegistry, this, std::placeholders::_1));
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
	bindRestMethod(web::http::methods::POST, REST_PATH_APP_TASK, std::bind(&RestHandler::apiSendMessage, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::DEL, REST_PATH_APP_TASK, std::bind(&RestHandler::apiRemoveMessage, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::GET, REST_PATH_APP_TASK, std::bind(&RestHandler::apiGetMessage, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::PUT, REST_PATH_APP_TASK, std::bind(&RestHandler::apiSendMessageResponse, this, std::placeholders::_1));

	// 6. File Management
	bindRestMethod(web::http::methods::GET, REST_PATH_FILE_DOWNLOAD, std::bind(&RestHandler::apiFileDownload, this, std::placeholders::_1));
	bindRestMethod(web::http::methods::POST, REST_PATH_FILE_UPLOAD, std::bind(&RestHandler::apiFileUpload, this, std::placeholders::_1));

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
	auto findPattern = [&path](const RestFunctions &functions) -> std::string
	{
		for (const auto &entry : functions)
		{
			if (path == entry.first || boost::regex_match(path, boost::regex(entry.first)))
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

	const auto route = matchRoute ? normalizedHttpRoute(path, routes) : std::string("unmatched");
	const auto started = std::chrono::steady_clock::now();
	const auto metrics = m_metrics;
	m_metrics->httpRequestStarted(method, route);
	message->setReplyMetricCallback([metrics, method, route, started](int status)
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
void RestHandler::apiOauthCallback(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiOauthCallback() ";
	LOG_DBG << fname << "Serving the OAuth callback relay page";

	std::string content(OAUTH_CALLBACK_RELAY_HTML);
	message->reply(web::http::status_codes::OK, content, CONTENT_TYPE_HTML);
}

void RestHandler::apiSwagger(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiSwagger() ";
	LOG_DBG << fname << "Redirecting to Swagger UI";

	auto host = message->m_headers.get("host");
	if (host.empty())
		host = message->m_headers.get("Host");

	std::string swaggerUrl = "https://petstore.swagger.io/?url=https://" + host + "/openapi.yaml";
	std::map<std::string, std::string> headers;
	headers["Location"] = swaggerUrl;

	std::string emptyBody;
	message->reply(web::http::status_codes::TemporaryRedirect, emptyBody, headers, CONTENT_TYPE_HTML);
}

void RestHandler::apiIndex(const std::shared_ptr<HttpRequest> &message)
{
	const static char fname[] = "RestHandler::apiIndex() ";
	LOG_DBG << fname << "Serving index.html";

	std::string content = getIndexHtmlContent();
	message->reply(web::http::status_codes::OK, content, CONTENT_TYPE_HTML);
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

std::string RestHandler::regexSearch(const std::string &value, const char *expr)
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
	LOG_WAR << fname << "Failed to parse data from path <" << value << "> for regex expression: <" << expr << ">";
	throw std::invalid_argument("Failed to search data from regex expression");
}

std::tuple<std::string, std::string> RestHandler::regexSearch2(const std::string &value, const char *expr)
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
	LOG_WAR << fname << "Failed to parse data pair from path <" << value << "> for regex expression: <" << expr << ">";
	throw std::invalid_argument("Failed to search data from regex expression");
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
	message->reply(web::http::status_codes::OK, Utility::text2json(std::string("Enable <") + appName + "> success."));
}

void RestHandler::apiAppDisable(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_app_control);
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_DISABLE);
	auto config = Configuration::instance();
	const auto app = config->getApp(appName);
	checkAppAccessPermission(message, app, true);
	bool stale = false;
	{
		const auto mutation = config->lockAppMutation();
		if (!config->isCurrentApp(appName, app))
			stale = true;
		else
			config->disableApp(appName);
	}
	if (stale)
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

		checkAppAccessPermission(message, app, true);
		bool stale = false;
		{
			const auto mutation = config->lockAppMutation();
			if (!config->isCurrentApp(appName, app))
				stale = true;
			else
				config->removeApp(appName, app.get());
		}
		if (stale)
		{
			message->reply(web::http::status_codes::Conflict);
			return;
		}
		message->reply(web::http::status_codes::OK, Utility::text2json(Utility::stringFormat("Application <%s> removed.", appName.c_str())));
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
	const auto &file = (message->m_headers.find(HTTP_HEADER_KEY_file_path)->second);
	if (!Utility::validateFilePath(file, Configuration::instance()->getFileAllowedBaseDir()))
	{
		message->reply(web::http::status_codes::Forbidden, Utility::text2json("Invalid file path"));
		return;
	}

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
	}
	else
	{
		// WebSocket clients reuse their original Dex bearer; never echo it in a response.
	}
	message->reply(web::http::status_codes::OK, body, headers);
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
	const auto &file = message->m_headers.find(HTTP_HEADER_KEY_file_path)->second;
	if (!Utility::validateFilePath(file, Configuration::instance()->getFileAllowedBaseDir()))
	{
		message->reply(web::http::status_codes::Forbidden, Utility::text2json("Invalid file path"));
		return;
	}

	if (Utility::isFileExist(file))
	{
		message->reply(web::http::status_codes::Forbidden, Utility::text2json("file already exist"));
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
	}
	else
	{
		// WebSocket clients reuse their original Dex bearer; never echo it in a response.
	}
	message->reply(web::http::status_codes::OK, body, headers);
	// set permission
	Utility::applyFilePermission(file, message->m_headers);
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
	auto labelKey = regexSearch(path, REST_PATH_LABEL_ADD);

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
	auto labelKey = regexSearch(path, REST_PATH_LABEL_DELETE);

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

	const auto workflowProcess = Configuration::instance()->getApp("workflow", false);
	if (!workflowProcess || !workflowProcess->isSystemProtected())
		throw AuthorizationException("managed Workflow system application is unavailable");
	const auto processKey = message->m_headers.get(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY);
	const auto processUuid = workflowProcess->currentProcessUuidForKey(processKey);
	if (processUuid.empty())
		throw AuthorizationException("workflow process proof is invalid or superseded");

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
				std::all_of(value.begin(), value.end(), [](unsigned char c)
							{ return std::isalnum(c) || c == '-' || c == '_'; });
		};
		if (!validIdentifier(workflowId) || !validIdentifier(runId))
			throw std::invalid_argument("workflow_id and run_id must be safe identifiers");

		const auto workflow = Configuration::instance()->getApp("workflow-" + workflowId, false);
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
	response["process_uuid"] = processUuid;
	message->reply(web::http::status_codes::OK, response);
}

void RestHandler::apiWorkflowCleanupOrphans(const std::shared_ptr<HttpRequest> &message)
{
	// This is a private startup reconciliation operation, not an app-delete
	// permission. HTTP, WSS, forwarded, and non-loopback TCP requests are denied.
	if (message->tcpClientId() <= 0 || !SocketServer::isLoopbackClient(message->tcpClientId()))
		throw AuthorizationException("workflow orphan cleanup is available only over local TCP");

	const auto workflowProcess = Configuration::instance()->getApp("workflow", false);
	if (!workflowProcess || !workflowProcess->isSystemProtected())
		throw AuthorizationException("managed Workflow system application is unavailable");
	const auto processKey = message->m_headers.get(HTTP_HEADER_KEY_X_APPMESH_PROCESS_KEY);
	const auto processUuid = workflowProcess->currentProcessUuidForKey(processKey);
	if (processUuid.empty())
		throw AuthorizationException("workflow process proof is invalid or superseded");

	constexpr const char *stepPrefix = "wf-cmd-";
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
			!metadata.contains("process_uuid") || !metadata.at("process_uuid").is_string())
			continue;
		const auto workflowId = metadata.at("workflow_id").get<std::string>();
		const auto runId = metadata.at("run_id").get<std::string>();
		const auto creatorProcessUuid = metadata.at("process_uuid").get<std::string>();
		if (!validIdentifier(workflowId) || !validIdentifier(runId) ||
			creatorProcessUuid.empty() || creatorProcessUuid == processUuid)
			continue;

		// removeApp's expected pointer makes the snapshot race-safe. A replacement
		// with the same name is not removed.
		const auto mutation = config->lockAppMutation();
		if (!config->isCurrentApp(name, app))
			continue;
		config->removeApp(name, app.get());
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
	if (principalId.compare(0, std::char_traits<char>::length("internal:workflow-controller:"),
			"internal:workflow-controller:") != 0)
	{
		throw AuthorizationException("workflow registry is available only to the managed Workflow controller");
	}

	nlohmann::json result = nlohmann::json::array();
	for (const auto &app : Configuration::instance()->getApps())
	{
		if (!app || app->getName().compare(0, std::char_traits<char>::length("workflow-"),
				"workflow-") != 0)
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
	permissionCheck(message, PERMISSION_KEY_view_host_resource);

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
			if (HAS_JSON_FIELD(jsonApp, JSON_KEY_APP_sec_env))
			{
				// Client provided fresh plaintext sec_env — leave as plaintext, no recover flag.
				existApp[JSON_KEY_APP_sec_env] = jsonApp[JSON_KEY_APP_sec_env];
			}
			else if (HAS_JSON_FIELD(existApp, JSON_KEY_APP_sec_env))
			{
				// Inherited sec_env is protected with a context containing the source app name.
				nlohmann::json decrypted = nlohmann::json::object();
				for (auto &env : existApp[JSON_KEY_APP_sec_env].items())
				{
					const std::string context = fromApp->getName() + '\0' + env.key();
					decrypted[env.key()] = SecretProtector::instance().unprotect(
						env.value().get<std::string>(), context);
				}
				existApp[JSON_KEY_APP_sec_env] = std::move(decrypted);
			}
			existApp[JSON_KEY_APP_name] = Configuration::instance()->generateRunAppName(clientProvideAppName);
			existApp[JSON_KEY_APP_owner_principal_id] = callerPrincipalId;
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

	jsonApp[JSON_KEY_APP_status] = (static_cast<int>(STATUS::NOTAVAILABLE));
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
	auto asyncRequest = std::make_shared<HttpRequestAutoCleanup>(message, appObj);
	appObj->runSync(timeout, asyncRequest);
}

void RestHandler::apiSendMessage(const std::shared_ptr<HttpRequest> &message)
{
	permissionCheck(message, PERMISSION_KEY_run_task);

	// Short default so a stuck target can't hold the app's active slot for days; override via ?timeout=.
	int timeout = getHttpQueryValue(*message, HTTP_QUERY_KEY_timeout, DEFAULT_RUN_TASK_TIMEOUT_SECONDS, 0, MAX_RUN_APP_TIMEOUT_SECONDS);
	const auto path = (curlpp::unescape(message->m_relative_uri));
	auto appName = regexSearch(path, REST_PATH_APP_TASK);

	auto app = Configuration::instance()->getApp(appName);
	checkAppAccessPermission(message, app, true);
	auto asyncRequest = std::make_shared<HttpRequestWithTimeout>(message);
	asyncRequest->initTimer(timeout);
	app->sendTask(asyncRequest);
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

	auto appName = normalizeAppName(GET_JSON_STR_VALUE(jsonApp, JSON_KEY_APP_name));
	jsonApp[JSON_KEY_APP_name] = appName;
	LOG_DBG << fname << "Registering application <" << appName << ">";
	auto config = Configuration::instance();
	const auto observed = config->getApp(appName, false);
	if (observed)
		checkAppAccessPermission(message, observed, true);

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
			// Keep same-name validation, subscription and replacement atomic.
			const auto mutation = config->lockAppMutation();
			if (!config->isCurrentApp(appName, observed))
				stale = true;
			else
			{
				if (eventMask != 0)
				{
					ConnectionKey connKey;
					DeliveryCallback deliveryCb;
					if (buildDeliveryCallback(message, connKey, deliveryCb))
						subId = EventDispatcher::instance()->subscribe(appName, eventMask, tokenUser, std::move(deliveryCb), connKey);
				}

				auto app = config->addApp(jsonApp);
				// Use returnRuntimeInfo=true so the response strips encrypted sec_env.
				result = app->AsJson(true);
			}
		}
		if (stale)
		{
			message->reply(web::http::status_codes::Conflict);
			return;
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
	const auto forwardRoute = message->m_headers.contains(HTTP_HEADER_KEY_APPMESH_FORWARDED) &&
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
#if defined(HAVE_UWEBSOCKETS)
	else if (message->uwsReplyContext() && message->uwsReplyContext()->getProtocolType() == WSS::ReplyContext::ProtocolType::WebSocket)
	{
		auto uwsCtx = message->uwsReplyContext();
		connKey = ConnectionKey::wss(uwsCtx->getNumericId());
		deliveryCb = [uwsCtx, forwardRoute](const EventEnvelope &envelope) -> bool
		{
			if (uwsCtx->isAborted())
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
				resp->headers["X-Subscription-Id"] = envelope.subscriptionId;
				resp->headers["X-Event-Type"] = envelope.eventType;
				resp->headers["X-App-Name"] = envelope.appName;
				if (!forwardRoute.empty())
					resp->headers[HTTP_HEADER_KEY_APPMESH_FORWARD_ROUTE] = forwardRoute;

				auto data = resp->serialize();
				uwsCtx->replyWebSocket(std::string(data->data(), data->size()), false, true);
				return true;
			}
			catch (...)
			{
				return false;
			}
		};
		return true;
	}
#else
	else if (message->lwsRef())
	{
		auto lwsRef = message->lwsRef();
		connKey = ConnectionKey::wss(lwsRef.sessionId);
		deliveryCb = [lwsRef, forwardRoute](const EventEnvelope &envelope) -> bool
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
#endif
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
