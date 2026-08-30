// src/daemon/rest/RestBase.cpp
#include <functional>
#include <algorithm>
#include <cctype>
#include <set>

#include <boost/algorithm/string_regex.hpp>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "../application/Application.h"
#include "../application/AppUtils.h"
#include "../security/InternalCapability.h"
#include "../security/Security.h"
#include "HttpRequest.h"
#include "RestBase.h"
#include "SocketServer.h"

namespace
{
	constexpr const char *INTERNAL_CAPABILITY_PREFIX = "amcap1.";
	constexpr const char *WORKFLOW_APP_NAME = "workflow";
	constexpr const char *WORKFLOW_DEFINITION_PREFIX = "workflow-";
	constexpr const char *WORKFLOW_STEP_PREFIX = "wf-cmd-";

	bool hasWorkflowStepPrefix(const std::string &appName)
	{
		return appName.compare(0, std::char_traits<char>::length(WORKFLOW_STEP_PREFIX),
			WORKFLOW_STEP_PREFIX) == 0;
	}

	void requireMatchingWorkflowStepMetadata(const nlohmann::json &definition,
		const InternalCapability::Claims &claims)
	{
		if (!definition.contains(JSON_KEY_APP_metadata) ||
			!definition.at(JSON_KEY_APP_metadata).is_object())
			throw AuthorizationException("workflow temporary application metadata is missing");
		const auto &metadata = definition.at(JSON_KEY_APP_metadata);
		auto matches = [&metadata](const char *field, const std::string &expected)
		{
			return metadata.contains(field) && metadata.at(field).is_string() &&
				metadata.at(field).get<std::string>() == expected;
		};
		if (!matches("type", "workflow-step") ||
			!matches("workflow_id", claims.workflowId) ||
			!matches("run_id", claims.runId) ||
			!matches("process_uuid", claims.processUuid))
		{
			throw AuthorizationException(
				"workflow temporary application is not bound to this run capability");
		}
	}

	std::string capabilityTargetAppName(const HttpRequest &message)
	{
		constexpr const char *appPrefix = "/appmesh/app/";
		const auto prefixLength = std::char_traits<char>::length(appPrefix);
		if (message.m_relative_uri.size() <= prefixLength ||
			message.m_relative_uri.compare(0, prefixLength, appPrefix) != 0)
			return {};

		auto resource = message.m_relative_uri.substr(prefixLength);
		for (const auto *suffix : {"/output", "/subscribe", "/task"})
		{
			const auto suffixLength = std::char_traits<char>::length(suffix);
			if (resource.size() > suffixLength &&
				resource.compare(resource.size() - suffixLength, suffixLength, suffix) == 0)
			{
				resource.resize(resource.size() - suffixLength);
				break;
			}
		}
		return resource.find('/') == std::string::npos ? resource : std::string();
	}

	void validateRunCapabilityTarget(const std::shared_ptr<HttpRequest> &message,
		const InternalCapability::Claims &claims)
	{
		auto config = Configuration::instance();
		if (message->m_method == web::http::methods::POST &&
			message->m_relative_uri == "/appmesh/app/run")
		{
			const auto definition = message->extractJson();
			if (!definition.is_object())
				throw std::invalid_argument("workflow application run request must be an object");
			const auto suppliedName = Utility::stdStringTrim(
				GET_JSON_STR_VALUE(definition, JSON_KEY_APP_name));
			if (suppliedName.empty())
				throw AuthorizationException(
					"workflow capability may create only explicitly named temporary applications");
			const auto appName = normalizeAppName(suppliedName);
			const auto existing = config->getApp(appName, false);
			if (existing)
			{
				// App steps may run an existing owner-authorized application. A reserved
				// workflow temporary name, however, must remain bound to this run.
				if (hasWorkflowStepPrefix(appName))
					requireMatchingWorkflowStepMetadata(existing->AsJson(false), claims);
				return;
			}
			if (!hasWorkflowStepPrefix(appName))
				throw AuthorizationException(
					"workflow capability may create applications only in the wf-cmd namespace");
			requireMatchingWorkflowStepMetadata(definition, claims);
			return;
		}

		const auto appName = capabilityTargetAppName(*message);
		if (appName.empty() || !hasWorkflowStepPrefix(appName))
			return;
		const auto app = config->getApp(appName, false);
		if (!app)
			throw NotFoundException("workflow temporary application not found");
		requireMatchingWorkflowStepMetadata(app->AsJson(false), claims);
	}

	std::set<std::string> capabilityOperationsForRequest(const HttpRequest &message)
	{
		const auto &path = message.m_relative_uri;
		if (message.m_method == web::http::methods::GET &&
			path == "/appmesh/internal/workflow/registry")
			return {PERMISSION_KEY_view_all_app};
		if (message.m_method == web::http::methods::POST && path == "/appmesh/app/run")
			return {PERMISSION_KEY_run_app_async};
		if (message.m_method == web::http::methods::GET && path == "/appmesh/labels")
			return {PERMISSION_KEY_label_view};
		if ((message.m_method == web::http::methods::POST || message.m_method == web::http::methods::DEL) &&
			path == "/appmesh/subscribe")
		{
			// Wildcard subscription performs both checks in its handler.
			return {PERMISSION_KEY_app_subscribe, PERMISSION_KEY_view_all_app};
		}
		constexpr const char *appPrefix = "/appmesh/app/";
		const auto appPrefixLength = std::char_traits<char>::length(appPrefix);
		if (path.size() > appPrefixLength && path.compare(0, appPrefixLength, appPrefix) == 0)
		{
			const auto resource = path.substr(appPrefixLength);
			auto isSingleResourceRoute = [&resource](const char *suffix)
			{
				const auto suffixLength = std::char_traits<char>::length(suffix);
				return resource.size() > suffixLength &&
					resource.compare(resource.size() - suffixLength, suffixLength, suffix) == 0 &&
					resource.substr(0, resource.size() - suffixLength).find('/') == std::string::npos;
			};
			if (message.m_method == web::http::methods::GET &&
				isSingleResourceRoute("/output"))
				return {PERMISSION_KEY_view_app_output};
			if ((message.m_method == web::http::methods::POST || message.m_method == web::http::methods::DEL) &&
				isSingleResourceRoute("/subscribe"))
				return {PERMISSION_KEY_app_subscribe};
			if ((message.m_method == web::http::methods::POST || message.m_method == web::http::methods::DEL) &&
				isSingleResourceRoute("/task"))
				return {PERMISSION_KEY_run_task};
			// Plain app view/delete has exactly one path segment. Never use a
			// generic GET/DELETE fallback for other /appmesh endpoints.
			if (resource.find('/') == std::string::npos && message.m_method == web::http::methods::DEL)
				return {PERMISSION_KEY_app_delete};
			if (resource.find('/') == std::string::npos && message.m_method == web::http::methods::GET)
				return {PERMISSION_KEY_view_app};
		}
		return {};
	}

	std::string validateInternalCapability(const std::shared_ptr<HttpRequest> &message,
		const std::string &token, const std::string &permission)
	{
		// tcpClientId is assigned by the accepted socket.  WSS/HTTP have no TCP
		// client ID and a remote TCP peer fails the socket-level loopback check.
		if (message->tcpClientId() <= 0 || !SocketServer::isLoopbackClient(message->tcpClientId()))
			throw std::domain_error("internal capabilities are accepted only over local TCP");

		const auto routeOperations = capabilityOperationsForRequest(*message);
		if (routeOperations.empty() ||
			(!permission.empty() && routeOperations.count(permission) == 0))
			throw std::domain_error("internal capability is not accepted for this route");
		// Empty permission checks are owner/access checks performed after the route's
		// primary RBAC check. Requiring one route operation again keeps such checks
		// from turning into a capability bypass.
		const auto operation = permission.empty() ? *routeOperations.begin() : permission;
		const auto claims = InternalCapability::instance().verify(token, operation);

		auto workflowProcess = Configuration::instance()->getApp(WORKFLOW_APP_NAME, false);
		if (!workflowProcess || !workflowProcess->isSystemProtected() ||
			!workflowProcess->isCurrentProcessUuid(claims.processUuid))
			throw std::domain_error("internal capability is not bound to the current Workflow process");

		if (claims.audience == InternalCapability::Audience::WorkflowControl)
		{
			// A distinct non-RBAC principal is returned only for the two control
			// operations issued by the Engine.  It is never a general system/admin
			// principal and cannot pass any operation outside the capability.
			return "internal:workflow-controller:" + claims.processUuid;
		}

		// Re-check the Engine-owned workflow registration on every operation so
		// ownership changes invalidate an already-issued run capability.
		auto workflow = Configuration::instance()->getApp(
			std::string(WORKFLOW_DEFINITION_PREFIX) + claims.workflowId, false);
		if (!workflow || workflow->getOwnerPrincipalId() != claims.ownerPrincipalId)
			throw AuthorizationException("workflow capability owner binding is no longer current");

		// permissions() also checks active status.  Role removal or principal
		// disable therefore takes effect immediately, without waiting for expiry.
		const auto currentPermissions = Security::instance()->permissions(claims.ownerPrincipalId);
		if (currentPermissions.count(operation) == 0)
			throw AuthorizationException("workflow capability owner no longer allows this operation");
		validateRunCapabilityTarget(message, claims);
		return claims.ownerPrincipalId;
	}
}

RestBase::RestBase()
{
}

RestBase::~RestBase()
{
}

void RestBase::handle_get(const std::shared_ptr<HttpRequest> &message)
{
    handleRest(message, m_restGetFunctions);
}

void RestBase::handle_put(const std::shared_ptr<HttpRequest> &message)
{
    handleRest(message, m_restPutFunctions);
}

void RestBase::handle_post(const std::shared_ptr<HttpRequest> &message)
{
    handleRest(message, m_restPostFunctions);
}

void RestBase::handle_delete(const std::shared_ptr<HttpRequest> &message)
{
    handleRest(message, m_restDelFunctions);
}

void RestBase::handle_options(const std::shared_ptr<HttpRequest> &message)
{
    message->reply(web::http::status_codes::OK);
}

void RestBase::handle_head(const std::shared_ptr<HttpRequest> &message)
{
    message->reply(web::http::status_codes::OK);
}

void RestBase::handleRest(const std::shared_ptr<HttpRequest> &message, const std::map<std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> &restFunctions)
{
    const static char fname[] = "RestBase::handleRest() ";
    REST_INFO_PRINT;

    const auto path = Utility::stringReplace(message->m_relative_uri, "//", "/");

	if (message->isManagedWorkerTransport())
	{
		constexpr const char *taskPrefix = "/appmesh/app/";
		constexpr const char *taskSuffix = "/task";
		const bool methodAllowed = message->m_method == web::http::methods::GET ||
			message->m_method == web::http::methods::PUT;
		const bool pathAllowed = path.rfind(taskPrefix, 0) == 0 &&
			path.size() > std::char_traits<char>::length(taskPrefix) + std::char_traits<char>::length(taskSuffix) &&
			path.compare(path.size() - std::char_traits<char>::length(taskSuffix),
				std::char_traits<char>::length(taskSuffix), taskSuffix) == 0 &&
			path.substr(std::char_traits<char>::length(taskPrefix),
				path.size() - std::char_traits<char>::length(taskPrefix) - std::char_traits<char>::length(taskSuffix)).find('/') == std::string::npos;
		// The two discovery endpoints are anonymous on every transport (OpenAPI:
		// security []). A loopback client that connected without a bearer holds a
		// managed-worker session and still needs them for login discovery.
		const bool publicDiscovery = message->m_method == web::http::methods::GET &&
			(path == "/appmesh/auth/config" || path == "/.well-known/oauth-protected-resource");
		if ((!methodAllowed || !pathAllowed) && !publicDiscovery)
		{
			message->reply(web::http::status_codes::Forbidden,
				Utility::text2json("Managed worker WebSocket sessions are restricted to their task RPC"));
			return;
		}
	}

    // Find matching REST function
    auto it = std::find_if(
        restFunctions.begin(), restFunctions.end(),
        [&](const std::pair<const std::string, std::function<void(const std::shared_ptr<HttpRequest> &)>> &kvp)
        {
            return path == kvp.first || boost::regex_match(path, boost::regex(kvp.first));
        });

    if (it == restFunctions.end())
    {
        if (message->m_method == web::http::methods::OPTIONS)
        {
            LOG_DBG << fname << "204 NoContent " << message->m_method << ":" << path;
            message->reply(web::http::status_codes::NoContent);
            return;
        }
        LOG_WAR << fname << "404 NotFound " << message->m_method << ":" << path;
        message->reply(web::http::status_codes::NotFound, Utility::text2json("Path not found " + message->m_method + ":" + path));
        return;
    }

    // TODO: those exception are well designed for different usage that reflect Client result
    try
    {
        it->second(message);
    }
    catch (const NotFoundException &e)
    {
        LOG_WAR << fname << "404 NotFound " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::NotFound, Utility::text2json(e.what()));
    }
    catch (const AuthenticationUnavailableException &e)
    {
        LOG_WAR << fname << "503 ServiceUnavailable " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::ServiceUnavailable, Utility::text2json(e.what()));
    }
    catch (const AuthorizationException &e)
    {
        LOG_WAR << fname << "403 Forbidden " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::Forbidden, Utility::text2json(e.what()));
    }
    catch (const std::domain_error &e)
    {
        LOG_WAR << fname << "401 Unauthorized " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::Unauthorized, Utility::text2json(e.what()),
            {{"WWW-Authenticate", "Bearer realm=\"appmesh\", error=\"invalid_token\""}});
    }
    catch (const std::invalid_argument &e)
    {
        // Input issue: invalid_argument -> 400
        LOG_WAR << fname << "400 BadRequest " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::BadRequest, Utility::text2json(e.what()));
    }
    catch (const std::runtime_error &e)
    {
        // Logic issue: runtime_error -> 412
        LOG_WAR << fname << "412 RuntimeError " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::PreconditionFailed, Utility::text2json(e.what()));
    }
    catch (const std::exception &e)
    {
        // Others: Server issue
        LOG_ERR << fname << "500 InternalServerError " << message->m_method << ":" << path << " - " << e.what();
        message->reply(web::http::status_codes::InternalError, Utility::text2json("Internal server error"));
    }
    catch (...)
    {
        // Others: Server issue
        LOG_ERR << fname << "500 InternalServerError " << message->m_method << ":" << path << " - Unknown exception";
        message->reply(web::http::status_codes::InternalError, Utility::text2json("Unknown exception"));
    }
}

void RestBase::bindRestMethod(const web::http::method &method, const std::string &path, std::function<void(const std::shared_ptr<HttpRequest> &)> func)
{
    const static char fname[] = "RestBase::bindRest() ";

    LOG_DBG << fname << "bind " << method << " for " << path;

    // bind to map
    if (method == web::http::methods::GET)
        m_restGetFunctions[path] = std::move(func);
    else if (method == web::http::methods::PUT)
        m_restPutFunctions[path] = std::move(func);
    else if (method == web::http::methods::POST)
        m_restPostFunctions[path] = std::move(func);
    else if (method == web::http::methods::DEL)
        m_restDelFunctions[path] = std::move(func);
    else
        LOG_ERR << fname << "Method <" << method << "> not supported for path <" << path << ">";
}

std::string RestBase::getDexBearerToken(const std::shared_ptr<HttpRequest> &message)
{
    if (!message->m_headers.count(HTTP_HEADER_JWT_Authorization))
        throw std::domain_error("No authentication token provided");

    const auto value = Utility::stdStringTrim(
        message->m_headers.find(HTTP_HEADER_JWT_Authorization)->second);
    const auto separator = value.find(' ');
    if (separator == std::string::npos)
        throw std::domain_error("Authorization header must use the Bearer scheme");
    auto scheme = value.substr(0, separator);
    std::transform(scheme.begin(), scheme.end(), scheme.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (scheme != "bearer")
        throw std::domain_error("Authorization header must use the Bearer scheme");
    const auto token = Utility::stdStringTrim(value.substr(separator + 1));
    if (token.empty() || token.find_first_of(" \t\r\n") != std::string::npos)
        throw std::domain_error("Bearer token is empty or malformed");
    return token;
}

std::string RestBase::permissionCheck(const std::shared_ptr<HttpRequest> &message, const std::string &permission)
{
    const static char fname[] = "RestBase::permissionCheck() ";

	// A user WebSocket is authenticated once during upgrade. Worker::process has
	// already rejected any frame that tried to change that identity. Re-check
	// current RBAC on every protected route.
	if (!message->transportPrincipalId().empty())
	{
		Security::requirePermission(message->transportPrincipalId(), permission);
		return message->transportPrincipalId();
	}

    const auto token = getDexBearerToken(message);
	if (token.compare(0, std::char_traits<char>::length(INTERNAL_CAPABILITY_PREFIX),
			INTERNAL_CAPABILITY_PREFIX) == 0)
	{
		return validateInternalCapability(message, token, permission);
	}

    // REST and WebSocket side channels share the exact same Bearer parser and
    // OIDC authentication boundary.
    const auto tokenValidationResult = Security::authenticateBearerAuthorization(
        message->m_headers.find(HTTP_HEADER_JWT_Authorization)->second);

    const auto &principalId = tokenValidationResult.id();

	Security::requirePermission(principalId, permission);

    LOG_DBG << fname << "Authentication successful for client: " << message->m_remote_address
            << ", principal: " << principalId << ", permission: " << (permission.empty() ? "none" : permission);
    return principalId;
}
