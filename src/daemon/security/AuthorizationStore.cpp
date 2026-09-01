#include "AuthorizationStore.h"

#include "../../common/Utility.h"
#include "../../common/os/filesystem.h"
#include "../Configuration.h"
#include "../application/Application.h"
#include "Security.h"

#include <ace/OS.h>

#include <cstdlib>
#include <stdexcept>

namespace
{
	const std::string SYSTEM_PRINCIPAL_ID = "system:appmesh";
	const char *AUTH_MODE_ENV = "APPMESH_AUTH_MODE";
	const char *AUTH_ROLE_ENV = "APPMESH_AUTH_ROLE";
	const char *BUILTIN_AUTH_MODE = "builtin";
	const char *EXTERNAL_AUTH_MODE = "external";
	const char *AUTH_STACK_CONFIG_FILE = "auth-stack.yaml";
	// Dex derives the static-password subject from the immutable packaged admin
	// userID and the local connector. This value is public identity metadata, not
	// a credential. It is used only to restrict the one-time local bootstrap claim.
	const char *DEFAULT_FIRST_ADMIN_SUBJECT =
		"CiQyZDFjOGMzOC0zODk4LTRjODktYTc4Yi0zY2FhNDJmMjAzYzESBWxvY2Fs";

	std::string resolveAuthRole()
	{
		auto role = Utility::getenv(AUTH_ROLE_ENV);
		if (role.empty())
		{
			const auto file = Utility::getConfigFilePath(AUTH_STACK_CONFIG_FILE);
			const auto root = Utility::yamlToJson(YAML::LoadFile(file));
			if (!root.contains("AuthStack") || !root.at("AuthStack").is_object())
				throw std::invalid_argument("auth-stack.yaml must contain an AuthStack object");
			role = GET_JSON_STR_VALUE(root.at("AuthStack"), "role");
		}
		if (role != "standalone" && role != "owner" && role != "follower")
			throw std::invalid_argument("AuthStack.role must be standalone, owner, or follower");
		return role;
	}

	std::set<std::string> readStringSet(const nlohmann::json &value, const char *field)
	{
		std::set<std::string> result;
		if (!value.is_array())
			throw std::invalid_argument(std::string(field) + " must be an array");
		for (const auto &entry : value)
		{
			if (!entry.is_string() || entry.get<std::string>().empty())
				throw std::invalid_argument(std::string(field) + " entries must be non-empty strings");
			result.insert(entry.get<std::string>());
		}
		return result;
	}

}

AuthorizationPrincipal::AuthorizationPrincipal(std::string principalId, Principal::Kind kind,
	std::string issuer, std::string subject)
	: m_id(std::move(principalId)), m_kind(kind), m_issuer(std::move(issuer)),
	  m_subject(std::move(subject)), m_status("active")
{
	if (m_id.empty() || m_issuer.empty() || m_subject.empty())
		throw std::invalid_argument("authorization principal requires id, issuer, and subject");
}

const std::string &AuthorizationPrincipal::id() const { return m_id; }
const std::string &AuthorizationPrincipal::issuer() const { return m_issuer; }
const std::string &AuthorizationPrincipal::subject() const { return m_subject; }
Principal::Kind AuthorizationPrincipal::kind() const { return m_kind; }
const std::string &AuthorizationPrincipal::status() const { return m_status; }
const std::string &AuthorizationPrincipal::executionUser() const { return m_executionUser; }
const std::set<std::string> &AuthorizationPrincipal::roles() const { return m_roles; }
bool AuthorizationPrincipal::active() const { return m_status == "active"; }

void AuthorizationPrincipal::updateClaims(const Principal &principal)
{
	if (m_issuer != principal.issuer() || m_subject != principal.subject())
		throw AuthorizationException("principal binding does not match token issuer and subject");
	m_displayName = principal.displayName();
	m_email = principal.email();
	m_connectorId = principal.connectorId();
}

void AuthorizationPrincipal::updatePolicy(const nlohmann::json &json)
{
	if (json.contains("status"))
	{
		const auto status = json.at("status").get<std::string>();
		if (status != "active" && status != "disabled" && status != "tombstoned")
			throw std::invalid_argument("principal status must be active, disabled, or tombstoned");
		m_status = status;
	}
	if (json.contains("execution_user"))
		m_executionUser = json.at("execution_user").get<std::string>();
	if (json.contains("roles"))
		m_roles = readStringSet(json.at("roles"), "roles");
	if (json.contains("display_name"))
		m_displayName = json.at("display_name").get<std::string>();
	if (json.contains("email"))
		m_email = json.at("email").get<std::string>();
	if (json.contains("connector_id"))
		m_connectorId = json.at("connector_id").get<std::string>();
}

nlohmann::json AuthorizationPrincipal::asJson() const
{
	nlohmann::json result;
	result["principal_id"] = m_id;
	result["kind"] = Principal::kindName(m_kind);
	result["issuer"] = m_issuer;
	result["subject"] = m_subject;
	result["display_name"] = m_displayName;
	result["email"] = m_email;
	result["connector_id"] = m_connectorId;
	result["status"] = m_status;
	result["execution_user"] = m_executionUser;
	result["roles"] = m_roles;
	return result;
}

Principal AuthorizationPrincipal::asPrincipal() const
{
	Principal principal(m_issuer, m_subject, m_kind);
	principal.displayName(m_displayName);
	principal.email(m_email);
	principal.connectorId(m_connectorId);
	return principal;
}

AuthorizationStore::AuthorizationStore()
	: m_provisioningMode("explicit-or-minimal"), m_firstAdminRole("appmesh-admin"),
	  m_firstAdminEnrolled(false), m_firstAdminEnrollmentEnabled(false),
	  m_builtinAuthentication(false)
{
}

void AuthorizationStore::init()
{
	const auto file = Utility::getConfigFilePath(APPMESH_AUTHORIZATION_CONFIG_FILE);
	auto root = Utility::yamlToJson(YAML::LoadFile(file));
	Configuration::overrideConfigWithEnv(root);
	load(root);
	initializeFirstAdminEnrollment();
}

void AuthorizationStore::load(const nlohmann::json &root)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (!root.contains("Authorization") || !root.at("Authorization").is_object())
		throw std::invalid_argument("authorization.yaml must contain an Authorization object");
	const auto &authorization = root.at("Authorization");
	m_provisioningMode = GET_JSON_STR_VALUE(authorization, "provisioning");
	if (m_provisioningMode.empty())
		m_provisioningMode = "explicit-or-minimal";
	if (m_provisioningMode != "explicit" && m_provisioningMode != "explicit-or-minimal")
		throw std::invalid_argument("Authorization.provisioning must be explicit or explicit-or-minimal");
	m_firstAdminRole = GET_JSON_STR_VALUE(authorization, "first_admin_role");
	// Preserve the role selection when upgrading a pre-enrollment authorization file.
	if (m_firstAdminRole.empty())
		m_firstAdminRole = GET_JSON_STR_VALUE(authorization, "bootstrap_admin_role");
	if (m_firstAdminRole.empty())
		m_firstAdminRole = "appmesh-admin";
	m_firstAdminSubject = GET_JSON_STR_VALUE(authorization, "first_admin_subject");
	if (m_firstAdminSubject.empty())
		m_firstAdminSubject = DEFAULT_FIRST_ADMIN_SUBJECT;
	m_firstAdminEnrolled = GET_JSON_BOOL_VALUE(authorization, "first_admin_enrolled");

	m_roles.clear();
	if (authorization.contains("roles"))
	{
		if (!authorization.at("roles").is_object())
			throw std::invalid_argument("Authorization.roles must be an object");
		for (const auto &entry : authorization.at("roles").items())
			m_roles[entry.key()] = readStringSet(entry.value(), "role permissions");
	}
	if (m_roles.count(m_firstAdminRole) == 0)
		throw std::invalid_argument("first_admin_role is not defined in Authorization.roles");

	m_principals.clear();
	if (authorization.contains("principals"))
	{
		if (!authorization.at("principals").is_object())
			throw std::invalid_argument("Authorization.principals must be an object");
		for (const auto &entry : authorization.at("principals").items())
		{
			const auto &definition = entry.value();
			const auto kind = parseKind(GET_JSON_STR_VALUE(definition, "kind"));
			const auto issuer = GET_JSON_STR_VALUE(definition, "issuer");
			const auto subject = GET_JSON_STR_VALUE(definition, "subject");
			if (kind != Principal::Kind::System && entry.key() != Principal::stableId(issuer, subject))
				throw std::invalid_argument("OIDC principal key must equal the stable (issuer, subject) identifier");
			auto principal = std::make_shared<AuthorizationPrincipal>(entry.key(), kind, issuer, subject);
			principal->updatePolicy(definition);
			validateRoles(principal->roles());
			m_principals[entry.key()] = std::move(principal);
		}
	}
	if (m_principals.count(SYSTEM_PRINCIPAL_ID) == 0)
		m_principals[SYSTEM_PRINCIPAL_ID] = std::make_shared<AuthorizationPrincipal>(
			SYSTEM_PRINCIPAL_ID, Principal::Kind::System, "appmesh-internal", "appmesh");
}

std::shared_ptr<AuthorizationPrincipal> AuthorizationStore::resolve(const Principal &principal)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto found = m_principals.find(principal.id());
	if (found == m_principals.end())
	{
		if (m_provisioningMode == "explicit")
			throw AuthorizationException("OIDC principal is not provisioned in App Mesh");
		auto record = std::make_shared<AuthorizationPrincipal>(
			principal.id(), principal.kind(), principal.issuer(), principal.subject());
		record->updateClaims(principal);
		record->updatePolicy(nlohmann::json{{"roles", nlohmann::json::array()}});
		m_principals[principal.id()] = record;
		try
		{
			saveLocked();
		}
		catch (...)
		{
			m_principals.erase(principal.id());
			throw;
		}
		found = m_principals.find(principal.id());
	}
	else
	{
		found->second->updateClaims(principal);
	}
	if (!found->second->active())
		throw AuthorizationException("App Mesh principal is not active");
	return found->second;
}

std::shared_ptr<AuthorizationPrincipal> AuthorizationStore::enrollFirstAdmin(const Principal &principal)
{
	const static char fname[] = "AuthorizationStore::enrollFirstAdmin() ";
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (!m_firstAdminEnrollmentEnabled)
		throw AuthorizationException("first-admin enrollment is not available");
	if (principal.kind() != Principal::Kind::User)
		throw AuthorizationException("only a verified user principal can enroll as first administrator");
	if (principal.subject() != m_firstAdminSubject)
		throw AuthorizationException("verified principal is not the packaged bootstrap administrator");

	auto found = m_principals.find(principal.id());
	if (found != m_principals.end() && !found->second->active())
		throw AuthorizationException("App Mesh principal is not active");
	if (m_firstAdminEnrolled || hasFirstAdminLocked())
	{
		// A retry after the role was committed but before the CLI session was saved
		// is safe and should succeed for the same immutable Principal only.
		if (found != m_principals.end() && found->second->roles().count(m_firstAdminRole) != 0)
			return found->second;
		throw AuthorizationException("first-admin enrollment is not available");
	}

	auto candidate = found == m_principals.end()
		? std::make_shared<AuthorizationPrincipal>(principal.id(), principal.kind(), principal.issuer(), principal.subject())
		: std::make_shared<AuthorizationPrincipal>(*found->second);
	candidate->updateClaims(principal);
	auto roles = candidate->roles();
	roles.insert(m_firstAdminRole);
	candidate->updatePolicy(nlohmann::json{{"roles", roles}});

	const auto previous = found == m_principals.end() ? nullptr : found->second;
	const bool previouslyEnrolled = m_firstAdminEnrolled;
	m_principals[principal.id()] = candidate;
	m_firstAdminEnrolled = true;
	try
	{
		saveLocked();
	}
	catch (...)
	{
		if (previous)
			m_principals[principal.id()] = previous;
		else
			m_principals.erase(principal.id());
		m_firstAdminEnrolled = previouslyEnrolled;
		throw;
	}

	LOG_INF << fname << "enrolled principal <" << principal.id()
			<< "> into the first-administrator role <" << m_firstAdminRole << ">";
	return candidate;
}

std::shared_ptr<AuthorizationPrincipal> AuthorizationStore::get(const std::string &principalId) const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto found = m_principals.find(principalId);
	if (found == m_principals.end())
		throw NotFoundException("principal not found");
	return found->second;
}

std::set<std::string> AuthorizationStore::permissions(const std::string &principalId) const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	const auto principal = get(principalId);
	if (!principal->active())
		throw AuthorizationException("App Mesh principal is not active");
	std::set<std::string> result;
	for (const auto &role : principal->roles())
	{
		auto found = m_roles.find(role);
		if (found != m_roles.end())
			result.insert(found->second.begin(), found->second.end());
	}
	return result;
}

std::set<std::string> AuthorizationStore::allPermissions() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	std::set<std::string> result;
	for (const auto &role : m_roles)
		result.insert(role.second.begin(), role.second.end());
	return result;
}

bool AuthorizationStore::builtinAuthentication() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	return m_builtinAuthentication;
}

nlohmann::json AuthorizationStore::firstAdminEnrollment() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	const bool available = m_firstAdminEnrollmentEnabled && !m_firstAdminEnrolled &&
		!hasFirstAdminLocked();
	nlohmann::json result{{"available", available}};
	if (available)
		result["subject"] = m_firstAdminSubject;
	return result;
}

nlohmann::json AuthorizationStore::principalsJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	nlohmann::json result = nlohmann::json::object();
	for (const auto &entry : m_principals)
		result[entry.first] = entry.second->asJson();
	return result;
}

nlohmann::json AuthorizationStore::rolesJson() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	nlohmann::json result = nlohmann::json::object();
	for (const auto &entry : m_roles)
		result[entry.first] = entry.second;
	return result;
}

void AuthorizationStore::updatePrincipal(const std::string &principalId, const nlohmann::json &definition)
{
	const static char fname[] = "AuthorizationStore::updatePrincipal() ";
	if (!definition.is_object())
		throw std::invalid_argument("principal definition must be an object");
	if (definition.contains("status") &&
		definition.at("status").is_string() &&
		definition.at("status").get<std::string>() == "tombstoned")
	{
		throw AuthorizationException(
			"use the Principal DELETE operation to create a tombstone after ownership checks");
	}
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto found = m_principals.find(principalId);
	if (principalId == SYSTEM_PRINCIPAL_ID)
		throw AuthorizationException("the App Mesh system principal cannot be changed through the authorization API");

	std::shared_ptr<AuthorizationPrincipal> candidate;
	if (found == m_principals.end())
	{
		const auto kind = parseKind(GET_JSON_STR_VALUE(definition, "kind"));
		const auto issuer = GET_JSON_STR_VALUE(definition, "issuer");
		const auto subject = GET_JSON_STR_VALUE(definition, "subject");
		if (kind == Principal::Kind::System)
			throw AuthorizationException("system principals cannot be created through the authorization API");
		if (principalId != Principal::stableId(issuer, subject))
			throw std::invalid_argument("OIDC principal key must equal the stable (issuer, subject) identifier");
		candidate = std::make_shared<AuthorizationPrincipal>(principalId, kind, issuer, subject);
	}
	else
	{
		candidate = std::make_shared<AuthorizationPrincipal>(*found->second);
		if (definition.contains("kind") &&
			parseKind(GET_JSON_STR_VALUE(definition, "kind")) != candidate->kind())
			throw std::invalid_argument("principal kind is immutable");
		if (definition.contains("issuer") &&
			GET_JSON_STR_VALUE(definition, "issuer") != candidate->issuer())
			throw std::invalid_argument("principal issuer is immutable");
		if (definition.contains("subject") &&
			GET_JSON_STR_VALUE(definition, "subject") != candidate->subject())
			throw std::invalid_argument("principal subject is immutable");
	}
	candidate->updatePolicy(definition);
	validateRoles(candidate->roles());

	const auto previous = found == m_principals.end() ? nullptr : found->second;
	const bool previouslyEnrolled = m_firstAdminEnrolled;
	if (candidate->roles().count(m_firstAdminRole) != 0)
		m_firstAdminEnrolled = true;
	m_principals[principalId] = candidate;
	try
	{
		saveLocked();
	}
	catch (...)
	{
		if (previous)
			m_principals[principalId] = previous;
		else
			m_principals.erase(principalId);
		m_firstAdminEnrolled = previouslyEnrolled;
		throw;
	}
	LOG_INF << fname << (previous ? "updated" : "created")
			<< " principal <" << principalId << "> roles: " << nlohmann::json(candidate->roles()).dump();
}

void AuthorizationStore::deletePrincipal(const std::string &principalId)
{
	const static char fname[] = "AuthorizationStore::deletePrincipal() ";
	const auto config = Configuration::instance();
	std::unique_lock<std::recursive_mutex> applicationMutation;
	if (config)
		applicationMutation = config->lockAppMutation();

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (principalId == SYSTEM_PRINCIPAL_ID)
		throw AuthorizationException("the App Mesh system principal cannot be deleted");
	auto found = m_principals.find(principalId);
	if (found == m_principals.end())
		throw NotFoundException("principal not found");
	if (found->second->status() == "tombstoned")
		throw NotFoundException("active principal not found");

	if (config)
	{
		for (const auto &app : config->getApps())
		{
			if (app && app->getOwnerPrincipalId() == principalId)
			{
				throw AuthorizationException(
					"principal owns application <" + app->getName() +
					">; transfer the application owner first (PUT /appmesh/app/<name> with owner_principal_id, requires the "
					+ std::string(PERMISSION_KEY_app_manage_all) + " permission) or delete the application");
			}
		}
	}

	// Keep the immutable issuer/subject binding as a durable tombstone. Erasing
	// it would let explicit-or-minimal provisioning recreate the same subject as
	// a new Principal and would destroy the authorization audit boundary.
	const auto previous = found->second;
	auto tombstone = std::make_shared<AuthorizationPrincipal>(*previous);
	tombstone->updatePolicy(nlohmann::json{
		{"status", "tombstoned"},
		{"execution_user", ""},
		{"roles", nlohmann::json::array()}});
	m_principals[principalId] = tombstone;
	try
	{
		saveLocked();
	}
	catch (...)
	{
		m_principals[principalId] = previous;
		throw;
	}
	LOG_INF << fname << "tombstoned principal <" << principalId << ">";
}

void AuthorizationStore::updateRole(const std::string &role, const nlohmann::json &permissions)
{
	const static char fname[] = "AuthorizationStore::updateRole() ";
	if (role.empty())
		throw std::invalid_argument("role name cannot be empty");
	const auto parsed = readStringSet(permissions, "role permissions");
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto found = m_roles.find(role);
	const bool existed = found != m_roles.end();
	const auto previous = existed ? found->second : std::set<std::string>();
	m_roles[role] = parsed;
	try
	{
		saveLocked();
	}
	catch (...)
	{
		if (existed)
			m_roles[role] = previous;
		else
			m_roles.erase(role);
		throw;
	}
	LOG_INF << fname << (existed ? "updated" : "created") << " role <"
			<< role << "> permissions: " << nlohmann::json(parsed).dump();
}

void AuthorizationStore::deleteRole(const std::string &role)
{
	const static char fname[] = "AuthorizationStore::deleteRole() ";
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (role == m_firstAdminRole)
		throw AuthorizationException("the first-administrator role cannot be deleted");
	if (m_roles.count(role) == 0)
		throw NotFoundException("role not found");
	for (const auto &principal : m_principals)
		if (principal.second->roles().count(role) != 0)
			throw AuthorizationException("role is still bound to a principal");
	const auto previous = m_roles.at(role);
	m_roles.erase(role);
	try
	{
		saveLocked();
	}
	catch (...)
	{
		m_roles[role] = previous;
		throw;
	}
	LOG_INF << fname << "deleted role <" << role << ">";
}

void AuthorizationStore::save() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	saveLocked();
}

void AuthorizationStore::saveLocked() const
{
	nlohmann::json authorization;
	authorization["provisioning"] = m_provisioningMode;
	authorization["first_admin_role"] = m_firstAdminRole;
	authorization["first_admin_subject"] = m_firstAdminSubject;
	authorization["first_admin_enrolled"] = m_firstAdminEnrolled;
	authorization["roles"] = rolesJson();
	authorization["principals"] = principalsJson();
	nlohmann::json root;
	root["Authorization"] = std::move(authorization);

	const auto path = Utility::getConfigFilePath(APPMESH_AUTHORIZATION_CONFIG_FILE, true);
	const auto tmp = os::createTmpFile(path, Utility::jsonToYaml(root), 0600);
	if (tmp.empty())
		throw std::runtime_error("could not create temporary authorization configuration");
	if (ACE_OS::rename(tmp.c_str(), path.c_str()) != 0)
	{
		Utility::removeFile(tmp);
		throw std::runtime_error(std::string("failed to replace authorization configuration: ") + last_error_msg());
	}
}

void AuthorizationStore::initializeFirstAdminEnrollment()
{
	const static char fname[] = "AuthorizationStore::initializeFirstAdminEnrollment() ";
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	const auto authMode = Utility::getenv(AUTH_MODE_ENV, BUILTIN_AUTH_MODE);
	if (authMode != BUILTIN_AUTH_MODE && authMode != EXTERNAL_AUTH_MODE)
		throw std::invalid_argument("APPMESH_AUTH_MODE must be builtin or external");
	m_builtinAuthentication = authMode == BUILTIN_AUTH_MODE;

	// Versions before automatic subject-pinned enrollment generated a second
	// owner-only proof. It is no longer accepted, so remove any stale copy during
	// the upgrade instead of leaving obsolete credential material behind.
	const auto legacyProofPath = (fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR /
		"auth" / "secrets" / "first-admin-enrollment-token").string();
	if (Utility::isFileExist(legacyProofPath))
		Utility::removeFile(legacyProofPath);

	const auto authRole = resolveAuthRole();
	m_firstAdminEnrollmentEnabled = authMode == BUILTIN_AUTH_MODE &&
		(authRole == "standalone" || authRole == "owner");

	const bool inferredEnrollment = hasFirstAdminLocked();
	if (inferredEnrollment && !m_firstAdminEnrolled)
	{
		// Migration safety: a previously provisioned administrator permanently closes
		// the one-time enrollment window even if the old file lacks the durable marker.
		m_firstAdminEnrolled = true;
		saveLocked();
	}
	if (!m_firstAdminEnrollmentEnabled || m_firstAdminEnrolled)
		return;

	LOG_INF << fname
			<< "first-admin enrollment is available only to the packaged administrator from loopback";
}

bool AuthorizationStore::hasFirstAdminLocked() const
{
	for (const auto &entry : m_principals)
	{
		if (entry.first != SYSTEM_PRINCIPAL_ID && entry.second->roles().count(m_firstAdminRole) != 0)
			return true;
	}
	return false;
}

void AuthorizationStore::validateRoles(const std::set<std::string> &roles) const
{
	for (const auto &role : roles)
		if (m_roles.count(role) == 0)
			throw std::invalid_argument("principal references an undefined role: " + role);
}

Principal::Kind AuthorizationStore::parseKind(const std::string &kind)
{
	if (kind == "user")
		return Principal::Kind::User;
	if (kind == "service")
		return Principal::Kind::Service;
	if (kind == "system")
		return Principal::Kind::System;
	throw std::invalid_argument("principal kind must be user, service, or system");
}

const std::string &AuthorizationStore::systemPrincipalId() { return SYSTEM_PRINCIPAL_ID; }
