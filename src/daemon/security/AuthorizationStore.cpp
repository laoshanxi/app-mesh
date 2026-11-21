#include "AuthorizationStore.h"

#include "../../common/Password.h"

#include "../../common/Utility.h"
#include "../../common/os/filesystem.h"
#include "../Configuration.h"
#include "../application/Application.h"
#include "SecretProtector.h"
#include "Security.h"

#include <ace/OS.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <stdexcept>

namespace
{
	const std::string SYSTEM_PRINCIPAL_ID = "system:appmesh";
	const char *BUILTIN_AUTH_MODE = "builtin";
	const char *EXTERNAL_AUTH_MODE = "external";
	const char *AUTH_STACK_CONFIG_FILE = "auth-stack.yaml";
	// Dex derives the static-password subject from the immutable packaged admin
	// userID and the local connector. This value is public identity metadata, not
	// a credential. It is used only to restrict the one-time local bootstrap claim.
	const char *DEFAULT_FIRST_ADMIN_SUBJECT =
		"CiQyZDFjOGMzOC0zODk4LTRjODktYTc4Yi0zY2FhNDJmMjAzYzESBWxvY2Fs";

	// Request-signing API keys per principal; the owner revokes before issuing more.
	constexpr std::size_t MAX_API_KEYS_PER_PRINCIPAL = 10;

	// SecretProtector ciphertext marker (same as Application.cpp).
	const char *PROTECTED_SECRET_PREFIX = "sp1:";

	/// Encryption context bound to the key id, so a ciphertext moved between entries does not decrypt.
	std::string apiKeySecretContext(const std::string &keyId)
	{
		return std::string("api_key") + '\0' + keyId;
	}

	/// Decrypt a persisted secret; a value without the ciphertext marker (or that
	/// fails decryption) throws.
	std::string readStoredSecret(const std::string &keyId, const std::string &stored)
	{
		if (!Utility::startWith(stored, PROTECTED_SECRET_PREFIX))
			throw std::invalid_argument("api key secret is not encrypted");
		return SecretProtector::instance().unprotect(stored, apiKeySecretContext(keyId));
	}

	// Every permission identifier the policy accepts; role updates are checked
	// against this set so typos cannot silently grant nothing.
	const std::set<std::string> &knownPermissions()
	{
		static const std::set<std::string> permissions{
			PERMISSION_KEY_view_app,
			PERMISSION_KEY_view_app_output,
			PERMISSION_KEY_view_all_app,
			PERMISSION_KEY_view_host_resource,
			PERMISSION_KEY_app_reg,
			PERMISSION_KEY_app_control,
			PERMISSION_KEY_app_delete,
			PERMISSION_KEY_app_manage_all,
			PERMISSION_KEY_run_app_async,
			PERMISSION_KEY_run_app_sync,
			PERMISSION_KEY_run_app_async_output,
			PERMISSION_KEY_run_task,
			PERMISSION_KEY_file_download,
			PERMISSION_KEY_file_upload,
			PERMISSION_KEY_file_delete,
			PERMISSION_KEY_host_forward,
			PERMISSION_KEY_label_view,
			PERMISSION_KEY_label_set,
			PERMISSION_KEY_label_delete,
			PERMISSION_KEY_config_view,
			PERMISSION_KEY_config_set,
			PERMISSION_KEY_principal_update,
			PERMISSION_KEY_principal_delete,
			PERMISSION_KEY_principal_list,
			PERMISSION_KEY_role_update,
			PERMISSION_KEY_role_delete,
			PERMISSION_KEY_role_view,
			PERMISSION_KEY_permission_list,
			PERMISSION_KEY_app_subscribe,
			// Granted by the packaged appmesh-admin role; consumed by the workflow
			// administration surface.
			"workflow-admin",
		};
		return permissions;
	}

	bool validRoleName(const std::string &role)
	{
		return !role.empty() && role.size() <= 128 &&
			   std::all_of(role.begin(), role.end(),
						   [](unsigned char c) { return std::isalnum(c) || c == '-' || c == '_'; });
	}

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

	m_apiKeys.clear();
	if (authorization.contains("api_keys"))
	{
		if (!authorization.at("api_keys").is_object())
			throw std::invalid_argument("Authorization.api_keys must be an object");
		for (const auto &entry : authorization.at("api_keys").items())
		{
			const auto &definition = entry.value();
			const auto principalId = GET_JSON_STR_VALUE(definition, "principal");
			// Decrypt for the in-memory snapshot.
			std::string secret;
			try
			{
				secret = readStoredSecret(entry.key(), GET_JSON_STR_VALUE(definition, "secret"));
			}
			catch (const std::exception &)
			{
				LOG_WAR << "AuthorizationStore::load() dropped request-signing API key <" << entry.key()
						<< ">: the stored secret is not a readable encrypted secret; restore the "
						   "SecretProtector master key or reissue the key";
				continue;
			}
			// Dangling keys (principal removed by an external policy edit) are
			// dropped with a warning instead of failing the whole policy load.
			if (principalId.empty() || secret.empty() || m_principals.count(principalId) == 0)
			{
				LOG_WAR << "AuthorizationStore::load() dropped request-signing API key <" << entry.key()
						<< ">: principal is missing or the secret is empty";
				continue;
			}
			ApiKey key;
			key.keyId = entry.key();
			key.principalId = principalId;
			key.secret = secret;
			key.createdAt = GET_JSON_INT64_VALUE(definition, "created_at");
			m_apiKeys[entry.key()] = std::move(key);
		}
	}
}

std::shared_ptr<AuthorizationPrincipal> AuthorizationStore::resolve(const Principal &principal)
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto found = m_principals.find(principal.id());
	if (found == m_principals.end())
	{
		if (m_provisioningMode == "explicit")
			throw AuthorizationException("OIDC principal is not provisioned in App Mesh");
		// An external writer (appmesh-auth.sh add-user) may have bound this
		// subject on disk after the policy was loaded; adopt those bindings
		// before auto-provisioning a role-less record whose save would
		// overwrite them.
		mergeDiskPolicyLocked();
		found = m_principals.find(principal.id());
	}
	if (found == m_principals.end())
	{
		auto record = std::make_shared<AuthorizationPrincipal>(
			principal.id(), principal.kind(), principal.issuer(), principal.subject());
		record->updateClaims(principal);
		record->updatePolicy(nlohmann::json{{"roles", nlohmann::json::array()}});
		m_principals[principal.id()] = std::move(record);
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

	mergeDiskPolicyLocked();
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
	if (principalId == SYSTEM_PRINCIPAL_ID)
		throw AuthorizationException("the App Mesh system principal cannot be changed through the authorization API");

	mergeDiskPolicyLocked();
	auto found = m_principals.find(principalId);

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
		// Without an explicit status an update to a tombstoned principal would
		// answer success while it stays unusable; reviving is a deliberate act.
		if (found->second->status() == "tombstoned" && !definition.contains("status"))
			throw std::invalid_argument(
				"principal is tombstoned; set \"status\": \"active\" to restore it (\"disabled\" keeps it inert)");
	}
	candidate->updatePolicy(definition);
	validateRoles(candidate->roles());

	const auto previous = found == m_principals.end() ? nullptr : found->second;
	// The last active first-administrator binding must not be removed or
	// deactivated: without it the policy can no longer be repaired through the
	// API at all.
	if (previous && previous->active() && previous->roles().count(m_firstAdminRole) != 0 &&
		!(candidate->active() && candidate->roles().count(m_firstAdminRole) != 0) && activeFirstAdminCountLocked() <= 1)
	{
		throw AuthorizationException("cannot remove the last active first-administrator binding; assign the role to "
									 "another active principal first");
	}
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
	mergeDiskPolicyLocked();
	auto found = m_principals.find(principalId);
	if (found == m_principals.end())
		throw NotFoundException("principal not found");
	if (found->second->status() == "tombstoned")
		throw NotFoundException("active principal not found");
	if (found->second->active() && found->second->roles().count(m_firstAdminRole) != 0 && activeFirstAdminCountLocked() <= 1)
	{
		throw AuthorizationException("cannot delete the last active first-administrator; assign the role to another "
									 "active principal first");
	}

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
	// The principal's request-signing API keys are credentials of the removed
	// identity and must not outlive it.
	std::map<std::string, ApiKey> removedKeys;
	for (auto it = m_apiKeys.begin(); it != m_apiKeys.end();)
	{
		if (it->second.principalId == principalId)
		{
			removedKeys.insert(*it);
			it = m_apiKeys.erase(it);
		}
		else
			++it;
	}
	const auto previous = found->second;
	auto tombstone = std::make_shared<AuthorizationPrincipal>(*previous);
	tombstone->updatePolicy(nlohmann::json{
		{"status", "tombstoned"},
		{"execution_user", ""},
		{"roles", nlohmann::json::array()}});
	m_principals[principalId] = std::move(tombstone);
	try
	{
		saveLocked();
	}
	catch (...)
	{
		m_principals[principalId] = previous;
		for (const auto &removedKey : removedKeys)
			m_apiKeys.insert(removedKey);
		throw;
	}
	LOG_INF << fname << "tombstoned principal <" << principalId << "> and revoked its <" << removedKeys.size()
			<< "> API key(s)";
}

void AuthorizationStore::updateRole(const std::string &role, const nlohmann::json &permissions)
{
	const static char fname[] = "AuthorizationStore::updateRole() ";
	if (!validRoleName(role))
		throw std::invalid_argument("role name must be 1-128 characters using only letters, digits, '_' or '-'");
	const auto parsed = readStringSet(permissions, "role permissions");
	for (const auto &permission : parsed)
	{
		if (knownPermissions().count(permission) == 0)
			throw std::invalid_argument("unknown permission identifier: " + permission);
	}
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	mergeDiskPolicyLocked();
	auto found = m_roles.find(role);
	const bool existed = found != m_roles.end();
	if (existed && role == m_firstAdminRole)
	{
		// Emptying or stripping the first-administrator role below the ability to
		// repair the policy itself locks every administrator out of the cluster;
		// the delete path already refuses this role for the same reason.
		for (const char *permission : {PERMISSION_KEY_role_update, PERMISSION_KEY_principal_update})
		{
			if (parsed.count(permission) == 0)
				throw AuthorizationException(std::string("the first-administrator role must keep the <") + permission +
											 "> permission; assign another administrator before reducing it");
		}
	}
	const auto previous = existed ? std::move(found->second) : std::set<std::string>();
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
	mergeDiskPolicyLocked();
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

nlohmann::json AuthorizationStore::issueApiKey(const std::string &principalId)
{
	const static char fname[] = "AuthorizationStore::issueApiKey() ";
	if (principalId == SYSTEM_PRINCIPAL_ID)
		throw AuthorizationException("API keys are not issued for the App Mesh system principal; sign requests with a "
									 "user or service principal's key");
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto found = m_principals.find(principalId);
	if (found == m_principals.end() || !found->second->active())
		throw NotFoundException("active principal not found");
	std::size_t owned = 0;
	for (const auto &entry : m_apiKeys)
		if (entry.second.principalId == principalId)
			++owned;
	if (owned >= MAX_API_KEYS_PER_PRINCIPAL)
		throw AuthorizationException("principal already holds the maximum of " +
									 std::to_string(MAX_API_KEYS_PER_PRINCIPAL) +
									 " API keys; revoke one first");

	ApiKey key;
	key.principalId = principalId;
	key.secret = generatePassword(48, true, true, true, true);
	key.createdAt = std::chrono::duration_cast<std::chrono::seconds>(
						std::chrono::system_clock::now().time_since_epoch())
						.count();
	do
	{
		key.keyId = "ak-" + generatePassword(12, true, false, true, false);
	} while (m_apiKeys.count(key.keyId) != 0);
	m_apiKeys[key.keyId] = key;
	try
	{
		saveLocked();
	}
	catch (...)
	{
		m_apiKeys.erase(key.keyId);
		throw;
	}
	LOG_INF << fname << "issued API key <" << key.keyId << "> for principal <" << principalId << ">";

	// The secret is returned exactly once; apiKeysJson never includes it.
	nlohmann::json result;
	result["key_id"] = key.keyId;
	result["principal"] = key.principalId;
	result["secret"] = key.secret;
	result["created_at"] = key.createdAt;
	return result;
}

nlohmann::json AuthorizationStore::apiKeysJson(const std::string &principalId, bool all) const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	nlohmann::json list = nlohmann::json::array();
	for (const auto &entry : m_apiKeys)
	{
		if (!all && entry.second.principalId != principalId)
			continue;
		nlohmann::json item;
		item["key_id"] = entry.first;
		item["principal"] = entry.second.principalId;
		item["created_at"] = entry.second.createdAt;
		list.push_back(std::move(item));
	}
	return list;
}

bool AuthorizationStore::deleteApiKey(const std::string &keyId, const std::string &requestingPrincipalId, bool manageAll)
{
	const static char fname[] = "AuthorizationStore::deleteApiKey() ";
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto found = m_apiKeys.find(keyId);
	if (found == m_apiKeys.end())
		return false;
	if (!manageAll && found->second.principalId != requestingPrincipalId)
		throw AuthorizationException("an API key can only be revoked by its owner or with the " +
									 std::string(PERMISSION_KEY_principal_update) + " permission");
	const auto removed = found->second;
	m_apiKeys.erase(found);
	try
	{
		saveLocked();
	}
	catch (...)
	{
		m_apiKeys[keyId] = removed;
		throw;
	}
	LOG_INF << fname << "revoked API key <" << keyId << "> at the request of <" << requestingPrincipalId << ">";
	return true;
}

bool AuthorizationStore::apiKeySecret(const std::string &keyId, std::string &principalId, std::string &secret) const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	auto found = m_apiKeys.find(keyId);
	if (found == m_apiKeys.end())
		return false;
	// The key's validity is bound to its owner's status: disabling the
	// principal revokes its keys (verification fails closed) without the
	// delete-level cascade, and a dangling owner can never sign either.
	auto owner = m_principals.find(found->second.principalId);
	if (owner == m_principals.end() || !owner->second->active())
		return false;
	principalId = found->second.principalId;
	secret = found->second.secret;
	return true;
}

void AuthorizationStore::save() const
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	saveLocked();
}

void AuthorizationStore::mergeDiskPolicyLocked()
{
	const static char fname[] = "AuthorizationStore::mergeDiskPolicyLocked() ";
	try
	{
		const auto file = Utility::getConfigFilePath(APPMESH_AUTHORIZATION_CONFIG_FILE);
		if (!Utility::isFileExist(file))
			return;
		const auto root = Utility::yamlToJson(YAML::LoadFile(file));
		if (!root.contains("Authorization") || !root.at("Authorization").is_object())
			return;
		const auto &authorization = root.at("Authorization");

		// Roles and principals this process deleted were removed from disk by the
		// saveLocked() of the deleting call, so entries present only on disk are
		// external additions and are adopted; entries present in memory keep the
		// in-memory state (deliberate API updates and tombstones win).
		if (authorization.contains("roles") && authorization.at("roles").is_object())
		{
			for (const auto &entry : authorization.at("roles").items())
			{
				if (m_roles.count(entry.key()) == 0)
				{
					m_roles[entry.key()] = readStringSet(entry.value(), "role permissions");
					LOG_INF << fname << "adopted on-disk role <" << entry.key() << ">";
				}
			}
		}
		if (authorization.contains("principals") && authorization.at("principals").is_object())
		{
			for (const auto &entry : authorization.at("principals").items())
			{
				if (m_principals.count(entry.key()) != 0)
					continue;
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
				LOG_INF << fname << "adopted on-disk principal binding <" << entry.key() << ">";
			}
		}
		// Same rule for request-signing keys: entries added on disk by an
		// external writer are adopted; in-memory state (and revocations) wins.
		if (authorization.contains("api_keys") && authorization.at("api_keys").is_object())
		{
			for (const auto &entry : authorization.at("api_keys").items())
			{
				if (m_apiKeys.count(entry.key()) != 0)
					continue;
				const auto &definition = entry.value();
				const auto principalId = GET_JSON_STR_VALUE(definition, "principal");
				std::string secret;
				try
				{
					secret = readStoredSecret(entry.key(), GET_JSON_STR_VALUE(definition, "secret"));
				}
				catch (const std::exception &)
				{
					LOG_WAR << fname << "stored secret of on-disk API key <" << entry.key()
							<< "> is not a readable encrypted secret; not adopted";
					continue;
				}
				if (principalId.empty() || secret.empty() || m_principals.count(principalId) == 0)
					continue;
				ApiKey key;
				key.keyId = entry.key();
				key.principalId = principalId;
				key.secret = secret;
				key.createdAt = GET_JSON_INT64_VALUE(definition, "created_at");
				m_apiKeys[entry.key()] = std::move(key);
				LOG_INF << fname << "adopted on-disk API key <" << entry.key() << ">";
			}
		}
	}
	catch (const std::exception &e)
	{
		// The policy file may be concurrently replaced by an external writer;
		// never break authentication or a policy update over a transient read.
		LOG_WAR << fname << "could not merge the on-disk authorization policy: " << e.what();
	}
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
	{
		nlohmann::json apiKeys = nlohmann::json::object();
		for (const auto &entry : m_apiKeys)
		{
			nlohmann::json item;
			item["principal"] = entry.second.principalId;
			// At rest: encrypted; a replication wire snapshot stays plaintext for follower-side HMAC.
			item["secret"] = SecretProtector::instance().protect(entry.second.secret, apiKeySecretContext(entry.first));
			item["created_at"] = entry.second.createdAt;
			apiKeys[entry.first] = std::move(item);
		}
		authorization["api_keys"] = std::move(apiKeys);
	}
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
		throw std::invalid_argument(std::string(AUTH_MODE_ENV) + " must be builtin or external");
	m_builtinAuthentication = authMode == BUILTIN_AUTH_MODE;

	// Versions before automatic subject-pinned enrollment generated a second
	// owner-only proof. It is no longer accepted, so remove any stale copy during
	// the upgrade instead of leaving obsolete credential material behind.
	const auto legacyProofPath = SecretProtector::secretsFilePath("first-admin-enrollment-token");
	if (Utility::isFileExist(legacyProofPath))
		Utility::removeFile(legacyProofPath);

	const auto authRole = resolveAuthRole();
	m_firstAdminEnrollmentEnabled = authMode == BUILTIN_AUTH_MODE &&
		(authRole == "standalone" || authRole == "owner");

	mergeDiskPolicyLocked();
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

std::size_t AuthorizationStore::activeFirstAdminCountLocked() const
{
	std::size_t count = 0;
	for (const auto &entry : m_principals)
	{
		if (entry.first != SYSTEM_PRINCIPAL_ID && entry.second->active() && entry.second->roles().count(m_firstAdminRole) != 0)
			++count;
	}
	return count;
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
