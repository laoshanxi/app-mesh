#include "AuthorizationStore.h"

#include "../../common/Utility.h"
#include "../../common/json.h"
#include "../../common/os/filesystem.h"
#include "../Configuration.h"
#include "../application/Application.h"
#include "AuthReplicator.h"
#include "Security.h"

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
	const char *DEFAULT_FIRST_ADMIN_SUBJECT = "CiQyZDFjOGMzOC0zODk4LTRjODktYTc4Yi0zY2FhNDJmMjAzYzESBWxvY2Fs";

	std::string resolveAuthRole()
	{
		auto role = Utility::getenv(AUTH_ROLE_ENV);
		if (role.empty())
		{
			const auto file = Utility::getConfigFilePath(AUTH_STACK_CONFIG_FILE);
			const auto root = Utility::yamlToJson(YAML::LoadFile(file));
			if (!root.isMember("AuthStack") || !root["AuthStack"].isObject())
				throw std::invalid_argument("auth-stack.yaml must contain an AuthStack object");
			role = GET_JSON_STR_VALUE(root["AuthStack"], "role");
		}
		if (role != "standalone" && role != "owner" && role != "follower")
			throw std::invalid_argument("AuthStack.role must be standalone, owner, or follower");
		return role;
	}

	// Serialize a role/permission set as a JSON string array
	Json::Value toJsonArray(const std::set<std::string> &values)
	{
		Json::Value array(Json::arrayValue);
		for (const auto &value : values)
			array.append(value);
		return array;
	}

	std::set<std::string> readStringSet(const Json::Value &value, const char *field)
	{
		std::set<std::string> result;
		if (!value.isArray())
			throw std::invalid_argument(std::string(field) + " must be an array");
		for (const auto &entry : value)
		{
			if (!entry.isString() || entry.asString().empty())
				throw std::invalid_argument(std::string(field) + " entries must be non-empty strings");
			result.insert(entry.asString());
		}
		return result;
	}

}

AuthorizationPrincipal::AuthorizationPrincipal(std::string principalId, Principal::Kind kind, std::string issuer,
											   std::string subject)
	: m_id(std::move(principalId)), m_kind(kind), m_issuer(std::move(issuer)), m_subject(std::move(subject)),
	  m_status("active")
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

void AuthorizationPrincipal::updatePolicy(const Json::Value &json)
{
	// Strict reads: asString() would coerce wrong-typed scalars (42 -> "42").
	if (json.isMember("status"))
	{
		const auto status = Utility::jsonStringField(json, "status");
		if (status != "active" && status != "disabled" && status != "tombstoned")
			throw std::invalid_argument("principal status must be active, disabled, or tombstoned");
		m_status = status;
	}
	if (json.isMember("execution_user"))
		m_executionUser = Utility::jsonStringField(json, "execution_user");
	if (json.isMember("roles"))
		m_roles = readStringSet(json["roles"], "roles");
	if (json.isMember("display_name"))
		m_displayName = Utility::jsonStringField(json, "display_name");
	if (json.isMember("email"))
		m_email = Utility::jsonStringField(json, "email");
	if (json.isMember("connector_id"))
		m_connectorId = Utility::jsonStringField(json, "connector_id");
}

Json::Value AuthorizationPrincipal::asJson() const
{
	Json::Value result;
	result["principal_id"] = m_id;
	result["kind"] = Principal::kindName(m_kind);
	result["issuer"] = m_issuer;
	result["subject"] = m_subject;
	result["display_name"] = m_displayName;
	result["email"] = m_email;
	result["connector_id"] = m_connectorId;
	result["status"] = m_status;
	result["execution_user"] = m_executionUser;
	result["roles"] = toJsonArray(m_roles);
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
	: m_provisioningMode("explicit-or-minimal"), m_firstAdminRole("appmesh-admin"), m_firstAdminEnrolled(false),
	  m_firstAdminEnrollmentEnabled(false), m_builtinAuthentication(false)
{
}

void AuthorizationStore::init()
{
	const static char fname[] = "AuthorizationStore::init() ";
	// Replica mode decides where the policy loads from and persists to; it must
	// be established before the first load.
	const auto replicationSource = Utility::stdStringTrim(Utility::getenv("APPMESH_AUTH_REPLICATION_FROM"));
	if (!replicationSource.empty())
	{
		m_replicaMode = true;
		// The cache is a follower-local accelerator, never a hand-edited policy
		// file; work/auth/replication/ cannot host it (mounted read-only).
		m_replicaCacheFile =
			(fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / APPMESH_WORK_CONFIG_DIR / "replica-policy.yaml").string();
	}

	Json::Value root;
	bool loaded = false;
	if (m_replicaMode && Utility::isFileExist(m_replicaCacheFile))
	{
		// Load the last synced snapshot so a restart authorizes immediately; the
		// schedule loop refreshes it from the owner right after boot.
		try
		{
			root = Utility::yamlToJson(YAML::LoadFile(m_replicaCacheFile));
			loaded = true;
			LOG_INF << fname << "loaded the replicated authorization policy cache <" << m_replicaCacheFile << ">";
		}
		catch (const std::exception &e)
		{
			LOG_WAR << fname << "replicated policy cache <" << m_replicaCacheFile << "> is unreadable: " << e.what();
		}
	}
	if (!loaded)
	{
		const auto file = Utility::getConfigFilePath(APPMESH_AUTHORIZATION_CONFIG_FILE);
		try
		{
			root = Utility::yamlToJson(YAML::LoadFile(file));
		}
		catch (const std::exception &e)
		{
			// An unreadable runtime policy (bad mode/owner after a manual copy) must not
			// crash-loop the node: fall back to the packaged policy and keep booting.
			LOG_ERR << fname << "authorization policy <" << file << "> is not readable: " << e.what()
					<< "; falling back to the packaged policy. Fix the file mode (0600) and owner, or let cluster "
					   "replication replace it.";
			const auto packaged =
				(fs::path(Utility::getHomeDir()) / APPMESH_WORK_CONFIG_DIR / APPMESH_AUTHORIZATION_CONFIG_FILE).string();
			root = Utility::yamlToJson(YAML::LoadFile(packaged));
		}
	}
	Configuration::overrideConfigWithEnv(root);
	load(root);
	initializeFirstAdminEnrollment();
}

AuthorizationStore::PolicyData AuthorizationStore::parsePolicy(const Json::Value &root)
{
	if (!root.isMember("Authorization") || !root["Authorization"].isObject())
		throw std::invalid_argument("authorization.yaml must contain an Authorization object");
	const auto &authorization = root["Authorization"];
	PolicyData data;
	data.provisioningMode = GET_JSON_STR_VALUE(authorization, "provisioning");
	if (data.provisioningMode.empty())
		data.provisioningMode = "explicit-or-minimal";
	if (data.provisioningMode != "explicit" && data.provisioningMode != "explicit-or-minimal")
		throw std::invalid_argument("Authorization.provisioning must be explicit or explicit-or-minimal");
	data.firstAdminRole = GET_JSON_STR_VALUE(authorization, "first_admin_role");
	// Preserve the role selection when upgrading a pre-enrollment authorization file.
	if (data.firstAdminRole.empty())
		data.firstAdminRole = GET_JSON_STR_VALUE(authorization, "bootstrap_admin_role");
	if (data.firstAdminRole.empty())
		data.firstAdminRole = "appmesh-admin";
	data.firstAdminSubject = GET_JSON_STR_VALUE(authorization, "first_admin_subject");
	if (data.firstAdminSubject.empty())
		data.firstAdminSubject = DEFAULT_FIRST_ADMIN_SUBJECT;
	data.firstAdminEnrolled = GET_JSON_BOOL_VALUE(authorization, "first_admin_enrolled");

	if (authorization.isMember("roles"))
	{
		if (!authorization["roles"].isObject())
			throw std::invalid_argument("Authorization.roles must be an object");
		for (const auto &role : authorization["roles"].getMemberNames())
			data.roles[role] = readStringSet(authorization["roles"][role], "role permissions");
	}
	if (data.roles.count(data.firstAdminRole) == 0)
		throw std::invalid_argument("first_admin_role is not defined in Authorization.roles");

	if (authorization.isMember("principals"))
	{
		if (!authorization["principals"].isObject())
			throw std::invalid_argument("Authorization.principals must be an object");
		for (const auto &principalId : authorization["principals"].getMemberNames())
		{
			const auto &definition = authorization["principals"][principalId];
			const auto kind = parseKind(GET_JSON_STR_VALUE(definition, "kind"));
			const auto issuer = GET_JSON_STR_VALUE(definition, "issuer");
			const auto subject = GET_JSON_STR_VALUE(definition, "subject");
			if (kind != Principal::Kind::System && principalId != Principal::stableId(issuer, subject))
				throw std::invalid_argument("OIDC principal key '" + principalId +
											"' must equal the stable (issuer, subject) identifier '" +
											Principal::stableId(issuer, subject) +
											"'; re-key principals in Authorization.principals after an issuer URL change");
			auto principal = std::make_shared<AuthorizationPrincipal>(principalId, kind, issuer, subject);
			principal->updatePolicy(definition);
			for (const auto &role : principal->roles())
				if (data.roles.count(role) == 0)
					throw std::invalid_argument("principal references an undefined role: " + role);
			data.principals[principalId] = std::move(principal);
		}
	}
	if (data.principals.count(SYSTEM_PRINCIPAL_ID) == 0)
		data.principals[SYSTEM_PRINCIPAL_ID] = std::make_shared<AuthorizationPrincipal>(
			SYSTEM_PRINCIPAL_ID, Principal::Kind::System, "appmesh-internal", "appmesh");
	return data;
}

Json::Value AuthorizationStore::policyToJson(const PolicyData &data)
{
	Json::Value authorization;
	authorization["provisioning"] = data.provisioningMode;
	authorization["first_admin_role"] = data.firstAdminRole;
	authorization["first_admin_subject"] = data.firstAdminSubject;
	authorization["first_admin_enrolled"] = data.firstAdminEnrolled;
	Json::Value roles(Json::objectValue);
	for (const auto &[role, permissions] : data.roles)
		roles[role] = toJsonArray(permissions);
	authorization["roles"] = roles;
	Json::Value principals(Json::objectValue);
	for (const auto &[id, principal] : data.principals)
		principals[id] = principal->asJson();
	authorization["principals"] = principals;
	Json::Value root;
	root["Authorization"] = std::move(authorization);
	return root;
}

void AuthorizationStore::commitPolicyLocked(const PolicyData &data)
{
	m_provisioningMode = data.provisioningMode;
	m_firstAdminRole = data.firstAdminRole;
	m_firstAdminSubject = data.firstAdminSubject;
	m_firstAdminEnrolled = data.firstAdminEnrolled;
	m_roles = data.roles;
	m_principals = data.principals;
}

void AuthorizationStore::requireWritablePolicyLocked() const
{
	if (m_replicaMode)
		throw AuthorizationException(
			"this node replicates the owner's authorization policy; apply the change on the owner node");
}

void AuthorizationStore::load(const Json::Value &root)
{
	std::lock_guard guard(m_mutex);
	commitPolicyLocked(parsePolicy(root));
}

std::shared_ptr<AuthorizationPrincipal> AuthorizationStore::resolve(const Principal &principal)
{
	std::lock_guard guard(m_mutex);
	auto found = m_principals.find(principal.id());
	if (found == m_principals.end())
	{
		if (m_provisioningMode == "explicit")
			throw AuthorizationException("OIDC principal is not provisioned in App Mesh");
		if (!m_replicaMode)
		{
			// An external writer (appmesh-auth.sh add-user) may have bound this
			// subject on disk after the policy was loaded; adopt those bindings
			// before auto-provisioning a role-less record whose save would
			// overwrite them. A replica skips this: the owner snapshot is the policy.
			mergeDiskPolicyLocked();
			found = m_principals.find(principal.id());
		}
	}
	if (found == m_principals.end())
	{
		auto record = std::make_shared<AuthorizationPrincipal>(principal.id(), principal.kind(), principal.issuer(),
															   principal.subject());
		record->updateClaims(principal);
		Json::Value policy;
		policy["roles"] = Json::Value(Json::arrayValue);
		record->updatePolicy(policy);
		m_principals[principal.id()] = std::move(record);
		if (!m_replicaMode)
		{
			// On a policy-owning node the first sight persists the role-less record.
			// A replica keeps it in memory only: the owner snapshot is the policy.
			try
			{
				saveLocked();
			}
			catch (...)
			{
				m_principals.erase(principal.id());
				throw;
			}
		}
		found = m_principals.find(principal.id());
		// First sight of this principal: pull the owner's binding for it
		// promptly instead of waiting out the replication interval (no-op
		// when replication is not configured).
		AuthReplicator::instance().notifyPolicyMiss();
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
	std::lock_guard guard(m_mutex);
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
						 ? std::make_shared<AuthorizationPrincipal>(principal.id(), principal.kind(), principal.issuer(),
																	principal.subject())
						 : std::make_shared<AuthorizationPrincipal>(*found->second);
	candidate->updateClaims(principal);
	auto roles = candidate->roles();
	roles.insert(m_firstAdminRole);
	Json::Value firstAdminPolicy;
	firstAdminPolicy["roles"] = Json::Value(Json::arrayValue);
	for (const auto &role : roles)
		firstAdminPolicy["roles"].append(role);
	candidate->updatePolicy(firstAdminPolicy);

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

	LOG_INF << fname << "enrolled principal <" << principal.id() << "> into the first-administrator role <"
			<< m_firstAdminRole << ">";
	return candidate;
}

std::shared_ptr<AuthorizationPrincipal> AuthorizationStore::get(const std::string &principalId) const
{
	std::lock_guard guard(m_mutex);
	auto found = m_principals.find(principalId);
	if (found == m_principals.end())
		throw NotFoundException("principal not found");
	return found->second;
}

std::set<std::string> AuthorizationStore::permissions(const std::string &principalId) const
{
	std::lock_guard guard(m_mutex);
	const auto principal = get(principalId);
	if (!principal->active())
		throw AuthorizationException("App Mesh principal is not active");
	std::set<std::string> result;
	for (const auto &role : principal->roles())
	{
		if (auto found = m_roles.find(role); found != m_roles.end())
			result.insert(found->second.begin(), found->second.end());
	}
	return result;
}

std::set<std::string> AuthorizationStore::allPermissions() const
{
	std::lock_guard guard(m_mutex);
	std::set<std::string> result;
	for (const auto &role : m_roles)
		result.insert(role.second.begin(), role.second.end());
	return result;
}

bool AuthorizationStore::builtinAuthentication() const
{
	std::lock_guard guard(m_mutex);
	return m_builtinAuthentication;
}

Json::Value AuthorizationStore::firstAdminEnrollment() const
{
	std::lock_guard guard(m_mutex);
	const bool available = m_firstAdminEnrollmentEnabled && !m_firstAdminEnrolled && !hasFirstAdminLocked();
	Json::Value result;
	result["available"] = available;
	if (available)
		result["subject"] = m_firstAdminSubject;
	return result;
}

Json::Value AuthorizationStore::principalsJson() const
{
	std::lock_guard guard(m_mutex);
	Json::Value result = Json::Value(Json::objectValue);
	for (const auto &[id, principal] : m_principals)
		result[id] = principal->asJson();
	return result;
}

Json::Value AuthorizationStore::rolesJson() const
{
	std::lock_guard guard(m_mutex);
	Json::Value result = Json::Value(Json::objectValue);
	for (const auto &[name, role] : m_roles)
		result[name] = toJsonArray(role);
	return result;
}

void AuthorizationStore::updatePrincipal(const std::string &principalId, const Json::Value &definition)
{
	const static char fname[] = "AuthorizationStore::updatePrincipal() ";
	if (!definition.isObject())
		throw std::invalid_argument("principal definition must be an object");
	if (definition.isMember("status") && definition["status"].isString() && definition["status"].asString() == "tombstoned")
	{
		throw AuthorizationException("use the Principal DELETE operation to create a tombstone after ownership checks");
	}
	std::lock_guard guard(m_mutex);
	if (principalId == SYSTEM_PRINCIPAL_ID)
		throw AuthorizationException("the App Mesh system principal cannot be changed through the authorization API");
	requireWritablePolicyLocked();

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
			throw std::invalid_argument("OIDC principal key '" + principalId +
										"' must equal the stable (issuer, subject) identifier '" +
										Principal::stableId(issuer, subject) + "'");
		candidate = std::make_shared<AuthorizationPrincipal>(principalId, kind, issuer, subject);
	}
	else
	{
		candidate = std::make_shared<AuthorizationPrincipal>(*found->second);
		if (definition.isMember("kind") && parseKind(GET_JSON_STR_VALUE(definition, "kind")) != candidate->kind())
			throw std::invalid_argument("principal kind is immutable");
		if (definition.isMember("issuer") && GET_JSON_STR_VALUE(definition, "issuer") != candidate->issuer())
			throw std::invalid_argument("principal issuer is immutable");
		if (definition.isMember("subject") && GET_JSON_STR_VALUE(definition, "subject") != candidate->subject())
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
	LOG_INF << fname << (previous ? "updated" : "created") << " principal <" << principalId
			<< "> roles: " << JSON::dump(toJsonArray(candidate->roles()));
}

void AuthorizationStore::deletePrincipal(const std::string &principalId)
{
	const static char fname[] = "AuthorizationStore::deletePrincipal() ";
	const auto config = Configuration::instance();
	std::unique_lock<std::recursive_mutex> applicationMutation;
	if (config)
		applicationMutation = config->lockAppMutation();

	std::lock_guard guard(m_mutex);
	if (principalId == SYSTEM_PRINCIPAL_ID)
		throw AuthorizationException("the App Mesh system principal cannot be deleted");
	requireWritablePolicyLocked();
	mergeDiskPolicyLocked();
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
				throw AuthorizationException("principal owns application <" + app->getName() +
											 ">; transfer the application owner first (PUT /appmesh/app/<name> with "
											 "owner_principal_id, requires the " +
											 std::string(PERMISSION_KEY_app_manage_all) +
											 " permission) or delete the application");
			}
		}
	}

	// Keep the immutable issuer/subject binding as a durable tombstone. Erasing
	// it would let explicit-or-minimal provisioning recreate the same subject as
	// a new Principal and would destroy the authorization audit boundary.
	const auto previous = found->second;
	auto tombstone = std::make_shared<AuthorizationPrincipal>(*previous);
	Json::Value tombstonePolicy;
	tombstonePolicy["status"] = "tombstoned";
	tombstonePolicy["execution_user"] = "";
	tombstonePolicy["roles"] = Json::Value(Json::arrayValue);
	tombstone->updatePolicy(tombstonePolicy);
	m_principals[principalId] = std::move(tombstone);
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

void AuthorizationStore::updateRole(const std::string &role, const Json::Value &permissions)
{
	const static char fname[] = "AuthorizationStore::updateRole() ";
	if (role.empty())
		throw std::invalid_argument("role name cannot be empty");
	const auto parsed = readStringSet(permissions, "role permissions");
	std::lock_guard guard(m_mutex);
	requireWritablePolicyLocked();
	mergeDiskPolicyLocked();
	auto found = m_roles.find(role);
	const bool existed = found != m_roles.end();
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
	LOG_INF << fname << (existed ? "updated" : "created") << " role <" << role
			<< "> permissions: " << JSON::dump(toJsonArray(parsed));
}

void AuthorizationStore::deleteRole(const std::string &role)
{
	const static char fname[] = "AuthorizationStore::deleteRole() ";
	std::lock_guard guard(m_mutex);
	if (role == m_firstAdminRole)
		throw AuthorizationException("the first-administrator role cannot be deleted");
	requireWritablePolicyLocked();
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

void AuthorizationStore::save() const
{
	std::lock_guard guard(m_mutex);
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
		if (!root.isMember("Authorization") || !root["Authorization"].isObject())
			return;
		const auto &authorization = root["Authorization"];

		// Roles and principals this process deleted were removed from disk by the
		// saveLocked() of the deleting call, so entries present only on disk are
		// external additions and are adopted; entries present in memory keep the
		// in-memory state (deliberate API updates and tombstones win).
		if (authorization.isMember("roles") && authorization["roles"].isObject())
		{
			for (const auto &role : authorization["roles"].getMemberNames())
			{
				if (m_roles.count(role) == 0)
				{
					m_roles[role] = readStringSet(authorization["roles"][role], "role permissions");
					LOG_INF << fname << "adopted on-disk role <" << role << ">";
				}
			}
		}
		if (authorization.isMember("principals") && authorization["principals"].isObject())
		{
			for (const auto &principalId : authorization["principals"].getMemberNames())
			{
				if (m_principals.count(principalId) != 0)
					continue;
				const auto &definition = authorization["principals"][principalId];
				const auto kind = parseKind(GET_JSON_STR_VALUE(definition, "kind"));
				const auto issuer = GET_JSON_STR_VALUE(definition, "issuer");
				const auto subject = GET_JSON_STR_VALUE(definition, "subject");
				if (kind != Principal::Kind::System && principalId != Principal::stableId(issuer, subject))
					throw std::invalid_argument("OIDC principal key must equal the stable (issuer, subject) identifier");
				auto principal = std::make_shared<AuthorizationPrincipal>(principalId, kind, issuer, subject);
				principal->updatePolicy(definition);
				validateRoles(principal->roles());
				m_principals[principalId] = std::move(principal);
				LOG_INF << fname << "adopted on-disk principal binding <" << principalId << ">";
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
	Json::Value authorization;
	authorization["provisioning"] = m_provisioningMode;
	authorization["first_admin_role"] = m_firstAdminRole;
	authorization["first_admin_subject"] = m_firstAdminSubject;
	authorization["first_admin_enrolled"] = m_firstAdminEnrolled;
	authorization["roles"] = rolesJson();
	authorization["principals"] = principalsJson();
	Json::Value root;
	root["Authorization"] = std::move(authorization);

	// A replica persists only its synced snapshot cache; the node-local
	// authorization.yaml keeps its own (packaged) content untouched.
	const auto path =
		m_replicaMode ? m_replicaCacheFile : Utility::getConfigFilePath(APPMESH_AUTHORIZATION_CONFIG_FILE, true);
	if (m_replicaMode)
		// The image ships no work/config/; only the non-replica branch creates it.
		Utility::createDirectory(fs::path(path).parent_path().string());
	const auto tmp = os::createTmpFile(path, Utility::jsonToYaml(root), 0600);
	if (tmp.empty())
		throw std::runtime_error("could not create temporary authorization configuration");
	std::error_code renameError;
	fs::rename(tmp, path, renameError);
	if (renameError)
	{
		Utility::removeFile(tmp);
		throw std::runtime_error(std::string("failed to replace authorization configuration: ") + renameError.message());
	}
}

Json::Value AuthorizationStore::replicationSnapshotJson() const
{
	std::lock_guard guard(m_mutex);
	PolicyData current;
	current.provisioningMode = m_provisioningMode;
	current.firstAdminRole = m_firstAdminRole;
	current.firstAdminSubject = m_firstAdminSubject;
	current.firstAdminEnrolled = m_firstAdminEnrolled;
	current.roles = m_roles;
	current.principals = m_principals;
	return policyToJson(current);
}

bool AuthorizationStore::applyReplicatedPolicy(const Json::Value &root)
{
	const static char fname[] = "AuthorizationStore::applyReplicatedPolicy() ";
	std::lock_guard guard(m_mutex);
	const auto incoming = parsePolicy(root);

	// Single-writer replication: the owner snapshot wins, including over the
	// follower-local auto-provisioned records, so a stale role-less shadow can
	// never mask the owner's binding. The snapshot carries only scalar policy
	// state, so serialized equality is a sound change test.
	PolicyData current;
	current.provisioningMode = m_provisioningMode;
	current.firstAdminRole = m_firstAdminRole;
	current.firstAdminSubject = m_firstAdminSubject;
	current.firstAdminEnrolled = m_firstAdminEnrolled;
	current.roles = m_roles;
	current.principals = m_principals;

	if (JSON::dump(policyToJson(incoming)) == JSON::dump(policyToJson(current)))
		return false;
	commitPolicyLocked(incoming);
	try
	{
		saveLocked();
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "policy applied in memory but could not be persisted: " << e.what();
	}
	LOG_INF << fname << "applied replicated policy: " << incoming.principals.size() << " principals, "
			<< incoming.roles.size() << " roles";
	return true;
}

void AuthorizationStore::initializeFirstAdminEnrollment()
{
	const static char fname[] = "AuthorizationStore::initializeFirstAdminEnrollment() ";
	std::lock_guard guard(m_mutex);
	const auto authMode = Utility::getenv(AUTH_MODE_ENV, BUILTIN_AUTH_MODE);
	if (authMode != BUILTIN_AUTH_MODE && authMode != EXTERNAL_AUTH_MODE)
		throw std::invalid_argument("APPMESH_AUTH_MODE must be builtin or external");
	m_builtinAuthentication = authMode == BUILTIN_AUTH_MODE;

	// Versions before automatic subject-pinned enrollment generated a second
	// owner-only proof. It is no longer accepted, so remove any stale copy during
	// the upgrade instead of leaving obsolete credential material behind.
	const auto legacyProofPath =
		(fs::path(Utility::getHomeDir()) / APPMESH_WORK_DIR / "auth" / "secrets" / "first-admin-enrollment-token").string();
	if (Utility::isFileExist(legacyProofPath))
		Utility::removeFile(legacyProofPath);

	const auto authRole = resolveAuthRole();
	m_firstAdminEnrollmentEnabled = authMode == BUILTIN_AUTH_MODE && (authRole == "standalone" || authRole == "owner");

	if (!m_replicaMode)
		mergeDiskPolicyLocked();
	const bool inferredEnrollment = hasFirstAdminLocked();
	if (inferredEnrollment && !m_firstAdminEnrolled)
	{
		// Migration safety: a previously provisioned administrator permanently closes
		// the one-time enrollment window even if the old file lacks the durable marker.
		m_firstAdminEnrolled = true;
		if (!m_replicaMode)
			saveLocked();
	}
	if (!m_firstAdminEnrollmentEnabled || m_firstAdminEnrolled)
		return;

	LOG_INF << fname << "first-admin enrollment is available only to the packaged administrator from loopback";
}

bool AuthorizationStore::hasFirstAdminLocked() const
{
	for (const auto &[id, principal] : m_principals)
	{
		if (id != SYSTEM_PRINCIPAL_ID && principal->roles().count(m_firstAdminRole) != 0)
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
