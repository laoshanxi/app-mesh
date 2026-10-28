#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <json/json.h>

#include "Principal.h"

class AuthorizationPrincipal
{
public:
	AuthorizationPrincipal(std::string principalId, Principal::Kind kind, std::string issuer, std::string subject);

	const std::string &id() const;
	const std::string &issuer() const;
	const std::string &subject() const;
	Principal::Kind kind() const;
	const std::string &status() const;
	const std::string &executionUser() const;
	const std::set<std::string> &roles() const;
	bool active() const;

	void updateClaims(const Principal &principal);
	void updatePolicy(const Json::Value &json);
	Json::Value asJson() const;
	/// Rebuild the verified identity view from this record, keeping the claims
	/// captured when the token was last verified.
	Principal asPrincipal() const;

private:
	std::string m_id;
	Principal::Kind m_kind;
	std::string m_issuer;
	std::string m_subject;
	std::string m_displayName;
	std::string m_email;
	std::string m_connectorId;
	std::string m_status;
	std::string m_executionUser;
	std::set<std::string> m_roles;
};

/// Password-free authorization store keyed by stable Principal ID.
class AuthorizationStore
{
public:
	AuthorizationStore();

	void init();
	std::shared_ptr<AuthorizationPrincipal> resolve(const Principal &principal);
	std::shared_ptr<AuthorizationPrincipal> enrollFirstAdmin(const Principal &principal);
	std::shared_ptr<AuthorizationPrincipal> get(const std::string &principalId) const;
	std::set<std::string> permissions(const std::string &principalId) const;
	std::set<std::string> allPermissions() const;
	bool builtinAuthentication() const;
	Json::Value firstAdminEnrollment() const;

	Json::Value principalsJson() const;
	Json::Value rolesJson() const;
	void updatePrincipal(const std::string &principalId, const Json::Value &definition);
	void deletePrincipal(const std::string &principalId);
	void updateRole(const std::string &role, const Json::Value &permissions);
	void deleteRole(const std::string &role);
	void save() const;

	/// Serialize the policy in the on-disk shape ({"Authorization": {...}}); this
	/// is the payload the cluster replication endpoint serves to followers.
	Json::Value replicationSnapshotJson() const;
	/// Replace the whole policy from a replicated owner snapshot. The snapshot is
	/// validated before anything is committed: an invalid snapshot throws and
	/// leaves the current policy untouched. Returns true when the policy changed.
	bool applyReplicatedPolicy(const Json::Value &root);

	static const std::string &systemPrincipalId();

private:
	/// A parsed policy snapshot. parsePolicy() throws on invalid input without
	/// touching member state, so callers can validate before committing.
	struct PolicyData
	{
		std::string provisioningMode;
		std::string firstAdminRole;
		std::string firstAdminSubject;
		bool firstAdminEnrolled = false;
		std::map<std::string, std::set<std::string>> roles;
		std::map<std::string, std::shared_ptr<AuthorizationPrincipal>> principals;
	};
	static PolicyData parsePolicy(const Json::Value &root);
	static Json::Value policyToJson(const PolicyData &data);
	void commitPolicyLocked(const PolicyData &data);
	/// Single-writer guard: a replica serves the owner's policy read-only.
	void requireWritablePolicyLocked() const;

	void load(const Json::Value &root);
	void initializeFirstAdminEnrollment();
	bool hasFirstAdminLocked() const;
	void validateRoles(const std::set<std::string> &roles) const;
	/// Adopt role and principal bindings written directly to the on-disk policy
	/// (e.g. by appmesh-auth.sh add-user) after this process loaded it, so the
	/// next saveLocked() upserts them instead of overwriting from stale memory.
	/// Caller must hold m_mutex; an unreadable or invalid file only logs.
	void mergeDiskPolicyLocked();
	void saveLocked() const;
	static Principal::Kind parseKind(const std::string &kind);

	mutable std::recursive_mutex m_mutex;
	std::map<std::string, std::shared_ptr<AuthorizationPrincipal>> m_principals;
	std::map<std::string, std::set<std::string>> m_roles;
	std::string m_provisioningMode;
	std::string m_firstAdminRole;
	std::string m_firstAdminSubject;
	bool m_firstAdminEnrolled;
	bool m_firstAdminEnrollmentEnabled;
	bool m_builtinAuthentication;
	/// Replica mode (APPMESH_AUTH_REPLICATION_FROM set): the store serves the
	/// owner's replicated policy. It is cached under work/auth/replication/, the
	/// node-local authorization.yaml stays untouched, and local policy edits are
	/// rejected so the owner stays the single writer.
	bool m_replicaMode = false;
	std::string m_replicaCacheFile;
};
