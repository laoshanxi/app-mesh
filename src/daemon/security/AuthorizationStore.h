#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include <nlohmann/json.hpp>

#include "Principal.h"

class AuthorizationPrincipal
{
public:
	AuthorizationPrincipal(std::string principalId, Principal::Kind kind,
		std::string issuer, std::string subject);

	const std::string &id() const;
	const std::string &issuer() const;
	const std::string &subject() const;
	Principal::Kind kind() const;
	const std::string &status() const;
	const std::string &executionUser() const;
	const std::set<std::string> &roles() const;
	bool active() const;

	void updateClaims(const Principal &principal);
	void updatePolicy(const nlohmann::json &json);
	nlohmann::json asJson() const;
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
	std::shared_ptr<AuthorizationPrincipal> enrollFirstAdmin(const Principal &principal,
		const std::string &enrollmentToken);
	std::shared_ptr<AuthorizationPrincipal> get(const std::string &principalId) const;
	std::set<std::string> permissions(const std::string &principalId) const;
	std::set<std::string> allPermissions() const;

	nlohmann::json principalsJson() const;
	nlohmann::json rolesJson() const;
	void updatePrincipal(const std::string &principalId, const nlohmann::json &definition);
	void deletePrincipal(const std::string &principalId);
	void updateRole(const std::string &role, const nlohmann::json &permissions);
	void deleteRole(const std::string &role);
	void save() const;

	static const std::string &systemPrincipalId();

private:
	void load(const nlohmann::json &root);
	void initializeFirstAdminEnrollment();
	bool hasFirstAdminLocked() const;
	void closeFirstAdminEnrollmentLocked();
	void validateRoles(const std::set<std::string> &roles) const;
	void saveLocked() const;
	static Principal::Kind parseKind(const std::string &kind);

	mutable std::recursive_mutex m_mutex;
	std::map<std::string, std::shared_ptr<AuthorizationPrincipal>> m_principals;
	std::map<std::string, std::set<std::string>> m_roles;
	std::string m_provisioningMode;
	std::string m_firstAdminRole;
	bool m_firstAdminEnrolled;
	bool m_firstAdminEnrollmentEnabled;
	std::string m_firstAdminEnrollmentToken;
	std::string m_firstAdminEnrollmentTokenPath;
};
