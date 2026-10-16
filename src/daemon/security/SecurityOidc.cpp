#include "SecurityOidc.h"
#include "SecretProtector.h"

void SecurityOidc::initialize()
{
	// Provision and validate the node-local encryption key before loading any
	// authorization or recovering persisted applications; unsafe key material is fatal.
	SecretProtector::instance().initialize();
	m_authorization.init();
	m_verifier.init();
}

void SecurityOidc::prewarmAuthentication() { m_verifier.prewarm(); }

Principal SecurityOidc::authenticate(const std::string &token)
{
	auto verified = m_verifier.verify(token);
	m_authorization.resolve(verified);
	return verified;
}

std::shared_ptr<AuthorizationPrincipal> SecurityOidc::enrollFirstAdmin(const std::string &bearerToken)
{
	return m_authorization.enrollFirstAdmin(m_verifier.verify(bearerToken));
}

std::shared_ptr<AuthorizationPrincipal> SecurityOidc::enrollFirstAdminPinned(const std::string &principalId)
{
	// The WebSocket upgrade already verified the Dex bearer and resolved this
	// principal into the store, so the pinned record matches what the HTTP path re-verifies.
	return m_authorization.enrollFirstAdmin(m_authorization.get(principalId)->asPrincipal());
}

std::shared_ptr<AuthorizationPrincipal> SecurityOidc::principal(const std::string &principalId) const
{
	return m_authorization.get(principalId);
}

std::set<std::string> SecurityOidc::permissions(const std::string &principalId) const
{
	return m_authorization.permissions(principalId);
}

std::set<std::string> SecurityOidc::allPermissions() const { return m_authorization.allPermissions(); }

Json::Value SecurityOidc::authConfig() const
{
	auto config = m_verifier.publicConfig();
	if (m_authorization.builtinAuthentication() && m_verifier.config().passwordFlow)
		config["flows"].append("password");
	config["first_admin_enrollment"] = m_authorization.firstAdminEnrollment();
	return config;
}
Json::Value SecurityOidc::protectedResourceMetadata() const { return m_verifier.protectedResourceMetadata(); }
Json::Value SecurityOidc::principalsJson() const { return m_authorization.principalsJson(); }
Json::Value SecurityOidc::rolesJson() const { return m_authorization.rolesJson(); }

void SecurityOidc::updatePrincipal(const std::string &principalId, const Json::Value &definition)
{
	m_authorization.updatePrincipal(principalId, definition);
}

void SecurityOidc::deletePrincipal(const std::string &principalId) { m_authorization.deletePrincipal(principalId); }

void SecurityOidc::updateRole(const std::string &role, const Json::Value &permissions)
{
	m_authorization.updateRole(role, permissions);
}

void SecurityOidc::deleteRole(const std::string &role) { m_authorization.deleteRole(role); }
