#pragma once

#include "AuthorizationStore.h"
#include "OidcTokenVerifier.h"
#include "Security.h"

class SecurityOidc : public Security
{
public:
	void initialize() override;
	void prewarmAuthentication() override;
	Principal authenticate(const std::string &token) override;
	std::shared_ptr<AuthorizationPrincipal> enrollFirstAdmin(
		const std::string &bearerToken) override;
	std::shared_ptr<AuthorizationPrincipal> enrollFirstAdminPinned(
		const std::string &principalId) override;
	std::shared_ptr<AuthorizationPrincipal> principal(const std::string &principalId) const override;
	std::set<std::string> permissions(const std::string &principalId) const override;
	std::set<std::string> allPermissions() const override;

	nlohmann::json authConfig() const override;
	nlohmann::json protectedResourceMetadata() const override;
	nlohmann::json principalsJson() const override;
	nlohmann::json rolesJson() const override;
	void updatePrincipal(const std::string &principalId, const nlohmann::json &definition) override;
	void deletePrincipal(const std::string &principalId) override;
	void updateRole(const std::string &role, const nlohmann::json &permissions) override;
	void deleteRole(const std::string &role) override;

private:
	OidcTokenVerifier m_verifier;
	AuthorizationStore m_authorization;
};
