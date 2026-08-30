#pragma once

#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <set>
#include <stdexcept>
#include <string>

#include "AuthorizationStore.h"
#include "Principal.h"

class AuthenticationUnavailableException : public std::runtime_error
{
public:
	explicit AuthenticationUnavailableException(const std::string &message) : std::runtime_error(message) {}
};

class AuthorizationException : public std::runtime_error
{
public:
	explicit AuthorizationException(const std::string &message) : std::runtime_error(message) {}
};

/// Runtime authentication facade. Dex establishes identity; AuthorizationStore establishes
/// local permissions. Passwords, MFA, token issuance, and upstream IdP APIs are intentionally
/// absent from this contract.
class Security
{
public:
	virtual ~Security() = default;
	virtual void initialize() = 0;
	virtual void prewarmAuthentication() = 0;
	virtual Principal authenticate(const std::string &token) = 0;
	virtual std::shared_ptr<AuthorizationPrincipal> enrollFirstAdmin(
		const std::string &bearerToken) = 0;
	/// Enroll the principal pinned by the transport (verified at the WebSocket
	/// upgrade, when the bearer was presented and the store record resolved).
	/// Frames on that transport never re-present the Authorization header.
	virtual std::shared_ptr<AuthorizationPrincipal> enrollFirstAdminPinned(
		const std::string &principalId) = 0;
	virtual std::shared_ptr<AuthorizationPrincipal> principal(const std::string &principalId) const = 0;
	virtual std::set<std::string> permissions(const std::string &principalId) const = 0;
	virtual std::set<std::string> allPermissions() const = 0;

	virtual nlohmann::json authConfig() const = 0;
	virtual nlohmann::json protectedResourceMetadata() const = 0;
	virtual nlohmann::json principalsJson() const = 0;
	virtual nlohmann::json rolesJson() const = 0;
	virtual void updatePrincipal(const std::string &principalId, const nlohmann::json &definition) = 0;
	virtual void deletePrincipal(const std::string &principalId) = 0;
	virtual void updateRole(const std::string &role, const nlohmann::json &permissions) = 0;
	virtual void deleteRole(const std::string &role) = 0;

	static void init();
	static std::shared_ptr<Security> instance();
	/// Parse an HTTP Authorization value, authenticate its Bearer token, and
	/// return the verified OIDC principal. This is the shared boundary used by
	/// REST and WebSocket transports.
	static Principal authenticateBearerAuthorization(const std::string &authorization);
	/// Re-check the current local policy for an already authenticated principal.
	static void requirePermission(const std::string &principalId, const std::string &permission);

	Security() = default;

private:
	Security(const Security &) = delete;
	Security &operator=(const Security &) = delete;
	Security(Security &&) = delete;
	Security &operator=(Security &&) = delete;

	static std::shared_ptr<Security> m_instance;
	static std::recursive_mutex m_mutex;
};
