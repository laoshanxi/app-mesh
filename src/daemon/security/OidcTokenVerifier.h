#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <string>

#include "../../common/RestClient.h"
#include "Principal.h"

/// Generic OIDC Resource Server verifier. It trusts one issuer (Dex), discovers its JWKS,
/// and never calls an upstream connector, user-info endpoint, or administration API.
class OidcTokenVerifier
{
public:
	struct Config
	{
		std::string issuer;
		std::string dexAccessUrl;
		/// Browser entry that fronts the issuer path (agent or web proxy), advertised
		/// in the public auth config so WSS/TCP clients can hand browser flows an
		/// address they can actually reach. The web UI registers <origin>/oauth/callback
		/// on it as its single redirect URI. Empty: this daemon's own HTTPS REST
		/// listener is advertised.
		std::string browserEntry;
		bool dexTlsVerify{true};
		std::string dexCaPath;
		std::string resourceUrl;
		std::string resourceAudience;
		std::string publicClientId;
		std::set<std::string> scopes;
		std::set<std::string> allowedAlgorithms;
	};

	OidcTokenVerifier();
	void init();
	void prewarm();
	Principal verify(const std::string &token);

	const Config &config() const;
	nlohmann::json publicConfig() const;
	nlohmann::json protectedResourceMetadata() const;

private:
	struct CachedKey
	{
		std::string pem;
		std::chrono::steady_clock::time_point fetchedAt;
	};

	void loadConfig();
	void refreshDiscoveryLocked();
	void refreshKeysLocked();
	std::string resolveKey(const std::string &kid);
	std::string requestJson(const std::string &absoluteUrl) const;
	std::string transportUrl(const std::string &publishedUrl) const;
	static std::string normalizeIssuer(std::string issuer);
	static std::string jwkToPem(const nlohmann::json &jwk);

	Config m_config;
	std::string m_jwksUri;
	std::map<std::string, CachedKey> m_keys;
	std::map<std::string, std::chrono::steady_clock::time_point> m_negativeKeys;
	std::chrono::steady_clock::time_point m_discoveryFetchedAt;
	std::chrono::steady_clock::time_point m_keysFetchedAt;
	std::chrono::steady_clock::time_point m_keyRefreshAttemptedAt;
	mutable std::recursive_mutex m_mutex;
	ClientSSLConfig m_dexSslConfig;
};
