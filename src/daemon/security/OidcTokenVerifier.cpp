#include "OidcTokenVerifier.h"

#include "../../common/JwtHelper.h"
#include "../../common/RestClient.h"
#include "../../common/UriParser.hpp"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Security.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <vector>

#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace
{
	const std::chrono::minutes DISCOVERY_TTL(15);
	const std::chrono::hours JWKS_TTL(1);
	const std::chrono::seconds NEGATIVE_KEY_TTL(30);
	const std::chrono::seconds KEY_REFRESH_MIN_INTERVAL(10);
	constexpr size_t MAX_NEGATIVE_KEYS = 256;
	constexpr size_t MAX_KEY_ID_LENGTH = 256;

	std::vector<unsigned char> decodeBase64Url(std::string value)
	{
		std::replace(value.begin(), value.end(), '-', '+');
		std::replace(value.begin(), value.end(), '_', '/');
		while (value.size() % 4 != 0)
			value.push_back('=');

		std::vector<unsigned char> decoded((value.size() / 4) * 3 + 1);
		const int length = EVP_DecodeBlock(decoded.data(),
			reinterpret_cast<const unsigned char *>(value.data()), static_cast<int>(value.size()));
		if (length < 0)
			throw std::domain_error("Invalid base64url value in JWKS");

		size_t padding = 0;
		if (!value.empty() && value[value.size() - 1] == '=')
			++padding;
		if (value.size() > 1 && value[value.size() - 2] == '=')
			++padding;
		decoded.resize(static_cast<size_t>(length) - padding);
		return decoded;
	}

	std::string bioToString(BIO *bio)
	{
		char *data = nullptr;
		const long size = BIO_get_mem_data(bio, &data);
		if (size <= 0 || data == nullptr)
			throw std::runtime_error("Failed to encode JWKS public key");
		return std::string(data, static_cast<size_t>(size));
	}

	std::string claimString(const JwtHelper::DecodedJwt &decoded, const char *name)
	{
		if (!decoded.has_payload_claim(name))
			return {};
		try
		{
			return decoded.get_payload_claim(name).as_string();
		}
		catch (const std::exception &)
		{
			return {};
		}
	}
}

OidcTokenVerifier::OidcTokenVerifier()
	: m_discoveryFetchedAt(), m_keysFetchedAt(), m_keyRefreshAttemptedAt()
{
}

void OidcTokenVerifier::init()
{
	const static char fname[] = "OidcTokenVerifier::init() ";
	loadConfig();
	LOG_INF << fname << "configured authentication issuer <" << m_config.issuer
			<< "> and resource audience <" << m_config.resourceAudience << ">";
}

void OidcTokenVerifier::prewarm()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	refreshKeysLocked();
}

void OidcTokenVerifier::loadConfig()
{
	const auto configFile = Utility::getConfigFilePath(APPMESH_OIDC_CONFIG_FILE);
	auto root = Utility::yamlToJson(YAML::LoadFile(configFile));
	Configuration::overrideConfigWithEnv(root);
	if (!root.contains("OIDC") || !root.at("OIDC").is_object())
		throw std::invalid_argument("oidc.yaml must contain an OIDC object");

	const auto &oidc = root.at("OIDC");
	m_config.issuer = normalizeIssuer(GET_JSON_STR_VALUE(oidc, "issuer"));
	const char *accessUrlKey = oidc.contains("access_url") ? "access_url" : "dex_access_url";
	const char *tlsVerifyKey = oidc.contains("tls_verify") ? "tls_verify" : "dex_tls_verify";
	const char *caPathKey = oidc.contains("ca_path") ? "ca_path" : "dex_ca_path";
	m_config.dexAccessUrl = normalizeIssuer(GET_JSON_STR_VALUE(oidc, accessUrlKey));
	if (oidc.contains(tlsVerifyKey))
	{
		if (!oidc.at(tlsVerifyKey).is_boolean())
			throw std::invalid_argument("OIDC tls_verify must be true or false");
		m_config.dexTlsVerify = oidc.at(tlsVerifyKey).get<bool>();
	}
	m_config.dexCaPath = Utility::stdStringTrim(GET_JSON_STR_VALUE(oidc, caPathKey));
	auto environment = [](const char *primary, const char *legacy) {
		const char *value = std::getenv(primary);
		return value != nullptr && value[0] != '\0' ? value : std::getenv(legacy);
	};
	const char *issuer = environment("APPMESH_AUTH_ISSUER", "APPMESH_DEX_ISSUER");
	if (issuer != nullptr && issuer[0] != '\0')
		m_config.issuer = normalizeIssuer(issuer);
	const char *accessUrl = environment("APPMESH_AUTH_ACCESS_URL", "APPMESH_DEX_ACCESS_URL");
	if (accessUrl != nullptr && accessUrl[0] != '\0')
		m_config.dexAccessUrl = normalizeIssuer(accessUrl);
	m_config.browserEntry = Utility::stdStringTrim(GET_JSON_STR_VALUE(oidc, "browser_entry"));
	const char *browserEntry = std::getenv("APPMESH_AUTH_BROWSER_ENTRY");
	if (browserEntry != nullptr && browserEntry[0] != '\0')
		m_config.browserEntry = normalizeIssuer(browserEntry);
	const char *caPath = environment("APPMESH_AUTH_CA_PATH", "APPMESH_DEX_CA_PATH");
	if (caPath != nullptr && caPath[0] != '\0')
		m_config.dexCaPath = caPath;
	const char *tlsVerify = environment("APPMESH_AUTH_TLS_VERIFY", "APPMESH_DEX_TLS_VERIFY");
	if (tlsVerify != nullptr && tlsVerify[0] != '\0')
	{
		std::string value(tlsVerify);
		std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
		if (value == "1" || value == "true")
			m_config.dexTlsVerify = true;
		else if (value == "0" || value == "false")
			m_config.dexTlsVerify = false;
		else
			throw std::invalid_argument("APPMESH_AUTH_TLS_VERIFY must be true or false");
	}
	m_config.resourceUrl = normalizeIssuer(GET_JSON_STR_VALUE(oidc, "resource_url"));
	m_config.resourceAudience = GET_JSON_STR_VALUE(oidc, "resource_audience");
	m_config.publicClientId = GET_JSON_STR_VALUE(oidc, "public_client_id");
	if (oidc.contains("service_client_ids"))
		throw std::invalid_argument(
			"OIDC service_client_ids is unsupported; every bearer must use resource_audience");

	if (oidc.contains("scopes"))
	{
		if (!oidc.at("scopes").is_array())
			throw std::invalid_argument("OIDC scopes must be an array");
		for (const auto &scope : oidc.at("scopes"))
		{
			if (!scope.is_string() || scope.get<std::string>().empty())
				throw std::invalid_argument("OIDC scopes entries must be non-empty strings");
			m_config.scopes.insert(scope.get<std::string>());
		}
	}
	if (oidc.contains("allowed_algorithms"))
	{
		if (!oidc.at("allowed_algorithms").is_array())
			throw std::invalid_argument("OIDC allowed_algorithms must be an array");
		for (const auto &algorithm : oidc.at("allowed_algorithms"))
		{
			if (!algorithm.is_string() || algorithm.get<std::string>().empty())
				throw std::invalid_argument("OIDC allowed_algorithms entries must be non-empty strings");
			m_config.allowedAlgorithms.insert(algorithm.get<std::string>());
		}
	}

	if (m_config.issuer.empty())
		throw std::invalid_argument("authentication issuer is not configured");
	if (m_config.resourceUrl.empty())
		throw std::invalid_argument("OIDC resource_url is not configured");
	if (m_config.resourceAudience.empty())
		throw std::invalid_argument("OIDC resource_audience is not configured");
	if (m_config.publicClientId.empty())
		throw std::invalid_argument("OIDC public_client_id is not configured");
	if (m_config.dexAccessUrl.empty())
		m_config.dexAccessUrl = m_config.issuer;
	for (const auto &endpoint : {m_config.issuer, m_config.dexAccessUrl, m_config.resourceUrl})
	{
		const auto uri = Uri::parse(endpoint);
		if ((uri.scheme != "http" && uri.scheme != "https") || uri.host.empty() ||
			!uri.user.empty() || !uri.pass.empty() || !uri.query.empty() || !uri.fragment.empty())
		{
			throw std::invalid_argument(
				"OIDC issuer, access_url, and resource_url must be absolute HTTP(S) URLs without credentials, query, or fragment");
		}
	}
	if (m_config.allowedAlgorithms.empty())
		m_config.allowedAlgorithms.insert("RS256");
	for (const auto &algorithm : m_config.allowedAlgorithms)
	{
		if (algorithm != "RS256" && algorithm != "RS384" && algorithm != "RS512" &&
			algorithm != "PS256" && algorithm != "PS384" && algorithm != "PS512")
			throw std::invalid_argument("OIDC allowed_algorithms contains an unsupported algorithm");
	}
	m_config.scopes.insert("audience:server:client_id:" + m_config.resourceAudience);
	m_dexSslConfig.m_verify_server = m_config.dexTlsVerify;
	m_dexSslConfig.m_ca_location = m_config.dexCaPath;
	if (!m_dexSslConfig.m_ca_location.empty() &&
		!Utility::isFileExist(m_dexSslConfig.m_ca_location) && !Utility::isDirExist(m_dexSslConfig.m_ca_location))
		throw std::invalid_argument("OIDC ca_path does not exist");
}

Principal OidcTokenVerifier::verify(const std::string &token)
{
	const auto decoded = [&token]()
	{
		try
		{
			return JwtHelper::decode(token);
		}
		catch (const std::exception &)
		{
			throw std::domain_error("bearer token is malformed");
		}
	}();
	if (!decoded.has_subject())
		throw std::domain_error("bearer token is missing subject");
	if (!decoded.has_payload_claim("iss"))
		throw std::domain_error("bearer token is missing issuer");
	if (!decoded.has_audience())
		throw std::domain_error("bearer token is missing audience");
	if (!decoded.has_expires_at())
		throw std::domain_error("bearer token is missing expiration");
	if (!decoded.has_header_claim("kid"))
		throw std::domain_error("bearer token is missing key identifier");

	std::string algorithm;
	std::string keyId;
	std::set<std::string> audiences;
	try
	{
		algorithm = decoded.get_algorithm();
		keyId = decoded.get_header_claim("kid").as_string();
		audiences = decoded.get_audience();
	}
	catch (const std::exception &)
	{
		throw std::domain_error("bearer token contains malformed claims");
	}
	if (m_config.allowedAlgorithms.count(algorithm) == 0)
		throw std::domain_error("bearer token uses an unsupported signing algorithm");

	const std::string key = resolveKey(keyId);
	try
	{
		auto verifier = jwt::verify()
			.with_issuer(m_config.issuer)
			.leeway(JWT_CLOCK_LEEWAY_SECONDS);
		if (algorithm == "RS256")
			verifier.allow_algorithm(jwt::algorithm::rs256{key});
		else if (algorithm == "RS384")
			verifier.allow_algorithm(jwt::algorithm::rs384{key});
		else if (algorithm == "RS512")
			verifier.allow_algorithm(jwt::algorithm::rs512{key});
		else if (algorithm == "PS256")
			verifier.allow_algorithm(jwt::algorithm::ps256{key});
		else if (algorithm == "PS384")
			verifier.allow_algorithm(jwt::algorithm::ps384{key});
		else if (algorithm == "PS512")
			verifier.allow_algorithm(jwt::algorithm::ps512{key});
		verifier.verify(decoded);
	}
	catch (const std::exception &e)
	{
		throw std::domain_error(Utility::stringFormat("bearer token validation failed: %s", e.what()));
	}

	if (audiences.count(m_config.resourceAudience) == 0)
	{
		throw std::domain_error("bearer token is not intended for the App Mesh API");
	}
	Principal principal(m_config.issuer, decoded.get_subject());
	std::string displayName = claimString(decoded, "name");
	if (displayName.empty())
		displayName = claimString(decoded, "preferred_username");
	principal.displayName(std::move(displayName));
	principal.email(claimString(decoded, "email"));
	principal.connectorId(claimString(decoded, "connector_id"));
	return principal;
}

const OidcTokenVerifier::Config &OidcTokenVerifier::config() const { return m_config; }

nlohmann::json OidcTokenVerifier::publicConfig() const
{
	nlohmann::json result;
	result["issuer"] = m_config.issuer;
	result["resource"] = m_config.resourceUrl;
	result["audience"] = m_config.resourceAudience;
	result["public_client_id"] = m_config.publicClientId;
	result["scopes"] = m_config.scopes;
	// An unconfigured entry defaults to this daemon's own HTTPS REST listener, so
	// bare deployments and dev servers need no manual redirect registration.
	result["browser_entry"] = !m_config.browserEntry.empty() ? m_config.browserEntry
		: "https://" + Configuration::instance()->getRestListenAddress() + ":" + std::to_string(Configuration::instance()->getRestListenPort());
	result["flows"] = nlohmann::json::array({"authorization_code_pkce", "device_code"});
	return result;
}

nlohmann::json OidcTokenVerifier::protectedResourceMetadata() const
{
	nlohmann::json result;
	result["resource"] = m_config.resourceUrl;
	result["authorization_servers"] = nlohmann::json::array({m_config.issuer});
	result["scopes_supported"] = m_config.scopes;
	result["bearer_methods_supported"] = nlohmann::json::array({"header"});
	return result;
}

void OidcTokenVerifier::refreshDiscoveryLocked()
{
	const std::string discoveryUrl = m_config.dexAccessUrl + "/.well-known/openid-configuration";
	auto metadata = nlohmann::json::parse(requestJson(discoveryUrl));
	if (!metadata.contains("issuer") || normalizeIssuer(metadata.at("issuer").get<std::string>()) != m_config.issuer)
		throw std::domain_error("OIDC discovery issuer does not match the configured issuer");
	if (!metadata.contains("jwks_uri") || !metadata.at("jwks_uri").is_string())
		throw std::runtime_error("OIDC discovery metadata does not publish jwks_uri");
	m_jwksUri = metadata.at("jwks_uri").get<std::string>();
	m_discoveryFetchedAt = std::chrono::steady_clock::now();
}

void OidcTokenVerifier::refreshKeysLocked()
{
	const static char fname[] = "OidcTokenVerifier::refreshKeysLocked() ";
	const auto now = std::chrono::steady_clock::now();
	if (m_jwksUri.empty() || now - m_discoveryFetchedAt >= DISCOVERY_TTL)
		refreshDiscoveryLocked();

	auto jwks = nlohmann::json::parse(requestJson(transportUrl(m_jwksUri)));
	if (!jwks.contains("keys") || !jwks.at("keys").is_array())
		throw std::runtime_error("OIDC JWKS response does not contain keys");

	std::map<std::string, CachedKey> refreshed;
	for (const auto &jwk : jwks.at("keys"))
	{
		if (!jwk.contains("kid") || !jwk.at("kid").is_string())
			continue;
		if (jwk.contains("use") && jwk.at("use").is_string() && jwk.at("use").get<std::string>() != "sig")
			continue;
		try
		{
			refreshed[jwk.at("kid").get<std::string>()] = CachedKey{jwkToPem(jwk), now};
		}
		catch (const std::exception &e)
		{
			LOG_WAR << fname << "skipped unusable JWKS key: " << e.what();
		}
	}
	if (refreshed.empty())
		throw std::runtime_error("OIDC JWKS response contains no supported signing keys");
	m_keys.swap(refreshed);
	m_negativeKeys.clear();
	m_keysFetchedAt = now;
}

std::string OidcTokenVerifier::resolveKey(const std::string &kid)
{
	const static char fname[] = "OidcTokenVerifier::resolveKey() ";
	if (kid.empty())
		throw std::domain_error("bearer token has an empty key identifier");
	if (kid.size() > MAX_KEY_ID_LENGTH)
		throw std::domain_error("bearer token key identifier is too long");

	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	const auto now = std::chrono::steady_clock::now();
	for (auto entry = m_negativeKeys.begin(); entry != m_negativeKeys.end();)
	{
		if (now - entry->second >= NEGATIVE_KEY_TTL)
			entry = m_negativeKeys.erase(entry);
		else
			++entry;
	}
	auto negative = m_negativeKeys.find(kid);
	if (negative != m_negativeKeys.end() && now - negative->second < NEGATIVE_KEY_TTL)
		throw std::domain_error("bearer token references an unknown signing key");

	auto existing = m_keys.find(kid);
	if (existing != m_keys.end() && now - m_keysFetchedAt < JWKS_TTL)
		return existing->second.pem;

	if (m_keyRefreshAttemptedAt.time_since_epoch().count() != 0 &&
		now - m_keyRefreshAttemptedAt < KEY_REFRESH_MIN_INTERVAL)
	{
		// A stale matching key remains cryptographically safe and is verified below.
		// Without any cached key, preserve the distinction between an unavailable
		// verifier and a token that is known to reference an absent key.
		if (existing != m_keys.end())
			return existing->second.pem;
		if (m_keys.empty())
			throw AuthenticationUnavailableException("signing-key refresh is temporarily rate-limited");
		throw std::domain_error("bearer token references an unknown signing key");
	}
	m_keyRefreshAttemptedAt = now;

	try
	{
		refreshKeysLocked();
	}
	catch (const std::domain_error &)
	{
		throw;
	}
	catch (const std::exception &e)
	{
		// Dex may be temporarily unavailable. A cached key remains safe until the bearer
		// token expires; never fall back to local signing or another issuer.
		if (existing != m_keys.end())
		{
			LOG_WAR << fname << "using a cached signing key after refresh failure: " << e.what();
			return existing->second.pem;
		}
		throw AuthenticationUnavailableException(
			Utility::stringFormat("authentication discovery or signing keys are unavailable: %s", e.what()));
	}

	existing = m_keys.find(kid);
	if (existing == m_keys.end())
	{
		// Also rate-limit the next distinct unknown kid after the initial JWKS load.
		// Do not negative-cache keys rejected only by the global interval: a newly
		// rotated legitimate key must be eligible for refresh as soon as it expires.
		if (m_negativeKeys.size() >= MAX_NEGATIVE_KEYS)
		{
			typedef std::map<std::string, std::chrono::steady_clock::time_point>::value_type NegativeKeyEntry;
			auto oldest = std::min_element(m_negativeKeys.begin(), m_negativeKeys.end(),
				[](const NegativeKeyEntry &left, const NegativeKeyEntry &right)
				{ return left.second < right.second; });
			if (oldest != m_negativeKeys.end())
				m_negativeKeys.erase(oldest);
		}
		m_negativeKeys[kid] = now;
		throw std::domain_error("bearer token references an unknown signing key");
	}
	return existing->second.pem;
}

std::string OidcTokenVerifier::requestJson(const std::string &absoluteUrl) const
{
	const Uri uri = Uri::parse(absoluteUrl);
	if ((uri.scheme != "http" && uri.scheme != "https") || uri.host.empty())
		throw std::invalid_argument("OIDC endpoint must be an absolute HTTP(S) URL");
	std::string host = uri.scheme + "://" + uri.host;
	if (uri.port >= 0)
		host += ":" + std::to_string(uri.port);
	const std::string path = uri.path.empty() ? "/" : uri.path;
	auto response = RestClient::request(host, web::http::methods::GET, path, "", {}, uri.queryParams(), {}, 5, &m_dexSslConfig);
	response->raise_for_status();
	return response->text;
}

std::string OidcTokenVerifier::transportUrl(const std::string &publishedUrl) const
{
	const Uri published = Uri::parse(publishedUrl);
	const Uri issuer = Uri::parse(m_config.issuer);
	const Uri transport = Uri::parse(m_config.dexAccessUrl);
	if (published.scheme != issuer.scheme || published.host != issuer.host || published.port != issuer.port)
		throw std::domain_error("OIDC metadata published an endpoint outside the configured issuer");
	const std::string issuerPath = normalizeIssuer(issuer.path.empty() ? "/" : issuer.path);
	if (issuerPath != "/" && published.path != issuerPath && !Utility::startWith(published.path, issuerPath + "/"))
		throw std::domain_error("OIDC metadata published an endpoint outside the configured issuer path");
	std::string suffix = published.path.substr(issuerPath == "/" ? 0 : issuerPath.size());
	if (!suffix.empty() && suffix.front() != '/')
		suffix.insert(suffix.begin(), '/');

	std::string base = transport.scheme + "://" + transport.host;
	if (transport.port >= 0)
		base += ":" + std::to_string(transport.port);
	std::string transportPath = normalizeIssuer(transport.path.empty() ? "/" : transport.path);
	if (transportPath == "/")
		transportPath.clear();
	std::string path = transportPath + suffix;
	// Uri::parse strips the leading '/' from absolute-URL paths, so the joined
	// host and path must be re-separated explicitly (requestJson re-parses this).
	if (path.empty() || path.front() != '/')
		path.insert(path.begin(), '/');
	return base + path + (published.query.empty() ? "" : "?" + published.query);
}

std::string OidcTokenVerifier::normalizeIssuer(std::string issuer)
{
	issuer = Utility::stdStringTrim(issuer);
	while (issuer.size() > 1 && issuer[issuer.size() - 1] == '/')
		issuer.erase(issuer.size() - 1);
	return issuer;
}

std::string OidcTokenVerifier::jwkToPem(const nlohmann::json &jwk)
{
	if (jwk.contains("x5c") && jwk.at("x5c").is_array() && !jwk.at("x5c").empty())
		return "-----BEGIN CERTIFICATE-----\n" + jwk.at("x5c").at(0).get<std::string>() + "\n-----END CERTIFICATE-----\n";

	if (!jwk.contains("kty") || jwk.at("kty") != "RSA" || !jwk.contains("n") || !jwk.contains("e"))
		throw std::invalid_argument("only RSA signing keys are supported in the configured signing-key set");
	const auto modulus = decodeBase64Url(jwk.at("n").get<std::string>());
	const auto exponent = decodeBase64Url(jwk.at("e").get<std::string>());

	BIGNUM *n = BN_bin2bn(modulus.data(), static_cast<int>(modulus.size()), nullptr);
	BIGNUM *e = BN_bin2bn(exponent.data(), static_cast<int>(exponent.size()), nullptr);
	RSA *rsa = RSA_new();
	if (!n || !e || !rsa)
	{
		BN_free(n);
		BN_free(e);
		RSA_free(rsa);
		throw std::runtime_error("Failed to construct RSA key from JWKS");
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000L
	rsa->n = n;
	rsa->e = e;
#else
	if (RSA_set0_key(rsa, n, e, nullptr) != 1)
	{
		BN_free(n);
		BN_free(e);
		RSA_free(rsa);
		throw std::runtime_error("Failed to attach RSA parameters from JWKS");
	}
#endif

	EVP_PKEY *pkey = EVP_PKEY_new();
	BIO *bio = BIO_new(BIO_s_mem());
	if (!pkey || !bio || EVP_PKEY_assign_RSA(pkey, rsa) != 1 || PEM_write_bio_PUBKEY(bio, pkey) != 1)
	{
		if (pkey)
			EVP_PKEY_free(pkey);
		else
			RSA_free(rsa);
		BIO_free(bio);
		throw std::runtime_error("Failed to encode RSA key from JWKS");
	}
	const std::string pem = bioToString(bio);
	BIO_free(bio);
	EVP_PKEY_free(pkey); // owns rsa after EVP_PKEY_assign_RSA
	return pem;
}
