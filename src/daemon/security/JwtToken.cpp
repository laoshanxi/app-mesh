// src/daemon/security/JwtToken.cpp
#include "JwtToken.h"

#include "../../common/JwtHelper.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Security.h"
#include "SecurityKeycloak.h"
#include "TokenBlacklist.h"

namespace JwtToken
{

	std::string generate(const std::string &userName, const std::string &userGroup, const std::string &audience, int timeoutSeconds)
	{
		if (userName.empty())
		{
			throw std::invalid_argument("must provide name to generate token");
		}

		// Validate audience
		std::string targetAudience = audience.empty() ? HTTP_HEADER_JWT_Audience_appmesh : audience;
		if (Configuration::instance()->getJwt()->m_jwtAudience.count(targetAudience) == 0)
		{
			throw std::invalid_argument(Utility::stringFormat("Audience <%s> verification failed", targetAudience.c_str()));
		}

		// Get user permissions and prepare resource access claim
		auto userRoles = Security::instance()->getUserInfo(userName);
		nlohmann::json resourceAccess;
		for (const auto &role : userRoles->getRoles())
		{
			resourceAccess[HTTP_HEADER_JWT_Audience_appmesh][JSON_KEY_USER_roles].push_back(role->getName());
		}

		// Load signing keys (done once due to static variables)
		const static std::string rsPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_RS256_PUBLIC_KEY_FILE).string());
		const static std::string rsPri = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_RS256_PRIVATE_KEY_FILE).string());
		const static std::string ecPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_ES256_PUBLIC_KEY_FILE).string());
		const static std::string ecPri = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_ES256_PRIVATE_KEY_FILE).string());

		// Create token with standard claims
		const auto now = std::chrono::system_clock::now();
		const auto jwt = jwt::create()
							 .set_issuer(Configuration::instance()->getRestJwtIssuer())
							 .set_subject(userName)
							 .set_audience(std::move(targetAudience))
							 .set_issued_at(jwt::date(now))
							 .set_expires_at(jwt::date(now + std::chrono::seconds{timeoutSeconds}))
							 .set_id(Utility::shortID())
							 .set_payload_claim("resource_access", jwt::claim(resourceAccess));

		// Sign token with configured algorithm
		std::string token;
		const auto &algo = Configuration::instance()->getJwt()->m_jwtAlgorithm;
		if (algo == APPMESH_JWT_ALGORITHM_HS256)
		{
			token = jwt.sign(jwt::algorithm::hs256{Configuration::instance()->getJwt()->m_jwtSalt});
		}
		else if (algo == APPMESH_JWT_ALGORITHM_RS256)
		{
			token = jwt.sign(jwt::algorithm::rs256{rsPub, rsPri});
		}
		else if (algo == APPMESH_JWT_ALGORITHM_ES256)
		{
			token = jwt.sign(jwt::algorithm::es256{ecPub, ecPri});
		}
		else
		{
			throw std::invalid_argument("JWT algorithm not supported");
		}

		// Ensure token is not blacklisted from a previous session
		TOKEN_BLACK_LIST::instance()->tryRemoveFromList(token);

		return token;
	}

	std::tuple<std::string, std::string, std::set<std::string>> verify(const std::string &token, const std::string &audience)
	{
		const static char fname[] = "JwtToken::verify() ";
		LOG_DBG << fname << "Verifying token for audience: " << audience;

		// Check blacklist before any crypto work
		if (TOKEN_BLACK_LIST::instance()->isTokenBlacklisted(token))
		{
			LOG_WAR << fname << "Token is blacklisted";
			throw std::domain_error("Token has been revoked");
		}

		const auto decodedToken = JwtHelper::decode(token);

		// Delegate to Keycloak if configured
		if (auto keycloak = dynamic_pointer_cast_if<SecurityKeycloak>(Security::instance()))
		{
			return keycloak->verifyKeycloakToken(decodedToken);
		}

		// Verify subject claim exists
		if (!decodedToken.has_subject())
		{
			LOG_WAR << fname << "Token missing subject claim";
			throw std::domain_error("No user info in token");
		}

		const auto userName = decodedToken.get_subject();
		LOG_DBG << fname << "Verifying token for user: " << userName;

		// Check user exists and is not locked
		const auto userObj = Security::instance()->getUserInfo(userName);
		if (userObj->locked())
		{
			LOG_WAR << fname << "User account is locked: " << userName;
			throw std::domain_error(Utility::stringFormat("User <%s> was locked", userName.c_str()));
		}

		// Load public keys for verification (done once due to static variables)
		const static std::string rsPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_RS256_PUBLIC_KEY_FILE).string());
		const static std::string ecPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_ES256_PUBLIC_KEY_FILE).string());

		// Verify signature and claims
		try
		{
			auto verifier = jwt::verify()
								.with_issuer(Configuration::instance()->getRestJwtIssuer())
								.with_audience(audience)
								.with_subject(userName);

			const auto &algo = Configuration::instance()->getJwt()->m_jwtAlgorithm;
			if (algo == APPMESH_JWT_ALGORITHM_HS256)
			{
				verifier.allow_algorithm(jwt::algorithm::hs256{Configuration::instance()->getJwt()->m_jwtSalt});
			}
			else if (algo == APPMESH_JWT_ALGORITHM_RS256)
			{
				verifier.allow_algorithm(jwt::algorithm::rs256{rsPub});
			}
			else if (algo == APPMESH_JWT_ALGORITHM_ES256)
			{
				verifier.allow_algorithm(jwt::algorithm::es256{ecPub});
			}
			else
			{
				LOG_ERR << fname << "Unsupported JWT algorithm: " << algo;
				throw std::domain_error("JWT algorithm not supported");
			}

			verifier.verify(decodedToken);
			LOG_DBG << fname << "Token verified successfully";
		}
		catch (const std::exception &e)
		{
			LOG_WAR << fname << "User <" << userName << "> token verification failed: " << e.what();
			throw std::domain_error(Utility::stringFormat("Authentication failed: %s", e.what()));
		}

		std::set<std::string> roles;
		return std::make_tuple(userName, userObj->getGroup(), roles);
	}

} // namespace JwtToken
