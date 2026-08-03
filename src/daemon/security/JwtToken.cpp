// src/daemon/security/JwtToken.cpp
#include <algorithm>

#include "JwtToken.h"

#include "../../common/JwtHelper.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Security.h"
#include "SecurityKeycloak.h"
#include "TokenBlacklist.h"

namespace JwtToken
{
	namespace
	{
		/// Sign a token without validating the audience against the configured list.
		/// Private on purpose: only generate() (which validates first) and generateRefresh()
		/// (whose audience is a compile-time constant) may reach it, so no request-supplied
		/// string can ever select an audience the operator did not configure.
		std::string signToken(const std::string &userName, const std::string &userGroup, std::string audience, int timeoutSeconds);

		/// Reject a token minted before the user's revocation point. Uses the iat claim the
		/// signer already sets, so nothing extra has to be carried in the token.
		/// @throws std::domain_error when the token predates the epoch.
		void checkTokenEpoch(const JwtHelper::DecodedJwt &decodedToken, const std::shared_ptr<User> &userObj, const char *fname)
		{
			const auto epoch = userObj->tokenEpoch();
			if (epoch.time_since_epoch().count() == 0)
			{
				return; // no revocation point for this user
			}
			// <=, not <: iat is whole seconds, so a token minted during the revocation's own
			// second is indistinguishable from one minted just before it. Fail closed —
			// signToken pushes a legitimate re-login past the epoch so it stays usable.
			if (!decodedToken.has_issued_at() || decodedToken.get_issued_at() <= epoch)
			{
				LOG_WAR << fname << "Token predates the revocation point for user <" << userObj->getName() << ">";
				throw std::domain_error("Token has been revoked");
			}
		}

		/// Verify a locally-signed token's signature and registered claims. Shared by
		/// verify() and verifyRefresh() so both enforce the same rules.
		/// @throws std::domain_error on any verification failure.
		void verifyLocalSignature(const JwtHelper::DecodedJwt &decodedToken,
								  const std::string &audience, const std::string &userName)
		{
			const static char fname[] = "JwtToken::verifyLocalSignature() ";

			// Load public keys for verification (done once due to static variables)
			const static std::string rsPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_RS256_PUBLIC_KEY_FILE).string());
			const static std::string ecPub = Utility::readFileCpp((fs::path(Utility::getHomeDir()) / APPMESH_JWT_ES256_PUBLIC_KEY_FILE).string());

			try
			{
				auto verifier = jwt::verify()
									.with_issuer(Configuration::instance()->getRestJwtIssuer())
									.with_audience(audience)
									.with_subject(userName)
									.leeway(JWT_CLOCK_LEEWAY_SECONDS); // tolerate clock skew on exp/nbf/iat

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
		}
	} // namespace

	std::string generate(const std::string &userName, const std::string &userGroup, const std::string &audience, int timeoutSeconds)
	{
		if (userName.empty())
		{
			throw std::invalid_argument("must provide name to generate token");
		}

		// Validate audience against the operator-configured list. This is an authorization
		// boundary, not a formality: the WebSocket file endpoints authorize on audience alone.
		std::string targetAudience = audience.empty() ? HTTP_HEADER_JWT_Audience_appmesh : audience;
		if (Configuration::instance()->getJwt()->m_jwtAudience.count(targetAudience) == 0)
		{
			throw std::invalid_argument(Utility::stringFormat("Audience <%s> verification failed", targetAudience.c_str()));
		}

		return signToken(userName, userGroup, std::move(targetAudience), timeoutSeconds);
	}

	namespace
	{
		std::string signToken(const std::string &userName, const std::string &userGroup, std::string targetAudience, int timeoutSeconds)
		{
		const static char fname[] = "JwtToken::signToken() ";

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

		// iat is whole seconds and the epoch check fails closed, so a token minted during the
		// revocation's own second would be rejected — stranding the caller that re-logs in
		// right after a password change. Push iat just past the epoch instead; the skew is
		// under a second and well inside JWT_CLOCK_LEEWAY_SECONDS. exp still runs from now,
		// so this never extends a token's life.
		auto issuedAt = std::chrono::time_point_cast<std::chrono::seconds>(now);
		const auto epoch = userRoles->tokenEpoch();
		if (epoch.time_since_epoch().count() > 0)
		{
			const auto epochSec = std::chrono::time_point_cast<std::chrono::seconds>(epoch);
			if (issuedAt <= epochSec)
			{
				// Capped at the verifier's own leeway: jwt-cpp rejects iat further ahead than
				// that, so an epoch stepped into the future (clock jump, hand-edited record)
				// would otherwise mint a token that is dead on arrival and reports itself as
				// "expired" rather than revoked. Capping keeps the failure diagnosable.
				const auto capped = issuedAt + std::chrono::seconds(JWT_CLOCK_LEEWAY_SECONDS);
				issuedAt = std::min(epochSec + std::chrono::seconds(1), capped);
				if (issuedAt == capped)
				{
					LOG_ERR << fname << "Revocation point for user <" << userName
							<< "> is more than " << JWT_CLOCK_LEEWAY_SECONDS
							<< "s ahead of this clock; issued token will not verify";
				}
			}
		}

		const auto jwt = jwt::create()
							 .set_issuer(Configuration::instance()->getRestJwtIssuer())
							 .set_subject(userName)
							 .set_audience(std::move(targetAudience))
							 .set_issued_at(jwt::date(issuedAt))
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
	} // namespace

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

		// A refresh token is only ever consumable by verifyRefresh(). Callers pick the
		// audience they verify against (apiUserAuth takes it from an X-Audience header), so
		// without this an attacker could present a refresh token as an access token simply
		// by naming its audience.
		if (audience == JWT_REFRESH_AUDIENCE)
		{
			LOG_WAR << fname << "Refresh token presented as an access token";
			throw std::domain_error("Refresh token is not valid for API access");
		}

		// Delegate to Keycloak if configured — except the internal file-service token, which
		// generate() always mints locally (even in OAuth2 mode); Keycloak cannot carry its
		// audience, so verify it locally to keep WebSocket file transfer working under OAuth2.
		if (audience != WEBSOCKET_FILE_AUDIENCE)
		{
			if (auto keycloak = dynamic_pointer_cast_if<SecurityKeycloak>(Security::instance()))
			{
				return keycloak->verifyKeycloakToken(decodedToken, audience);
			}
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

		checkTokenEpoch(decodedToken, userObj, fname);
		verifyLocalSignature(decodedToken, audience, userName);

		std::set<std::string> roles;
		return std::make_tuple(userName, userObj->getGroup(), roles);
	}

	std::string generateRefresh(const std::string &userName, const std::string &userGroup, int timeoutSeconds)
	{
		if (userName.empty())
		{
			throw std::invalid_argument("must provide name to generate token");
		}
		// Signed like an access token but under the refresh audience, which verify() refuses
		// and verifyRefresh() requires — so neither token can be presented as the other.
		// Signs directly: the refresh audience is internal and deliberately not in the
		// operator's configured list.
		return signToken(userName, userGroup, JWT_REFRESH_AUDIENCE, timeoutSeconds);
	}

	std::tuple<std::string, std::string> verifyRefresh(const std::string &token)
	{
		const static char fname[] = "JwtToken::verifyRefresh() ";

		// Rotation blacklists a used refresh token, so seeing one again is a replay.
		// Reject before any crypto work.
		if (TOKEN_BLACK_LIST::instance()->isTokenBlacklisted(token))
		{
			LOG_WAR << fname << "Refresh token has been used or revoked";
			throw std::domain_error("Refresh token has been revoked");
		}

		const auto decodedToken = JwtHelper::decode(token);

		if (!decodedToken.has_subject())
		{
			LOG_WAR << fname << "Refresh token missing subject claim";
			throw std::domain_error("No user info in refresh token");
		}

		const auto userName = decodedToken.get_subject();

		// Locking an account must also stop it minting new access tokens.
		const auto userObj = Security::instance()->getUserInfo(userName);
		if (userObj->locked())
		{
			LOG_WAR << fname << "User account is locked: " << userName;
			throw std::domain_error(Utility::stringFormat("User <%s> was locked", userName.c_str()));
		}

		checkTokenEpoch(decodedToken, userObj, fname);
		verifyLocalSignature(decodedToken, JWT_REFRESH_AUDIENCE, userName);

		LOG_DBG << fname << "Refresh token verified for user <" << userName << ">";
		return std::make_tuple(userName, userObj->getGroup());
	}

} // namespace JwtToken
