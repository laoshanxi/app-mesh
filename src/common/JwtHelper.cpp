#include "JwtHelper.h"

#include <cerrno>
#include <cstdlib>

#include "Utility.h"

namespace JwtHelper
{
std::string normalizeBearerToken(const std::string &token)
{
	auto normalized = Utility::stdStringTrim(token);
	normalized = Utility::stdStringTrim(normalized, HTTP_HEADER_JWT_BearerSpace, true, false);
	return Utility::stdStringTrim(normalized);
}

std::string buildBearerAuthorization(const std::string &token)
{
	const auto normalized = normalizeBearerToken(token);
	if (normalized.empty())
		return std::string();

	return std::string(HTTP_HEADER_JWT_BearerSpace) + normalized;
}

DecodedJwt decode(const std::string &token)
{
	return jwt::decode(normalizeBearerToken(token));
}

bool tryGetSubject(const std::string &token, std::string &subject)
{
	const auto decodedToken = decode(token);
	if (!decodedToken.has_subject())
		return false;

	subject = decodedToken.get_subject();
	return true;
}

static bool parseExpireSeconds(const nlohmann::json &expireValue, long long &expireSeconds)
{
	if (expireValue.is_number_integer() || expireValue.is_number_unsigned())
	{
		expireSeconds = expireValue.get<long long>();
		return true;
	}

	if (expireValue.is_number_float())
	{
		expireSeconds = static_cast<long long>(expireValue.get<double>());
		return true;
	}

	if (expireValue.is_string())
	{
		const auto expireStr = Utility::stdStringTrim(expireValue.get<std::string>());
		if (expireStr.empty())
			return true;

		char *end = nullptr;
		errno = 0;
		const auto parsed = std::strtoll(expireStr.c_str(), &end, 10);
		if (errno != 0 || end == expireStr.c_str() || *end != '\0')
			return false;

		expireSeconds = parsed;
		return true;
	}

	return false;
}

bool extractTokenResponse(const nlohmann::json &jsonResponse, TokenResponse &tokenResponse)
{
	const auto tokenIt = jsonResponse.find(HTTP_HEADER_JWT_access_token);
	if (tokenIt == jsonResponse.end() || !tokenIt->is_string())
		return false;

	tokenResponse.accessToken = normalizeBearerToken(tokenIt->get<std::string>());
	if (tokenResponse.accessToken.empty())
		return false;

	tokenResponse.expiresIn = 0;
	const auto expireIt = jsonResponse.find(HTTP_BODY_KEY_JWT_expires_in);
	if (expireIt == jsonResponse.end())
		return true;

	return parseExpireSeconds(*expireIt, tokenResponse.expiresIn);
}

bool extractTokenResponse(const std::string &jsonText, TokenResponse &tokenResponse)
{
	try
	{
		return extractTokenResponse(nlohmann::json::parse(jsonText), tokenResponse);
	}
	catch (const std::exception &)
	{
		return false;
	}
}

bool extractTokenResponse(const std::vector<std::uint8_t> &jsonBytes, TokenResponse &tokenResponse)
{
	try
	{
		return extractTokenResponse(nlohmann::json::parse(jsonBytes), tokenResponse);
	}
	catch (const std::exception &)
	{
		return false;
	}
}

} // namespace JwtHelper
