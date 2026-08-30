#include "JwtHelper.h"

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

} // namespace JwtHelper
