#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <nlohmann/json.hpp>

namespace JwtHelper
{
using DecodedJwt = jwt::decoded_jwt<jwt::traits::nlohmann_json>;

struct TokenResponse
{
	std::string accessToken;
	long long expiresIn{0};
};

std::string normalizeBearerToken(const std::string &token);
std::string buildBearerAuthorization(const std::string &token);
DecodedJwt decode(const std::string &token);
bool tryGetSubject(const std::string &token, std::string &subject);
bool extractTokenResponse(const nlohmann::json &jsonResponse, TokenResponse &tokenResponse);
bool extractTokenResponse(const std::string &jsonText, TokenResponse &tokenResponse);
bool extractTokenResponse(const std::vector<std::uint8_t> &jsonBytes, TokenResponse &tokenResponse);
} // namespace JwtHelper
