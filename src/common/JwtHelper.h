#pragma once

#include <optional>
#include <string>

#include <jwt-cpp/traits/nlohmann-json/defaults.h>
#include <nlohmann/json.hpp>

namespace JwtHelper
{
using DecodedJwt = jwt::decoded_jwt<jwt::traits::nlohmann_json>;

std::string normalizeBearerToken(const std::string &token);
std::string buildBearerAuthorization(const std::string &token);
DecodedJwt decode(const std::string &token);
std::optional<std::string> tryGetSubject(const std::string &token);
} // namespace JwtHelper
