#pragma once

#include <optional>
#include <string>

#include <jwt-cpp/traits/open-source-parsers-jsoncpp/defaults.h>

namespace JwtHelper
{
using JwtTrait = jwt::traits::open_source_parsers_jsoncpp;
using DecodedJwt = jwt::decoded_jwt<JwtTrait>;

std::string normalizeBearerToken(const std::string &token);
std::string buildBearerAuthorization(const std::string &token);
DecodedJwt decode(const std::string &token);
std::optional<std::string> tryGetSubject(const std::string &token);
} // namespace JwtHelper
