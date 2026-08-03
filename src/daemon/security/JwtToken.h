// src/daemon/security/JwtToken.h
#pragma once

#include <set>
#include <string>
#include <tuple>

#include "../../common/Utility.h"

/// Server-side JWT token generation and verification.
/// Centralizes all signing/verification logic, key loading, and algorithm selection.
namespace JwtToken
{
    /// Generate a signed JWT token for the given user.
    /// @throws std::invalid_argument on invalid input or unsupported algorithm.
    std::string generate(const std::string &userName, const std::string &userGroup, const std::string &audience, int timeoutSeconds);

    /// Verify a JWT token signature and claims.
    /// @return tuple of (username, group, roles).
    /// @throws std::domain_error on verification failure.
    std::tuple<std::string, std::string, std::set<std::string>> verify(const std::string &token, const std::string &audience = HTTP_HEADER_JWT_Audience_appmesh);

    /// Generate a local-mode refresh token, usable only on /appmesh/token/renew: it carries
    /// JWT_REFRESH_AUDIENCE, which the ordinary audience check rejects everywhere else.
    /// @throws std::invalid_argument on invalid input or unsupported algorithm.
    std::string generateRefresh(const std::string &userName, const std::string &userGroup, int timeoutSeconds);

    /// Verify a refresh token from generateRefresh. Independent of the access token, which
    /// may already have expired — renewing anyway is the point of a refresh token.
    /// @return tuple of (username, group).
    /// @throws std::domain_error on verification failure (including a revoked/replayed token).
    std::tuple<std::string, std::string> verifyRefresh(const std::string &token);

} // namespace JwtToken
