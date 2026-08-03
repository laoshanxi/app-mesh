// src/daemon/security/TokenBlacklist.h
#include <chrono>
#include <string>
#include <unordered_map>

#include <ace/Null_Mutex.h>
#include <ace/Singleton.h>
#include <nlohmann/json.hpp>

/// <summary>
/// TODO: persist support recover
/// </summary>
class TokenBlacklist
{
public:
    TokenBlacklist();
    virtual ~TokenBlacklist();

    void addToken(const std::string &token, const std::chrono::system_clock::time_point &expiryTime);
    bool isTokenBlacklisted(const std::string &token);

    /// Atomically revoke a token, returning false if it was already revoked. Callers that
    /// consume a single-use token (refresh-token rotation) must gate on this rather than on
    /// a separate isTokenBlacklisted() check: requests are served by a worker pool, so a
    /// check-then-insert lets two concurrent presentations of the same token both succeed.
    bool revokeOnce(const std::string &token, const std::chrono::system_clock::time_point &expiryTime);

    void init(std::unordered_map<std::string, std::chrono::system_clock::time_point> &tokens) noexcept(false);
    std::unordered_map<std::string, std::chrono::system_clock::time_point> getTokens() const;

    bool tryRemoveFromList(const std::string &token);

protected:
    /// Map key for a token: its jti when present, else a hash. Never the token itself.
    static std::string keyOf(const std::string &token);

    void removeExpiredTokens();
    void clearSoonestExpiring(size_t numTokens);

    mutable std::recursive_mutex m_mutex;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> m_tokenSet;
    size_t m_maxSize; // Maximum size of the token pool
};

typedef ACE_Singleton<TokenBlacklist, ACE_Null_Mutex> TOKEN_BLACK_LIST;