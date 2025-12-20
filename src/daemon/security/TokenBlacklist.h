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

    void init(std::unordered_map<std::string, std::chrono::system_clock::time_point> &tokens) noexcept(false);
    std::unordered_map<std::string, std::chrono::system_clock::time_point> getTokens() const;

    bool tryRemoveFromList(const std::string &token);

protected:
    void removeExpiredTokens();
    void clearTokens(size_t numTokens);

    mutable std::recursive_mutex m_mutex;
    std::unordered_map<std::string, std::chrono::system_clock::time_point> m_tokenSet;
    size_t m_maxSize; // Maximum size of the token pool
};

typedef ACE_Singleton<TokenBlacklist, ACE_Null_Mutex> TOKEN_BLACK_LIST;