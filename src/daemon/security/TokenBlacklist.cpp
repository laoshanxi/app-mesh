// src/daemon/security/TokenBlacklist.cpp
#include <chrono>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "../../common/Utility.h"
#include "TokenBlacklist.h"

constexpr int MAX_BLACK_LIST_SIZE = 10240;

TokenBlacklist::TokenBlacklist()
    : m_maxSize(MAX_BLACK_LIST_SIZE)
{
}

TokenBlacklist::~TokenBlacklist()
{
}

void TokenBlacklist::addToken(const std::string &token, const std::chrono::system_clock::time_point &expiryTime)
{
    const static char fname[] = "TokenBlacklist::addToken() ";

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    // TODO: clean periodic
    removeExpiredTokens();
    if (m_tokenSet.size() >= m_maxSize)
    {
        // Clear half of the tokens when the maximum size is reached
        clearTokens(m_maxSize / 2);
    }
    // m_tokenSet.emplace(token, expiryTime);
    m_tokenSet[token] = expiryTime;
    LOG_DBG << fname << "token black list size: " << m_tokenSet.size();
}

bool TokenBlacklist::tryRemoveFromList(const std::string &token)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    auto find = m_tokenSet.find(token);
    if (find != m_tokenSet.end())
    {
        m_tokenSet.erase(find);
        return true;
    }
    return false;
}

void TokenBlacklist::removeExpiredTokens()
{
    std::chrono::system_clock::time_point currentTime = std::chrono::system_clock::now();
    std::unordered_set<std::string> expiredTokens;

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    // Select expired tokens
    for (const auto &token : m_tokenSet)
    {
        if (currentTime >= token.second)
            expiredTokens.emplace(token.first);
    }

    // Remove expired tokens from the pool
    for (const std::string &token : expiredTokens)
        m_tokenSet.erase(token);
}

bool TokenBlacklist::isTokenBlacklisted(const std::string &token)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    return m_tokenSet.count(token) > 0;
}

void TokenBlacklist::clearTokens(size_t numTokens)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);

    auto it = m_tokenSet.begin();
    auto maxNum = m_tokenSet.size();
    for (size_t i = 0; i < numTokens && i < maxNum; ++i)
        it++;

    // Erase the desired elements from the map
    m_tokenSet.erase(m_tokenSet.begin(), it);
}

void TokenBlacklist::init(std::unordered_map<std::string, std::chrono::system_clock::time_point> &tokens) noexcept(false)
{
    const static char fname[] = "TokenBlacklist::init() ";

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    m_tokenSet = tokens;
    LOG_INF << fname << "token black list size: " << m_tokenSet.size();
}

std::unordered_map<std::string, std::chrono::system_clock::time_point> TokenBlacklist::getTokens() const
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    return m_tokenSet;
}