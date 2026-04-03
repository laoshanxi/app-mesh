// src/daemon/security/TokenBlacklist.cpp
#include <algorithm>
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
    removeExpiredTokens();
    if (m_tokenSet.size() >= m_maxSize)
    {
        // Evict tokens closest to expiry (least remaining lifetime first)
        clearSoonestExpiring(m_maxSize / 2);
    }
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

void TokenBlacklist::clearSoonestExpiring(size_t numTokens)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);

    // Collect and sort by expiry time (soonest first) so we evict tokens
    // that are closest to natural expiration — preserving long-lived revocations
    std::vector<std::pair<std::chrono::system_clock::time_point, std::string>> sorted;
    sorted.reserve(m_tokenSet.size());
    for (const auto &entry : m_tokenSet)
        sorted.emplace_back(entry.second, entry.first);
    std::sort(sorted.begin(), sorted.end());

    const auto count = std::min(numTokens, sorted.size());
    for (size_t i = 0; i < count; ++i)
        m_tokenSet.erase(sorted[i].second);
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