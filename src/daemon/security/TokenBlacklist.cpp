// src/daemon/security/TokenBlacklist.cpp
#include <algorithm>
#include <chrono>
#include <mutex>
#include <unordered_set>
#include <vector>

#include "../../common/JwtHelper.h"
#include "../../common/Utility.h"
#include "TokenBlacklist.h"

constexpr int MAX_BLACK_LIST_SIZE = 10240;

std::string TokenBlacklist::keyOf(const std::string &token)
{
    // Key on the token's jti, not the token itself: ~16 bytes instead of ~800, so the same
    // cap holds far more revocations before the eviction below starts silently un-revoking
    // them — and the persisted snapshot stops being a file full of live bearer credentials.
    try
    {
        const auto decoded = JwtHelper::decode(token);
        if (decoded.has_id())
        {
            const auto jti = decoded.get_id();
            if (!jti.empty())
            {
                return jti;
            }
        }
    }
    catch (const std::exception &)
    {
        // Undecodable: fall through to the hash, which is still not the credential.
    }
    return Utility::hash(token);
}

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
        // Evict tokens closest to expiry (least remaining lifetime first). This silently
        // un-revokes them, so it is logged loudly rather than at debug.
        LOG_WAR << fname << "revocation list full (" << m_tokenSet.size() << "); evicting " << (m_maxSize / 2)
                << " soonest-expiring entries, which un-revokes them";
        clearSoonestExpiring(m_maxSize / 2);
    }
    m_tokenSet[keyOf(token)] = expiryTime;
    LOG_DBG << fname << "token blacklist size: " << m_tokenSet.size();
}

bool TokenBlacklist::revokeOnce(const std::string &token, const std::chrono::system_clock::time_point &expiryTime)
{
    const static char fname[] = "TokenBlacklist::revokeOnce() ";

    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    if (m_tokenSet.count(keyOf(token)))
    {
        LOG_WAR << fname << "token already revoked";
        return false;
    }
    addToken(token, expiryTime); // recursive mutex: safe to nest
    return true;
}

bool TokenBlacklist::tryRemoveFromList(const std::string &token)
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    auto find = m_tokenSet.find(keyOf(token));
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
    return m_tokenSet.count(keyOf(token)) > 0;
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
    m_tokenSet.clear();
    size_t migrated = 0;
    for (const auto &entry : tokens)
    {
        // Snapshots written before this list was keyed on jti hold whole JWTs. Re-key them
        // on load, otherwise every revocation recorded before the upgrade would silently
        // stop matching and those tokens would become usable again.
        if (entry.first.find('.') != std::string::npos)
        {
            m_tokenSet[keyOf(entry.first)] = entry.second;
            ++migrated;
        }
        else
        {
            m_tokenSet[entry.first] = entry.second;
        }
    }
    if (migrated > 0)
    {
        LOG_INF << fname << "re-keyed " << migrated << " revocation(s) from a pre-upgrade snapshot";
    }
    LOG_INF << fname << "token blacklist size: " << m_tokenSet.size();
}

std::unordered_map<std::string, std::chrono::system_clock::time_point> TokenBlacklist::getTokens() const
{
    std::lock_guard<std::recursive_mutex> guard(m_mutex);
    return m_tokenSet;
}