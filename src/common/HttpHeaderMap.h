#pragma once

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>
#include <utility>

/**
 * @brief Case-insensitive map for HTTP headers.
 */
class HttpHeaderMap
{
public:
    using MapType = std::unordered_map<std::string, std::string>;
    using iterator = MapType::iterator;
    using const_iterator = MapType::const_iterator;

public:
    HttpHeaderMap() = default;

    // Generic constructor: accept std::map, std::unordered_map, etc.
    template <typename AssocContainer>
    HttpHeaderMap(const AssocContainer &other)
    {
        for (const auto &kv : other)
        {
            std::string k = normalize(kv.first);
            m_headers.emplace(std::move(k), kv.second);
        }
    }

    // -------- Access --------

    std::string &operator[](const std::string &key)
    {
        return m_headers[normalize(key)];
    }

    std::string &at(const std::string &key)
    {
        return m_headers.at(normalize(key));
    }

    const std::string &at(const std::string &key) const
    {
        return m_headers.at(normalize(key));
    }

    size_t erase(const std::string &key)
    {
        return m_headers.erase(normalize(key));
    }

    std::pair<iterator, bool> insert(std::pair<std::string, std::string> kv)
    {
        kv.first = normalize(std::move(kv.first));
        return m_headers.insert(std::move(kv));
    }

    // Perfect forwarding version of emplace for efficient construction.
    template <typename K, typename V>
    std::pair<iterator, bool> emplace(K &&key, V &&value)
    {
        return m_headers.emplace(std::forward<K>(key), std::forward<V>(value));
    }

    // -------- Lookup --------

    iterator find(const std::string &key)
    {
        return m_headers.find(normalize(key));
    }

    const_iterator find(const std::string &key) const
    {
        return m_headers.find(normalize(key));
    }

    bool contains(const std::string &key) const
    {
        return m_headers.find(normalize(key)) != m_headers.end();
    }

    size_t count(const std::string &key) const
    {
        return m_headers.count(normalize(key));
    }

    std::string get(const std::string &key, const std::string &defaultValue = "") const
    {
        auto it = m_headers.find(normalize(key));
        return it != m_headers.end() ? it->second : defaultValue;
    }

    // -------- Container API --------

    void clear() noexcept { m_headers.clear(); }
    bool empty() const noexcept { return m_headers.empty(); }
    size_t size() const noexcept { return m_headers.size(); }

    iterator begin() noexcept { return m_headers.begin(); }
    iterator end() noexcept { return m_headers.end(); }

    const_iterator begin() const noexcept { return m_headers.begin(); }
    const_iterator end() const noexcept { return m_headers.end(); }

    const_iterator cbegin() const noexcept { return m_headers.cbegin(); }
    const_iterator cend() const noexcept { return m_headers.cend(); }

private:
    static std::string normalize(std::string key)
    {
        for (char &c : key)
        {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return key;
    }

private:
    MapType m_headers;
};
