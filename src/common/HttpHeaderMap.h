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
            std::string k = kv.first;
            normalize(k);
            m_headers.emplace(std::move(k), kv.second);
        }
    }

    // -------- Access --------

    std::string &operator[](const std::string &key)
    {
        std::string k = key;
        normalize(k);
        return m_headers[k];
    }

    std::string &at(const std::string &key)
    {
        std::string k = key;
        normalize(k);
        return m_headers.at(k);
    }

    const std::string &at(const std::string &key) const
    {
        std::string k = key;
        normalize(k);
        return m_headers.at(k);
    }

    size_t erase(const std::string &key)
    {
        std::string k = key;
        normalize(k);
        return m_headers.erase(k);
    }

    std::pair<iterator, bool> insert(std::pair<std::string, std::string> kv)
    {
        normalize(kv.first);
        return m_headers.insert(std::move(kv));
    }

    // Perfect forwarding version of emplace for efficient construction.
    template <typename K, typename V>
    std::pair<iterator, bool> emplace(K&& key, V&& value)
    {
        return m_headers.emplace(std::forward<K>(key), std::forward<V>(value));
    }

    // -------- Lookup --------

    iterator find(const std::string &key)
    {
        std::string k = key;
        normalize(k);
        return m_headers.find(k);
    }

    const_iterator find(const std::string &key) const
    {
        std::string k = key;
        normalize(k);
        return m_headers.find(k);
    }

    bool contains(const std::string &key) const noexcept
    {
        std::string k = key;
        normalize(k);
        return m_headers.find(k) != m_headers.end();
    }

    size_t count(const std::string &key) const noexcept
    {
        std::string k = key;
        normalize(k);
        return m_headers.count(k);
    }

    std::string get(const std::string &key, const std::string &defaultValue = "") const
    {
        std::string k = key;
        normalize(k);

        auto it = m_headers.find(k);
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
    static void normalize(std::string &key)
    {
        for (char &c : key)
        {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }

private:
    MapType m_headers;
};
