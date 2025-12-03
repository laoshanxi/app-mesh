#pragma once

#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>

#include <msgpack.hpp>

/**
 * @brief C++11 Case-insensitive map for HTTP headers, supporting Msgpack serialization.
 */
class HttpHeaderMap
{
public:
    using MapType = std::unordered_map<std::string, std::string>;
    using iterator = MapType::iterator;
    using const_iterator = MapType::const_iterator;

public:
    HttpHeaderMap() = default;

    HttpHeaderMap(std::initializer_list<std::pair<std::string, std::string>> init)
    {
        m_headers.reserve(init.size());
        for (const auto &kv : init)
        {
            m_headers.emplace(normalize(kv.first), kv.second);
        }
    }

    template <typename AssocContainer,
              typename Value = typename AssocContainer::value_type,
              typename = typename std::enable_if<std::is_convertible<Value, std::pair<std::string, std::string>>::value>::type>
    explicit HttpHeaderMap(const AssocContainer &other)
    {
        for (const auto &kv : other)
        {
            m_headers.emplace(normalize(kv.first), kv.second);
        }
    }

    // -------- Access --------

    std::string &operator[](const std::string &key)
    {
        return m_headers[normalize(key)];
    }

    size_t erase(const std::string &key)
    {
        return m_headers.erase(normalize(key));
    }

    template <typename K, typename V>
    std::pair<iterator, bool> emplace(K &&key, V &&value)
    {
        std::string k = normalize(std::string(std::forward<K>(key)));
        return m_headers.emplace(std::move(k), std::string(std::forward<V>(value)));
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

    bool contains(const std::string &key) const noexcept
    {
        return m_headers.count(normalize(key)) != 0;
    }

    size_t count(const std::string &key) const
    {
        return m_headers.count(normalize(key));
    }

    std::string get(const std::string &key, const std::string &defaultValue = "") const
    {
        auto it = find(key);
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
        std::transform(key.begin(), key.end(), key.begin(),
                       [](unsigned char c)
                       { return static_cast<char>(std::tolower(c)); });
        return key;
    }

private:
    MapType m_headers;

public:
    // -------- MsgPack Serialization --------

    template <typename Packer>
    void msgpack_pack(Packer &pk) const
    {
        pk.pack(m_headers);
    }

    void msgpack_unpack(const msgpack::object &obj)
    {
        if (obj.type != msgpack::type::MAP)
        {
            throw msgpack::type_error();
        }

        // Unpack into a temporary map and then normalize keys for internal storage.
        MapType temp_headers;
        obj.convert(temp_headers);

        m_headers.clear();
        m_headers.reserve(temp_headers.size());
        for (auto &kv : temp_headers)
        {
            m_headers.emplace(normalize(std::move(kv.first)), std::move(kv.second));
        }
    }
};
