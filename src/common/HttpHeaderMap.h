// src/common/HttpHeaderMap.h
#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#if __cplusplus >= 201703L
#include <string_view>
#endif

#include <msgpack.hpp>

// -------- Internal Helpers --------

// Fast, locale-independent ASCII tolower.
// HTTP headers are strictly ASCII (RFC 7230).
inline char ascii_tolower(char c)
{
    unsigned char uc = static_cast<unsigned char>(c);
    if (uc >= 'A' && uc <= 'Z')
    {
        return static_cast<char>(uc + ('a' - 'A'));
    }
    return c;
}

// -------- C++17 Helpers (Transparent Hashing) --------
#if __cplusplus >= 201703L

struct CiHash
{
    using is_transparent = void; // Enables heterogeneous lookup (std::string_view)

    std::size_t operator()(std::string_view sv) const
    {
        // FNV-1a Hash (64-bit) implementation for better distribution
        constexpr uint64_t FNV_prime = 1099511628211ULL;
        constexpr uint64_t FNV_offset_basis = 14695981039346656037ULL;

        uint64_t hash = FNV_offset_basis;
        for (char c : sv)
        {
            // Cast to unsigned char to prevent sign-extension issues on non-ASCII bytes
            hash ^= static_cast<unsigned char>(ascii_tolower(c));
            hash *= FNV_prime;
        }
        return static_cast<std::size_t>(hash);
    }
};

struct CiEqual
{
    using is_transparent = void; // Enables heterogeneous lookup

    bool operator()(std::string_view l, std::string_view r) const
    {
        if (l.size() != r.size())
            return false;
        return std::equal(l.begin(), l.end(), r.begin(), [](char a, char b)
                          { return ascii_tolower(static_cast<unsigned char>(a)) ==
                                   ascii_tolower(static_cast<unsigned char>(b)); });
    }
};
#endif

/**
 * @brief Case-insensitive map for HTTP headers, supporting Msgpack serialization.
 * Keys are stored in lower-case.
 */
class HttpHeaderMap
{
public:
    // Define MapType based on C++ version
#if __cplusplus >= 201703L
    // C++17: Use custom hasher/equal for transparent lookups
    using MapType = std::unordered_map<std::string, std::string, CiHash, CiEqual>;
    using StringParam = std::string_view;
#else
    // C++11: Standard map, relies on normalizing keys before lookup
    using MapType = std::unordered_map<std::string, std::string>;
    using StringParam = const std::string &;
#endif

    using iterator = MapType::iterator;
    using const_iterator = MapType::const_iterator;
    using value_type = MapType::value_type;

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

    // Templated constructor for map-like containers
    template <typename AssocContainer, typename = typename std::enable_if<std::is_convertible<typename AssocContainer::value_type, std::pair<std::string, std::string>>::value>::type>
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

    // Move optimization for operator[]
    std::string &operator[](std::string &&key)
    {
        return m_headers[normalize(std::move(key))];
    }

    size_t erase(StringParam key)
    {
#if __cplusplus >= 201703L
        // C++17: Heterogeneous lookup avoids allocation
        auto it = m_headers.find(key);
        if (it != m_headers.end())
        {
            m_headers.erase(it);
            return 1;
        }
        return 0;
#else
        return m_headers.erase(normalize(key));
#endif
    }

    template <typename K, typename V>
    std::pair<iterator, bool> emplace(K &&key, V &&value)
    {
        // Forward key to normalize, creating a temporary string if needed, then move
        return m_headers.emplace(normalize(std::string(std::forward<K>(key))), std::forward<V>(value));
    }

    // -------- Lookup --------

    iterator find(StringParam key)
    {
#if __cplusplus >= 201703L
        return m_headers.find(key);
#else
        return m_headers.find(normalize(key));
#endif
    }

    const_iterator find(StringParam key) const
    {
#if __cplusplus >= 201703L
        return m_headers.find(key);
#else
        return m_headers.find(normalize(key));
#endif
    }

#if __cplusplus >= 201703L
    [[nodiscard]]
#endif
    bool contains(StringParam key) const noexcept
    {
#if __cplusplus >= 202002L
        return m_headers.contains(key);
#elif __cplusplus >= 201703L
        return m_headers.find(key) != m_headers.end();
#else
        return m_headers.count(normalize(key)) != 0;
#endif
    }

    size_t count(StringParam key) const
    {
#if __cplusplus >= 201703L
        return m_headers.count(key);
#else
        return m_headers.count(normalize(key));
#endif
    }

    // Returns by value to be safe, though slightly less efficient than returning const&
    // because defaultValue might be temporary.
    std::string get(StringParam key, const std::string &defaultValue = "") const
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
    // Normalize in place to avoid extra allocation when passing lvalues
    static std::string normalize(std::string key)
    {
        std::transform(key.begin(), key.end(), key.begin(), ascii_tolower);
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

        // Clear and optimize reservation
        m_headers.clear();
        m_headers.reserve(obj.via.map.size);

        // Iterate the raw msgpack kv pairs directly to avoid intermediate map allocation
        const auto *kv_ptr = obj.via.map.ptr;
        const auto *kv_end = kv_ptr + obj.via.map.size;

        for (; kv_ptr != kv_end; ++kv_ptr)
        {
            std::string key;
            kv_ptr->key.convert(key); // Extract key

            std::string val;
            kv_ptr->val.convert(val); // Extract value

            // Now we can truly move 'key' because it's a local non-const string
            m_headers.emplace(normalize(std::move(key)), std::move(val));
        }
    }
};
