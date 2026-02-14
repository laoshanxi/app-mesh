// src/common/UriParser.hpp
// C++11 lightweight wrapper around uriparser to provide simple Boost::url-like API.

#pragma once

#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <uriparser/Uri.h>

class Uri
{
public:
    std::string scheme, user, pass, host, path, query, fragment;
    int port = -1;

    static Uri parse(const std::string &uriStr)
    {
        Uri result;

        bool originalStartsWithSlash = (!uriStr.empty() && uriStr[0] == '/');

        // 1. Schemeless / protocol-relative detection
        size_t colonPos = uriStr.find(':');
        size_t slashPos = uriStr.find('/');
        bool isProtocolRelative = (uriStr.size() >= 2 && uriStr[0] == '/' && uriStr[1] == '/');

        // A scheme must:
        // - Have a colon before any slash
        // - The part before the colon must be alphabetic (schemes can't start with digits)
        // - Be followed by "//" for authority-based URIs, or at least not be purely numeric
        bool hasScheme = false;
        if (colonPos != std::string::npos && (slashPos == std::string::npos || colonPos < slashPos))
        {
            std::string potentialScheme = uriStr.substr(0, colonPos);
            // Valid schemes start with a letter and contain only [a-zA-Z0-9+.-]
            // If it looks like a host:port (e.g., starts with digit or is an IP), it's not a scheme
            if (!potentialScheme.empty() && std::isalpha(static_cast<unsigned char>(potentialScheme[0])))
            {
                // Check if what follows the colon is just digits (port) or looks like a path/authority
                std::string afterColon = uriStr.substr(colonPos + 1);
                // If after colon is purely numeric, this is likely host:port, not scheme:rest
                bool isPort = !afterColon.empty() && afterColon.find_first_not_of("0123456789") == std::string::npos;
                if (!isPort)
                {
                    hasScheme = true;
                }
            }
        }

        bool autoScheme = !hasScheme && !isProtocolRelative;

        // If autoScheme, prepend http:// so uriparser can parse the host
        std::string temp = autoScheme ? ("http://" + uriStr) : uriStr;

        // 2. Parse using RAII wrapper
        UriWrapper wrapper(temp);
        if (!wrapper.isValid())
            return result;

        const UriUriA *uri = wrapper.get();

        // 3. Extract fields
        // Only extract scheme if we didn't fake it
        if (!autoScheme)
            result.scheme = rangeToString(uri->scheme);

        result.host = rangeToString(uri->hostText);
        result.query = rangeToString(uri->query);
        result.fragment = rangeToString(uri->fragment);

        // UserInfo split (user:pass)
        std::string ui = rangeToString(uri->userInfo);
        size_t colon = ui.find(':');
        if (colon != std::string::npos)
        {
            result.user = ui.substr(0, colon);
            result.pass = ui.substr(colon + 1);
        }
        else
        {
            result.user = ui;
        }

        // Port
        std::string portStr = rangeToString(uri->portText);
        if (!portStr.empty())
            result.port = std::atoi(portStr.c_str());

        // 4. Path Construction (preserve leading slash when appropriate)
        // Decide whether the resulting path should start with '/'
        // - If the original input started with '/', preserve that.
        // - If we forced a scheme (autoScheme == true) but the parser actually produced a host,
        //   then this is an absolute URL (example.com/path) and we must include a leading '/' for the path
        //   so that toString() concatenation yields host + "/" + path (not host+path).
        bool addLeadingSlash = originalStartsWithSlash || (autoScheme && !result.host.empty());

        if (uri->pathHead)
        {
            const UriPathSegmentA *seg = uri->pathHead;
            result.path.clear();

            if (addLeadingSlash)
                result.path.push_back('/');

            bool first = true;
            while (seg)
            {
                if (!first)
                    result.path.push_back('/');
                result.path += rangeToString(seg->text);
                first = false;
                seg = seg->next;
            }
        }
        else
        {
            // No path segments present
            result.path = addLeadingSlash ? std::string("/") : std::string();
        }

        return result;
    }

    std::map<std::string, std::string> queryParams() const
    {
        std::map<std::string, std::string> params;
        if (query.empty())
            return params;

        size_t start = 0;
        while (start < query.length())
        {
            size_t end = query.find('&', start);
            if (end == std::string::npos)
                end = query.length();

            size_t eq = query.find('=', start);
            if (eq != std::string::npos && eq < end)
            {
                params[decode(query.substr(start, eq - start))] = decode(query.substr(eq + 1, end - eq - 1));
            }
            else
            {
                params[decode(query.substr(start, end - start))] = "";
            }
            start = end + 1;
        }
        return params;
    }

    std::string toString() const
    {
        std::string out;
        if (!scheme.empty())
            out += scheme + "://";

        if (!host.empty())
        {
            if (!user.empty())
            {
                out += user;
                if (!pass.empty())
                    out += ":" + pass;
                out += "@";
            }
            out += host;
        }

        if (port != -1)
            out += ":" + std::to_string(port);

        out += path;

        if (!query.empty())
            out += "?" + query;
        if (!fragment.empty())
            out += "#" + fragment;
        return out;
    }

private:
    // Inner RAII Class for uriparser resource management
    class UriWrapper
    {
        UriUriA m_uri;
        bool m_valid;

    public:
        explicit UriWrapper(const std::string &s)
        {
            std::memset(&m_uri, 0, sizeof(m_uri));
            UriParserStateA state;
            state.uri = &m_uri;
            int code = uriParseUriA(&state, s.c_str());
            // Consider non-negative codes as success (success or non-fatal warnings).
            m_valid = (code >= 0);
        }

        ~UriWrapper()
        {
            uriFreeUriMembersA(&m_uri);
        }

        bool isValid() const { return m_valid; }
        const UriUriA *get() const { return &m_uri; }
    };

    static std::string rangeToString(UriTextRangeA r)
    {
        if (!r.first || r.first >= r.afterLast)
            return "";
        // length = afterLast - first
        return std::string(r.first, static_cast<size_t>(r.afterLast - r.first));
    }

    static std::string decode(const std::string &s)
    {
        std::string out;
        out.reserve(s.size());
        for (size_t i = 0; i < s.size(); ++i)
        {
            if (s[i] == '%' && i + 2 < s.size())
            {
                auto fromHex = [](char c)
                {
                    return (c >= '0' && c <= '9')   ? c - '0'
                           : (c >= 'a' && c <= 'f') ? c - 'a' + 10
                           : (c >= 'A' && c <= 'F') ? c - 'A' + 10
                                                    : 0;
                };
                out += static_cast<char>((fromHex(s[i + 1]) << 4) + fromHex(s[i + 2]));
                i += 2;
            }
            else if (s[i] == '+')
            {
                out += ' ';
            }
            else
            {
                out += s[i];
            }
        }
        return out;
    }
};
