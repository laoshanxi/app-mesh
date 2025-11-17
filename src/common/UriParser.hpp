// UriParser.cpp
// C++11 lightweight wrapper around uriparser to provide simple Boost::url-like API.

#pragma once

#include <cstdlib>
#include <cstring>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <uriparser/Uri.h>

class Uri
{
public:
    std::string scheme;
    std::string userinfo; // user:pass
    std::string host;
    int port = -1;
    std::string path = "/";
    std::string query;
    std::string fragment;

    Uri() = default;

    static Uri parse(const std::string &str)
    {
        Uri out;

        UriUriA uri;
        UriParserStateA state;
        memset(&uri, 0, sizeof(uri));
        state.uri = &uri;

        if (uriParseUriA(&state, str.c_str()) != URI_SUCCESS)
        {
            uriFreeUriMembersA(&uri);

            // handle pure hostname case: e.g. "example.com"
            out.host = str;
            return out;
        }

        auto r2s = [](const UriTextRangeA &r)
        {
            return (!r.first || r.first == r.afterLast)
                       ? std::string()
                       : std::string(r.first, r.afterLast - r.first);
        };

        out.scheme = r2s(uri.scheme);
        out.userinfo = r2s(uri.userInfo);
        out.host = r2s(uri.hostText);
        out.query = r2s(uri.query);
        out.fragment = r2s(uri.fragment);

        { // port
            std::string p = r2s(uri.portText);
            out.port = p.empty() ? -1 : std::atoi(p.c_str());
        }

        // ---- Simplified path build ----
        {
            std::string p;
            const UriPathSegmentA *seg = uri.pathHead;
            while (seg)
            {
                if (seg != uri.pathHead)
                    p += "/";
                p += r2s(seg->text);
                seg = seg->next;
            }

            if (uri.absolutePath)
                out.path = "/" + p;
            else if (!p.empty())
                out.path = p;

            if (out.path.empty())
                out.path = "/";
        }

        uriFreeUriMembersA(&uri);
        return out;
    }

    // Query map
    std::map<std::string, std::string> queryParams() const
    {
        std::map<std::string, std::string> m;
        if (query.empty())
            return m;

        size_t i = 0;
        while (i < query.size())
        {
            size_t amp = query.find('&', i);
            std::string kv = (amp == std::string::npos)
                                 ? query.substr(i)
                                 : query.substr(i, amp - i);

            size_t eq = kv.find('=');
            std::string key = (eq == std::string::npos) ? kv : kv.substr(0, eq);
            std::string val = (eq == std::string::npos) ? "" : kv.substr(eq + 1);

            m[decode(key)] = decode(val);

            if (amp == std::string::npos)
                break;
            i = amp + 1;
        }
        return m;
    }

    // Minimal reconstruction
    std::string toString() const
    {
        std::ostringstream ss;

        if (!scheme.empty())
            ss << scheme << ":";

        if (!host.empty())
        {
            ss << "//";
            if (!userinfo.empty())
                ss << userinfo << "@";
            ss << host;
            if (port > 0)
                ss << ":" << port;
        }

        ss << path;
        if (!query.empty())
            ss << "?" << query;
        if (!fragment.empty())
            ss << "#" << fragment;

        return ss.str();
    }

private:
    static std::string decode(const std::string &s)
    {
        std::string out;
        out.reserve(s.size());

        auto hex = [](char c) -> int
        {
            if (c >= '0' && c <= '9')
                return c - '0';
            if (c >= 'a' && c <= 'f')
                return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F')
                return 10 + (c - 'A');
            return -1;
        };

        for (size_t i = 0; i < s.size(); ++i)
        {
            if (s[i] == '%' && i + 2 < s.size())
            {
                int hi = hex(s[i + 1]);
                int lo = hex(s[i + 2]);
                if (hi >= 0 && lo >= 0)
                {
                    out.push_back(char((hi << 4) | lo));
                    i += 2;
                    continue;
                }
            }
            out.push_back(s[i]);
        }
        return out;
    }
};
