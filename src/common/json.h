// src/common/json.h
#pragma once

#include <json/json.h>
#include <string>

class JSON
{
public:
    // Dump JSON to a valid UTF-8 string; invalid sequences become U+FFFD
    static std::string dump(const Json::Value &j, int indent = -1);

    // Dump JSON converted to the local encoding (Windows CP_ACP, UTF-8 on POSIX)
    static std::string dumpToLocalEncoding(const Json::Value &j, int indent = -1);

    // Strict parse: rejects malformed JSON, invalid UTF-8 and number overflow
    // with std::invalid_argument (mapped to HTTP 400 by the request layer)
    static Json::Value parse(const std::string &text);

    // Non-throwing parse: returns a null value on failure, error text in *error
    static Json::Value parse(const std::string &text, std::string *error);

    // RFC 7386 merge-patch: null deletes a member, objects merge recursively
    static void mergePatch(Json::Value &target, const Json::Value &patch);
};
