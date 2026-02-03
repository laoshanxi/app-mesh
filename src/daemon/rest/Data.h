// src/daemon/rest/Data.h
#pragma once
#include <tuple>
#include <vector>

#include <msgpack.hpp>

#ifdef __has_include
#if __has_include(<ace/SSL/SSL_SOCK_Stream.h>)
#include <ace/SSL/SSL_SOCK_Stream.h>
#else
#include <ace/SSL_SOCK_Stream.h>
#endif
#else
#include <ace/SSL/SSL_SOCK_Stream.h>
#endif

#include "../../common/HttpHeaderMap.h"

using ByteBuffer = std::shared_ptr<std::vector<std::uint8_t>>;

class Response
{
public:
	Response();
	virtual ~Response();
	std::unique_ptr<msgpack::sbuffer> serialize() const;
	bool deserialize(const std::uint8_t *data, std::size_t dataSize);

	bool handleAuthCookies();
	bool setAuthCookie();

public:
	std::string uuid;
	std::string request_uri;
	int http_status;
	std::string body_msg_type;
	std::vector<std::uint8_t> body;
	std::map<std::string, std::string> headers;
	HttpHeaderMap file_upload_request_headers;

	MSGPACK_DEFINE_MAP(uuid, request_uri, http_status, body_msg_type, body, headers);
};

class Request
{
public:
	Request() = default;
	~Request() = default;

	std::unique_ptr<msgpack::sbuffer> serialize() const;
	bool deserialize(const ByteBuffer &data);

	bool contain_body();
	bool convertCookieToAuthorization();

public:
	std::string uuid;
	std::string request_uri;
	std::string http_method;
	std::string client_addr;
	std::vector<std::uint8_t> body; // raw binary
	HttpHeaderMap headers;
	std::map<std::string, std::string> query;

	MSGPACK_DEFINE_MAP(uuid, request_uri, http_method, client_addr, body, headers, query);
};
