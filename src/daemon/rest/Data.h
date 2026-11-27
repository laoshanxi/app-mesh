// src/daemon/rest/Data.h
#pragma once
#include <cstdint>
#include <string>
#include <tuple>
#include <vector>

#include <msgpack.hpp>

#include "../../common/HttpHeaderMap.h"

class Response
{
public:
	Response();
	virtual ~Response();
	std::string serialize() const;
	bool deserialize(const std::uint8_t *data, std::size_t dataSize);

	void applyCorsHeaders(const std::string &origin);
	void applySecurityHeaders();

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

	std::string serialize() const;
	bool deserialize(const std::string &data);

public:
	std::string uuid;
	std::string request_uri;
	std::string http_method;
	std::string client_addr;
	std::string connection_id; // HTTP connection the request arrived on; empty on multiplexed transports and when forwarded
	std::vector<std::uint8_t> body; // raw binary
	HttpHeaderMap headers;
	std::map<std::string, std::string> query;

	MSGPACK_DEFINE_MAP(uuid, request_uri, http_method, client_addr, connection_id, body, headers, query);
};
