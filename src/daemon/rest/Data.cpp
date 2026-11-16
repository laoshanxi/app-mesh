// src/daemon/rest/Data.cpp
#include <chrono>
#include <tuple>

#include <msgpack.hpp>
#include <nlohmann/json.hpp>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Data.h"

Response::Response()
	: http_status(0)
{
}

Response::~Response()
{
}

namespace
{
	// msgpack packs into any stream with write(const char *, size_t).
	struct StringWriteStream
	{
		std::string &out;
		void write(const char *data, std::size_t len) { out.append(data, len); }
	};
}

std::string Response::serialize() const
{
	std::string out;
	StringWriteStream stream{out};
	msgpack::pack(stream, *this);
	return out;
}

bool Response::deserialize(const std::uint8_t *data, std::size_t dataSize)
{
	const static char fname[] = "Response::deserialize() ";
	try
	{
		msgpack::unpacked result;
		msgpack::unpack(result, reinterpret_cast<const char *>(data), dataSize);
		msgpack::object obj = result.get();
		obj.convert(*this);
		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "Failed to deserialize response message with size <" << dataSize << ">: " << e.what();
	}
	return false;
}

void Response::applyCorsHeaders(const std::string &origin)
{
	if (Configuration::instance()->getCorsDisabled())
		return;
	// CORS is opt-in: no wildcard. Without a matching Origin allowlist entry
	// no CORS headers are sent at all (the UI is a same-origin proxy).
	if (origin.empty() || Configuration::instance()->getCorsAllowOrigins().count(origin) == 0)
		return;

	headers[web::http::header_names::access_control_allow_origin] = origin;
	headers[web::http::header_names::access_control_allow_methods] = "GET, POST, PUT, DELETE, OPTIONS";
	headers[web::http::header_names::access_control_allow_headers] = "Authorization, Content-Type";
}

void Response::applySecurityHeaders()
{
	headers["X-Content-Type-Options"] = "nosniff";
	headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
	// Daemon-wide CSP. A handler-pinned policy (the OAuth relay page allows
	// exactly its inline script hash) wins over this default.
	if (headers.count(web::http::header_names::content_security_policy) == 0)
		headers[web::http::header_names::content_security_policy] = "default-src 'none'";
}

std::string Request::serialize() const
{
	std::string out;
	StringWriteStream stream{out};
	msgpack::pack(stream, *this);
	return out;
}

bool Request::deserialize(const ByteBuffer &data)
{
	const static char fname[] = "Request::deserialize() ";
	try
	{
		msgpack::unpacked result;
		msgpack::unpack(result, reinterpret_cast<const char *>(data.data()), data.size());
		msgpack::object obj = result.get();
		obj.convert(*this);
		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "Failed to deserialize request message with size <" << data.size() << ">: " << e.what();
	}
	return false;
}

bool Request::contain_body() const
{
	auto it = headers.find("content-length");
	if (it != headers.end())
	{
		char *end;
		errno = 0;
		long long len = std::strtoll(it->second.c_str(), &end, 10);
		if (errno == 0 && end != it->second.c_str())
		{
			return len > 0;
		}
		return false;
	}

	it = headers.find("transfer-encoding");
	if (it != headers.end())
	{
		return it->second.find("chunked") != std::string::npos;
	}

	return false;
}
