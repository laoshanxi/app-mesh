// src/daemon/rest/Data.cpp
#include <charconv>
#include <chrono>
#include <tuple>

#include <json/json.h>
#include <msgpack.hpp>

#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Data.h"

Response::Response() : http_status(0) {}

Response::~Response() {}

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
	headers[web::http::header_names::x_content_type_options] = "nosniff";
	headers[web::http::header_names::strict_transport_security] = "max-age=31536000; includeSubDomains";
}

std::string Request::serialize() const
{
	std::string out;
	StringWriteStream stream{out};
	msgpack::pack(stream, *this);
	return out;
}

bool Request::deserialize(const std::string &data)
{
	const static char fname[] = "Request::deserialize() ";
	try
	{
		msgpack::unpacked result;
		msgpack::unpack(result, data.data(), data.size());
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
	if (auto it = headers.find(web::http::header_names::content_length); it != headers.end())
	{
		long long len = 0;
		const auto result = std::from_chars(it->second.data(), it->second.data() + it->second.size(), len);
		if (result.ec == std::errc{} && result.ptr != it->second.data())
			return len > 0;
		return false;
	}

	if (auto it = headers.find(web::http::header_names::transfer_encoding); it != headers.end())
	{
		return it->second.find("chunked") != std::string::npos;
	}

	return false;
}
