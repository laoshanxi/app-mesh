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

std::unique_ptr<msgpack::sbuffer> Response::serialize() const
{
	// pack
	auto sbuf = std::make_unique<msgpack::sbuffer>();
	msgpack::pack(*sbuf, *this);
	return sbuf;
}

std::string Response::serializeToString() const
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

void Response::applyCorsHeaders()
{
	if (Configuration::instance()->getCorsDisabled())
		return;

	headers[web::http::header_names::access_control_allow_origin] = "*";
	headers[web::http::header_names::access_control_allow_methods] = "GET, POST, PUT, DELETE, OPTIONS";
	headers[web::http::header_names::access_control_allow_headers] = "Authorization, Content-Type";
	// Note: Removed Access-Control-Allow-Credentials as it conflicts with wildcard origin
}

void Response::applySecurityHeaders()
{
	headers[web::http::header_names::x_content_type_options] = "nosniff";
	headers[web::http::header_names::strict_transport_security] = "max-age=31536000; includeSubDomains";
}

std::unique_ptr<msgpack::sbuffer> Request::serialize() const
{
	auto sbuf = std::make_unique<msgpack::sbuffer>();
	msgpack::pack(*sbuf, *this);
	return sbuf;
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
	auto it = headers.find(web::http::header_names::content_length);
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

	it = headers.find(web::http::header_names::transfer_encoding);
	if (it != headers.end())
	{
		return it->second.find("chunked") != std::string::npos;
	}

	return false;
}
