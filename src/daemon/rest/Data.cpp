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

std::unique_ptr<msgpack::sbuffer> Response::serialize() const
{
	// pack
	auto sbuf = std::make_unique<msgpack::sbuffer>();
	msgpack::pack(*sbuf, *this);
	return sbuf;
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

	headers["Access-Control-Allow-Origin"] = "*";
	headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
	headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
	// Note: Removed Access-Control-Allow-Credentials as it conflicts with wildcard origin
}

void Response::applySecurityHeaders()
{
	headers["X-Content-Type-Options"] = "nosniff";
	headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
}

std::unique_ptr<msgpack::sbuffer> Request::serialize() const
{
	auto sbuf = std::make_unique<msgpack::sbuffer>();
	msgpack::pack(*sbuf, *this);
	return sbuf;
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
