// src/daemon/rest/Data.cpp
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

namespace
{
/// Shared msgpack frame decode: logs and returns false on any failure, leaving
/// `out` untouched.
template <typename T>
bool msgpackUnpack(const char *data, std::size_t dataSize, T &out, const char *fname, const char *kind)
{
	try
	{
		msgpack::unpacked result;
		msgpack::unpack(result, data, dataSize);
		msgpack::object obj = result.get();
		obj.convert(out);
		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "Failed to deserialize " << kind << " message with size <" << dataSize << ">: " << e.what();
	}
	return false;
}
} // namespace

bool Response::deserialize(const std::uint8_t *data, std::size_t dataSize)
{
	return msgpackUnpack(reinterpret_cast<const char *>(data), dataSize, *this, "Response::deserialize() ",
						 "response");
}

void Response::applyCorsHeaders(const std::string &origin)
{
	if (!Configuration::instance()->corsAllowsOrigin(origin))
		return;

	headers[web::http::header_names::access_control_allow_origin] = origin;
	headers[web::http::header_names::access_control_allow_methods] = "GET, POST, PUT, DELETE, OPTIONS";
	headers[web::http::header_names::access_control_allow_headers] = "Authorization, Content-Type, X-File-Path";
	headers[web::http::header_names::vary] = "Origin";
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
	return msgpackUnpack(data.data(), data.size(), *this, "Request::deserialize() ", "request");
}
