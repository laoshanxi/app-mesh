#include <chrono>
#include <errno.h>
#include <tuple>

#include <msgpack.hpp>

#include "../../common/Utility.h"
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
		Response resp = obj.as<Response>();
		*this = resp;
		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "failed with error: " << e.what();
	}
	return false;
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
		msgpack::unpack(result, reinterpret_cast<const char *>(data->data()), data->size());

		msgpack::object obj = result.get();
		obj.convert(*this); // directly fill into *this

		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "failed with error: " << e.what();
	}
	return false;
}
