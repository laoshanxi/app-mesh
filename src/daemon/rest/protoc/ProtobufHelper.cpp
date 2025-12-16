#include <chrono>
#include <errno.h>
#include <tuple>

#include <msgpack.hpp>

#include "../../../common/Utility.h"
#include "ProtobufHelper.h"

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

const ByteBuffer ProtobufHelper::readMessageBlock(const ACE_SSL_SOCK_Stream &socket)
{
	const static char fname[] = "ProtobufHelper::readMessageBlock() ";
	LOG_DBG << fname << "entered";

	ssize_t recvReturn = 0;
	const auto bodySize = readMsgHeader(socket, recvReturn);
	if (bodySize <= 0)
	{
		return nullptr;
	}
	return readBytes(socket, bodySize, recvReturn);
}

int ProtobufHelper::readMsgHeader(const ACE_SSL_SOCK_Stream &socket, ssize_t &recvReturn)
{
	const static char fname[] = "ProtobufHelper::readMsgHeader() ";
	// read header socket data (4 bytes)
	auto data = readBytes(socket, TCP_MESSAGE_HEADER_LENGTH, recvReturn);
	if (!data)
	{
		LOG_DBG << fname << "read header length failed with error: " << last_error_msg();
		return -1;
	}

	// Step 1: Safely copy and parse the 4-byte magic number from the header
	// Step 2: Safely copy and parse the 4-byte body size from the header
	uint32_t magic = 0, bodySize = 0;
	std::memcpy(&magic, data->data(), sizeof(magic));
	magic = ntohl(magic); // Convert to host byte order
	if (magic != TCP_MESSAGE_MAGIC)
	{
		LOG_ERR << fname << "invalid message received: magic number [0x" << std::hex << std::uppercase << std::setw(8)
				<< std::setfill('0') << magic << "] (expected: 0x" << TCP_MESSAGE_MAGIC << ")";
		return -1;
	}
	std::memcpy(&bodySize, data->data() + sizeof(magic), sizeof(bodySize));
	bodySize = ntohl(bodySize); // Convert to host byte order
	LOG_DBG << fname << "body length read from header: " << bodySize << " bytes";

	if (bodySize > TCP_MAX_BLOCK_SIZE)
	{
		LOG_ERR << fname << "read data size reached limitation, aborting connection";
		return -1;
	}
	return bodySize;
}

const ByteBuffer ProtobufHelper::readBytes(const ACE_SSL_SOCK_Stream &socket, size_t bodySize, ssize_t &recvReturn)
{
	const static char fname[] = "ProtobufHelper::readBytes() ";

	// read socket data with given length
	const auto bufferSize = bodySize;
	auto bodyBuffer = std::make_shared<std::vector<std::uint8_t>>(bufferSize);
	// https://www.demo2s.com/c/c-if-errno-eintr-fiag.html
	// https://programmerall.com/article/5562684780/#:~:text=When%20a%20certain%20signal%20is%20caught%2C%20the%20system,system%20calls%20that%20may%20block%20the%20process%20forever.
	errno = 0;
	size_t totalReceived = 0;

	while (totalReceived < bufferSize)
	{
		size_t transferred = 0;
		recvReturn = socket.recv_n(bodyBuffer->data() + totalReceived, bufferSize - totalReceived, 0, &transferred);

		if (recvReturn <= 0)
		{
			int lastErr = ACE_OS::last_error();

#if defined(_WIN32)
			// Windows: WSAEWOULDBLOCK is transient
			// 	- retry on WSAEWOULDBLOCK (10035) if the socket is non-blocking.
			if (lastErr == WSAEWOULDBLOCK)
			{
				::Sleep(1); // tiny backoff to avoid busy loop
				continue;
			}
#else
			// Linux/Unix: retry on EINTR/EAGAIN
			// 	- EINTR (signal interruption) and EAGAIN (non-blocking socket temporarily unavailable).
			if (lastErr == EINTR || lastErr == EAGAIN)
			{
				continue;
			}
#endif
			// Hard failure
			LOG_WAR << fname << "read socket data failed with error(" << lastErr << "): " << ACE_OS::strerror(lastErr);
			return nullptr;
		}

		totalReceived += transferred;
	}

	LOG_DBG << fname << "read message block data with length: " << totalReceived;

	return bodyBuffer;
}
