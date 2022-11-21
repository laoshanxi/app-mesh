#include <chrono>
#include <errno.h>
#include <tuple>

#include "../../../common/Utility.h"
#include "ProtobufHelper.h"

const std::tuple<std::shared_ptr<char>, size_t> ProtobufHelper::serialize(const google::protobuf::Message &msg)
{
	const static char fname[] = "ProtobufHelper::serialize() ";

	const auto msgLength = msg.ByteSizeLong();
	const auto totalLength = PROTOBUF_HEADER_LENGTH + msgLength;
	const auto buffer = make_shared_array<char>(totalLength);
	*((uint32_t *)buffer.get()) = htonl(msgLength); // host to network byte order
	if (!msg.SerializeToArray(buffer.get() + 4, msgLength))
	{
		LOG_ERR << fname << msg.DebugString();
		return std::make_tuple(nullptr, 0);
	}
	return std::make_tuple(buffer, totalLength); // return buffer and length pair
}

bool ProtobufHelper::deserialize(google::protobuf::Message &msg, const char *data, int dataSize)
{
	const static char fname[] = "ProtobufHelper::deserialize() ";

	// De-Serialize
	if (!msg.ParseFromArray(data, dataSize))
	{
		LOG_ERR << fname << "ParseFromCodedStream failed with error :" << msg.DebugString();
		return false;
	}
	return true;
}

const std::tuple<std::shared_ptr<char>, int> ProtobufHelper::readMessageBlock(const ACE_SSL_SOCK_Stream &socket)
{
	const static char fname[] = "ProtobufHelper::readMessageBlock() ";
	LOG_DBG << fname << "entered";

	ssize_t recvReturn = 0;
	const auto bodySize = readMsgHeader(socket, recvReturn);
	if (bodySize <= 0)
	{
		LOG_ERR << fname << "parse header length with error :" << std::strerror(errno);
		return std::make_tuple(nullptr, recvReturn);
	}
	return readBytes(socket, bodySize, recvReturn);
}

int ProtobufHelper::readMsgHeader(const ACE_SSL_SOCK_Stream &socket, ssize_t &recvReturn)
{
	const static char fname[] = "ProtobufHelper::readMsgHeader() ";
	// read header socket data (4 bytes)
	auto result = readBytes(socket, PROTOBUF_HEADER_LENGTH, recvReturn);
	auto data = std::get<0>(result);
	if (recvReturn <= 0)
	{
		LOG_ERR << fname << "read header length failed with error :" << std::strerror(errno);
		return -1;
	}
	// parse header data (get body length). network to host byte order
	const auto bodySize = ntohl(*((int *)(data.get()))); // host to network byte order
	LOG_DBG << fname << "read length :" << bodySize << " from header";
	if (bodySize > MAX_TCP_BLOCK_SIZE)
	{
		LOG_ERR << fname << "read data size reached limitation, aborting connection";
		return -1;
	}
	return bodySize;
}

const std::tuple<std::shared_ptr<char>, int> ProtobufHelper::readBytes(const ACE_SSL_SOCK_Stream &socket, size_t bodySize, ssize_t &recvReturn)
{
	const static char fname[] = "ProtobufHelper::readBytes() ";

	// read socket data with given length
	const auto bufferSize = bodySize;
	auto bodyBuffer = make_shared_array<char>(bufferSize);
	// https://www.demo2s.com/c/c-if-errno-eintr-fiag.html
	// https://programmerall.com/article/5562684780/#:~:text=When%20a%20certain%20signal%20is%20caught%2C%20the%20system,system%20calls%20that%20may%20block%20the%20process%20forever.
	errno = 0;
	size_t totalRecieved = 0;
	recvReturn = socket.recv_n(bodyBuffer.get(), bufferSize, 0, &totalRecieved);
	while (totalRecieved < bufferSize && errno == EINTR)
	{
		size_t transfered = 0;
		recvReturn = socket.recv_n(bodyBuffer.get() + totalRecieved, bufferSize - totalRecieved, 0, &transfered);
		totalRecieved += transfered;
	}
	if (bufferSize == totalRecieved)
		recvReturn = totalRecieved;
	if (socket.get_handle() != ACE_INVALID_HANDLE && recvReturn <= 0)
	{
		LOG_ERR << fname << "read body socket data failed with error: " << std::strerror(errno);
		return std::make_tuple(nullptr, recvReturn);
	}
	LOG_DBG << fname << "read message block data with length: " << bufferSize;
	return std::make_tuple(bodyBuffer, recvReturn);
}
