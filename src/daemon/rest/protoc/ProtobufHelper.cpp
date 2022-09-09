#include <chrono>
#include <errno.h>
#include <tuple>

#include "../../../common/Utility.h"
#include "ProtobufHelper.h"

// The first 4 bytes of the protocol buffer data contains the size of the following body data.
constexpr size_t PROTOBUF_HEADER_LENGTH = 4;

const std::tuple<std::shared_ptr<char>, size_t> ProtobufHelper::serialize(const google::protobuf::Message &msg)
{
	const auto msgLength = msg.ByteSizeLong();
	const auto totalLength = PROTOBUF_HEADER_LENGTH + msgLength;
	const auto buffer = make_shared_array<char>(totalLength);
	*((uint32_t *)buffer.get()) = htonl(msgLength); // host to network byte order
	msg.SerializeToArray(buffer.get() + 4, msgLength);

	return std::make_tuple(buffer, totalLength); // return buffer and length pair
}

bool ProtobufHelper::deserialize(google::protobuf::Message &msg, const char *data)
{
	const static char fname[] = "ProtobufHelper::deserialize() ";

	const auto dataSize = ntohl(*((uint32_t *)(data)));
	// De-Serialize
	if (!msg.ParseFromArray(data + PROTOBUF_HEADER_LENGTH, dataSize))
	{
		LOG_ERR << fname << "ParseFromCodedStream failed with error :" << std::strerror(errno);
		return false;
	}
	return true;
}

const std::tuple<std::shared_ptr<char>, int> ProtobufHelper::readMessageBlock(const ACE_SOCK_Stream &socket)
{
	const static char fname[] = "ProtobufHelper::readMessageBlock() ";
	LOG_DBG << fname << "entered";

	// 1. read header socket data (4 bytes), use MSG_PEEK to not clear data from cache
	char header[PROTOBUF_HEADER_LENGTH] = {0};
	ssize_t recvReturn = ACE::recv_n(socket.get_handle(), header, PROTOBUF_HEADER_LENGTH, MSG_PEEK);
	if (socket.get_handle() != ACE_INVALID_HANDLE && recvReturn <= 0)
	{
		socket.dump();
		LOG_ERR << fname << "read header length failed with error :" << std::strerror(errno);
		return std::make_tuple(nullptr, recvReturn);
	}

	// 2. parse header data (get body length). network to host byte order
	const auto bodySize = ntohl(*((int *)(header))); // host to network byte order
	if (bodySize == 0)
	{
		socket.dump();
		LOG_ERR << fname << "parse header length with error :" << std::strerror(errno);
		return std::make_tuple(nullptr, recvReturn);
	}

	// 3. read header + body socket data
	const auto bufferSize = bodySize + PROTOBUF_HEADER_LENGTH;
	auto bodyBuffer = make_shared_array<char>(bufferSize);
	// https://www.demo2s.com/c/c-if-errno-eintr-fiag.html
	// https://programmerall.com/article/5562684780/#:~:text=When%20a%20certain%20signal%20is%20caught%2C%20the%20system,system%20calls%20that%20may%20block%20the%20process%20forever.
	// https://www.dre.vanderbilt.edu/Doxygen/7.0.8/html/libace-doc/a07501.html
	size_t totalRecieved = 0;
	recvReturn = ACE::recv_n(socket.get_handle(), bodyBuffer.get(), bufferSize, 0, &totalRecieved);
	while (totalRecieved < bufferSize && errno == EINTR)
	{
		size_t transfered = 0;
		recvReturn = ACE::recv_n(socket.get_handle(), bodyBuffer.get() + totalRecieved, bufferSize - totalRecieved, 0, &transfered);
		totalRecieved += transfered;
	}
	if (bufferSize == totalRecieved)
		recvReturn = totalRecieved;
	if (socket.get_handle() != ACE_INVALID_HANDLE && recvReturn <= 0)
	{
		LOG_ERR << fname << "read body socket data failed with error :" << std::strerror(errno);
		return std::make_tuple(nullptr, recvReturn);
	}
	LOG_DBG << fname << "read message block data with length: " << bufferSize;
	return std::make_tuple(bodyBuffer, recvReturn);
}
