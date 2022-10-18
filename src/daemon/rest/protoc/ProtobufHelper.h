#pragma once
#include <tuple>

#include <ace/SOCK_Stream.h>
#include <google/protobuf/message.h>

/// <summary>
/// ProtobufHelper common functions
/// </summary>
class ProtobufHelper
{
public:
	ProtobufHelper();
	virtual ~ProtobufHelper();

	/**
	 * Serialize data for sending over a socket.
	 * @param msg the protocol buffer message
	 * @return std::shared_ptr<char>: packet The data buffer to write data into
	 * @return size_t: the number of bytes encoded
	 */
	static const std::tuple<std::shared_ptr<char>, size_t> serialize(const google::protobuf::Message &msg);

	/**
	 * Read a protocol buffer from raw data.
	 * @param msg the message to read
	 * @param data the raw data containing the message plus the header
	 * @return success or not
	 */
	static bool deserialize(google::protobuf::Message &msg, const char *data);

	/**
	 * Read a message block from socket (include header and body).
	 * @param socket ACE_SOCK_Stream used to receive data
	 * @return char *: The complete data buffer according to a Protocbuf message
	 * @return int: the number of bytes received
	 */
	static const std::tuple<std::shared_ptr<char>, int> readProtobufBlock(const ACE_SOCK_Stream &socket);

	static int readMsgHeader(const ACE_SOCK_Stream &socket, bool shift, ssize_t &recvReturn);
	static const std::tuple<std::shared_ptr<char>, int> readMsgBody(const ACE_SOCK_Stream &socket, int bodySize, ssize_t &recvReturn);
};
