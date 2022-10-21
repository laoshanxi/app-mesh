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

	/// @brief Serialize data for sending over a socket.
	/// @param msg the protocol buffer message
	/// @return std::shared_ptr<char>: packet The data buffer to write data into
	/// @return size_t: the number of bytes encoded
	static const std::tuple<std::shared_ptr<char>, size_t> serialize(const google::protobuf::Message &msg);

	/// @brief Read a protocol buffer from raw data.
	/// @param msg the message to read
	/// @param data the raw data containing the message plus the header
	/// @param dataSize the raw data size
	/// @return success or not
	static bool deserialize(google::protobuf::Message &msg, const char *data, int dataSize);

	/// @brief Read a message block from socket (include header and body).
	/// @param socket ACE_SOCK_Stream used to receive data
	/// @return char *: The complete data buffer according to a Protocbuf message
	/// @return int: the message data size
	static const std::tuple<std::shared_ptr<char>, int> readMessageBlock(const ACE_SOCK_Stream &socket);

	/// @brief Read 4 bytes int (network order) for below message size
	/// @param socket ACE_SOCK_Stream used to receive data
	/// @param recvReturn
	/// @return int value for the header, less than 1 means read failed
	static int readMsgHeader(const ACE_SOCK_Stream &socket, ssize_t &recvReturn);

	/// @brief Read message from socket
	/// @param socket ACE_SOCK_Stream used to receive data
	/// @param bodySize message size used to read from socket
	/// @param recvReturn socket return code
	/// @return char *: message data
	/// @return int: the message data size
	static const std::tuple<std::shared_ptr<char>, int> readBytes(const ACE_SOCK_Stream &socket, int bodySize, ssize_t &recvReturn);
};
