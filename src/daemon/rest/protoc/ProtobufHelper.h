#pragma once
#include <tuple>

#include <ace/SSL/SSL_SOCK_Stream.h>
#include <msgpack.hpp>

class Response
{
public:
	Response();
	virtual ~Response();
	std::shared_ptr<msgpack::sbuffer> serialize() const;
	bool deserialize(const char *data, int dataSize);

public:
	std::string uuid;
	std::string request_uri;
	int http_status;
	std::string body_msg_type;
	std::string body;
	std::map<std::string, std::string> headers;
	std::map<std::string, std::string> file_upload_request_headers;

	MSGPACK_DEFINE_MAP(uuid, request_uri, http_status, body_msg_type, body, headers);
};

class Request
{
public:
	Request();
	virtual ~Request();
	std::shared_ptr<msgpack::sbuffer> serialize() const;
	bool deserialize(const char *data, int dataSize);
	bool verifyHMAC();

public:
	std::string uuid;
	std::string request_uri;
	std::string http_method;
	std::string client_addr;
	std::string body;
	std::map<std::string, std::string> headers;
	std::map<std::string, std::string> querys;

	MSGPACK_DEFINE_MAP(uuid, request_uri, http_method, http_method, client_addr, body, headers, querys);
};

/// <summary>
/// ProtobufHelper common functions
/// </summary>
class ProtobufHelper
{
public:
	ProtobufHelper();
	virtual ~ProtobufHelper();

	/// @brief Read a message block from socket (include header and body).
	/// @param socket ACE_SSL_SOCK_Stream used to receive data
	/// @return char *: The complete data buffer according to a Protocbuf message
	/// @return int: the message data size
	static const std::tuple<std::shared_ptr<char>, int> readMessageBlock(const ACE_SSL_SOCK_Stream &socket);

	/// @brief Read 4 bytes int (network order) for below message size
	/// @param socket ACE_SSL_SOCK_Stream used to receive data
	/// @param recvReturn
	/// @return int value for the header, less than 1 means read failed
	static int readMsgHeader(const ACE_SSL_SOCK_Stream &socket, ssize_t &recvReturn);

	/// @brief Read message from socket
	/// @param socket ACE_SSL_SOCK_Stream used to receive data
	/// @param bodySize message size used to read from socket
	/// @param recvReturn socket return code
	/// @return char *: message data
	/// @return int: the message data size
	static const std::tuple<std::shared_ptr<char>, int> readBytes(const ACE_SSL_SOCK_Stream &socket, size_t bodySize, ssize_t &recvReturn);
};
