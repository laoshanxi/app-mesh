#pragma once
#include <tuple>
#include <vector>

#include <msgpack.hpp>

#ifdef __has_include
#if __has_include(<ace/SSL/SSL_SOCK_Stream.h>)
#include <ace/SSL/SSL_SOCK_Stream.h>
#else
#include <ace/SSL_SOCK_Stream.h>
#endif
#else
#include <ace/SSL/SSL_SOCK_Stream.h>
#endif

#include "../../../common/HttpHeaderMap.h"

using ByteBuffer = std::shared_ptr<std::vector<std::uint8_t>>;

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
	std::vector<std::uint8_t> body;
	std::map<std::string, std::string> headers;
	HttpHeaderMap file_upload_request_headers;

	MSGPACK_DEFINE_MAP(uuid, request_uri, http_status, body_msg_type, body, headers);
};

class Request
{
public:
	Request() = default;
	~Request() = default;

	std::shared_ptr<msgpack::sbuffer> serialize() const;
	bool deserialize(const ByteBuffer &data);

public:
	std::string uuid;
	std::string request_uri;
	std::string http_method;
	std::string client_addr;
	std::vector<std::uint8_t> body; // raw binary
	HttpHeaderMap headers;
	std::map<std::string, std::string> query;

	MSGPACK_DEFINE_MAP(uuid, request_uri, http_method, client_addr, body, headers, query);
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
	static const ByteBuffer readMessageBlock(const ACE_SSL_SOCK_Stream &socket);

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
	static const ByteBuffer readBytes(const ACE_SSL_SOCK_Stream &socket, size_t bodySize, ssize_t &recvReturn);
};
