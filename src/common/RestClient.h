// src/common/RestClient.h
#pragma once

#include <map>
#include <memory>
#include <string>

#include "HttpHeaderMap.h"
#include "Utility.h"

/// @brief HTTP response data structure
struct HttpResponse
{
	long statusCode = 0;
	std::string text;
	HttpHeaderMap header; // case-insensitive; keys normalized to lower-case
	void raiseForStatus();
};

/// @brief TLS configuration structure for the HTTP client
struct ClientSSLConfig
{
	ClientSSLConfig();
	// Convert relative paths to absolute paths if necessary
	static std::string resolveAbsolutePath(const std::string &workingHome, std::string filePath);
	bool m_verify_client;             // present a client certificate (mTLS)
	bool m_verify_server;             // verify the server certificate and host name
	std::string m_certificate;        // certificate file (PEM format)
	std::string m_private_key;        // private key file (PEM format)
	std::string m_private_key_passwd; // private key password
	std::string m_ca_location;        // trusted CA file or directory
};

/**
 * @brief Synchronous HTTP client facade.
 * @details The transport backend is trantor (drogon's network library, RestClientDrogon.cpp).
 */
class RestClient
{
public:
	/**
	 * @brief Performs an HTTP request
	 * @details Response header names are stored lower-cased and matched case-insensitively (see HttpHeaderMap).
	 *          The request body is sent for POST/PUT requests only (Content-Type defaults to
	 *          application/json when the caller did not set one).
	 *
	 * @param host The server host address (scheme://host[:port])
	 * @param mtd The HTTP method to use
	 * @param path The request path
	 * @param body The request body
	 * @param header Map of request headers
	 * @param query Map of query parameters
	 * @param timeoutSeconds Request timeout override; zero uses the client default
	 * @param sslConfig Per-request TLS configuration; nullptr applies no TLS options
	 * @return std::shared_ptr<HttpResponse> containing status code, response body and headers
	 */
	static std::shared_ptr<HttpResponse> request(const std::string &host, const web::http::method &mtd,
												 const std::string &path, const std::string &body,
												 std::map<std::string, std::string> header,
												 std::map<std::string, std::string> query, long timeoutSeconds = 0,
												 const ClientSSLConfig *sslConfig = nullptr);

private:
	/// Shared URL handling of both backends: validation, default port, request
	/// target (path plus encoded query) and Host header value.
	struct RequestTarget
	{
		std::string host;
		int port = 0;
		bool useSSL = false;
		std::string target;     // path plus percent-encoded query
		std::string hostHeader; // host[:port] for the Host header
	};
	static bool parseRequestTarget(const std::string &host, const std::string &path,
								   const std::map<std::string, std::string> &query, RequestTarget &out, std::string &error);
};
