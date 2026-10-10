// src/common/RestClient.h
#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "HttpHeaderMap.h"
#include "Utility.h"

/// @brief HTTP response data structure
struct HttpResponse
{
	long status_code = 0;
	std::string text;
	HttpHeaderMap header; // case-insensitive; keys normalized to lower-case
	void raise_for_status();
};

/// @brief TLS configuration structure for the HTTP client
struct ClientSSLConfig
{
	ClientSSLConfig();
	void ResolveAbsolutePaths(std::string workingHome);
	// Convert relative paths to absolute paths if necessary
	static std::string ResolveAbsolutePath(const std::string &workingHome, std::string filePath);
	bool m_verify_client;			  // present a client certificate (mTLS)
	bool m_verify_server;			  // verify the server certificate and host name
	std::string m_certificate;		  // certificate file (PEM format)
	std::string m_private_key;		  // private key file (PEM format)
	std::string m_private_key_passwd; // private key password
	std::string m_ca_location;		  // trusted CA file or directory
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
	 * @param sslConfig Per-request TLS configuration; nullptr uses the process-wide default
	 * @return std::shared_ptr<HttpResponse> containing status code, response body and headers
	 */
	static std::shared_ptr<HttpResponse> request(
		const std::string &host,
		const web::http::method &mtd,
		const std::string &path,
		const std::string &body,
		std::map<std::string, std::string> header,
		std::map<std::string, std::string> query,
		long timeoutSeconds = 0,
		const ClientSSLConfig *sslConfig = nullptr);

	/**
	 * @brief Sets the default TLS configuration for requests without an explicit one
	 * @param sslConfig TLS configuration object containing certificates and verification options
	 */
	static void defaultSslConfiguration(const ClientSSLConfig &sslConfig);

private:
	// A URL path joins with '/', never the native separator: fs::path would
	// render http://host:port\path on Windows.
	static std::string joinUrl(const std::string &host, const std::string &path);

	// The explicit per-request config wins; otherwise the process-wide default is used.
	static ClientSSLConfig resolveSslConfig(const ClientSSLConfig *sslConfig);

	/// Shared URL handling of both backends: validation, default port, request
	/// target (path plus encoded query) and Host header value.
	struct RequestTarget
	{
		std::string host;
		int port = 0;
		bool useSSL = false;
		std::string target;       // path plus percent-encoded query
		std::string hostHeader;   // host[:port] for the Host header
	};
	static bool parseRequestTarget(const std::string &host, const std::string &path,
		const std::map<std::string, std::string> &query, RequestTarget &out, std::string &error);

private:
	static ClientSSLConfig m_sslConfig;
	static std::mutex m_sslMutex;
};
