#pragma once

#include <map>
#include <memory>
#include <mutex>

#include "Utility.h"
#include <curl/curl.h>

/// @brief CURL response data structure
struct CurlResponse
{
	long status_code = 0;
	std::string text;
	std::map<std::string, std::string> header;
	void raise_for_status();
};

/// @brief SSL configuration structure for CURL client
struct ClientSSLConfig
{
	ClientSSLConfig();
	void ResolveAbsolutePaths(std::string workingHome);
	// Convert relative paths to absolute paths if necessary
	static std::string ResolveAbsolutePath(const std::string &workingHome, std::string filePath);
	unsigned long m_ssl_version;
	bool m_verify_client;			  // client certificate verification
	bool m_verify_server;			  // server's certificate matches the host name
	std::string m_certificate;		  // certificate file (PEM format)
	std::string m_private_key;		  // private key file (PEM format)
	std::string m_private_key_passwd; // private key password
	std::string m_ca_location;		  // trusted CA file or directory
};

/// @brief Session configuration for managing cookies
struct SessionConfig
{
	bool enable_session = false;	// Enable session management
	bool use_memory_cookies = true; // Use memory cookies (true) or file-based (false)
	std::string cookie_file;		// Cookie file path (for file-based storage)

	SessionConfig() = default;

	// Factory methods for convenience
	static SessionConfig MemorySession()
	{
		SessionConfig config;
		config.enable_session = true;
		config.use_memory_cookies = true;
		return config;
	}

	static SessionConfig FileSession(const std::string &cookieFilePath)
	{
		SessionConfig config;
		config.enable_session = true;
		config.use_memory_cookies = false;
		config.cookie_file = cookieFilePath;
		return config;
	}
};

/// @brief Cookie structure
struct Cookie
{
	std::string domain;
	bool include_subdomains = false;
	std::string path;
	bool secure = false;
	long long expiration = 0; // Unix timestamp, 0 means session cookie
	std::string name;
	std::string value;
	bool httponly = false;
};

class RestClient
{
public:
	/**
	 * @brief Performs an HTTP request
	 * @details The response headers are returned in lowercase
	 *
	 * @param host The server host address
	 * @param mtd The HTTP method to use
	 * @param path The request path
	 * @param body The request body
	 * @param header Map of request headers
	 * @param query Map of query parameters
	 * @param formData Optional form data parameters (sent as application/x-www-form-urlencoded)
	 * @return std::shared_ptr<CurlResponse> containing status code, response body and headers
	 */
	static std::shared_ptr<CurlResponse> request(
		const std::string &host,
		const web::http::method &mtd,
		const std::string &path,
		const std::string &body,
		std::map<std::string, std::string> header,
		std::map<std::string, std::string> query,
		std::map<std::string, std::string> formData = {});

	/**
	 * @brief Uploads a file using multipart/form-data
	 *
	 * @param host The server host address
	 * @param path The upload endpoint path
	 * @param file The path to the local file to upload
	 * @param header Map of request headers
	 * @param fieldName The form field name for the file (defaults to "file")
	 * @return std::shared_ptr<CurlResponse> containing upload response
	 */
	static std::shared_ptr<CurlResponse> upload(
		const std::string &host,
		const std::string &path,
		const std::string &file,
		std::map<std::string, std::string> header,
		const std::string &fieldName = "file");

	/**
	 * @brief Downloads a file from remote server
	 *
	 * @param host The server host address
	 * @param path The download endpoint path
	 * @param remoteFile The path/name of file on remote server
	 * @param localFile The path where to save the downloaded file
	 * @param header Map of request headers
	 * @return std::shared_ptr<CurlResponse> containing download response
	 */
	static std::shared_ptr<CurlResponse> download(
		const std::string &host,
		const std::string &path,
		const std::string &remoteFile,
		const std::string &localFile,
		std::map<std::string, std::string> header);

	/**
	 * @brief Sets the default SSL configuration for all requests
	 * @param sslConfig SSL configuration object containing certificates and verification options
	 */
	static void defaultSslConfiguration(const ClientSSLConfig &sslConfig);

	/**
	 * @brief Sets the session configuration for cookie management
	 * @param sessionConfig Session configuration object
	 */
	static void setSessionConfiguration(const SessionConfig &sessionConfig);

	/**
	 * @brief Gets current session configuration
	 * @return Current session configuration
	 */
	static SessionConfig getSessionConfiguration();

	/**
	 * @brief Clears all session cookies
	 * @details Clears memory cookies or deletes cookie file depending on configuration
	 */
	static void clearSession();

	/**
	 * @brief Gets a specific cookie value by name
	 * @param cookieName The name of the cookie to retrieve
	 * @return The cookie value, or empty string if not found
	 */
	static std::string getCookie(const std::string &cookieName);

	/**
	 * @brief Gets all cookies in the current session
	 * @return Map of cookie names to Cookie structures
	 */
	static std::map<std::string, Cookie> getAllCookies();

	/**
	 * @brief Gets a specific cookie by name with full details
	 * @param cookieName The name of the cookie to retrieve
	 * @param cookie Output parameter to store the cookie details
	 * @return true if cookie was found, false otherwise
	 */
	static bool getCookieDetails(const std::string &cookieName, Cookie &cookie);

private:
	/**
	 * @brief Configures SSL parameters for a CURL handle
	 * @param curl The CURL handle to configure
	 */
	static void setSslConfig(CURL *curl);

	/**
	 * @brief Configures session/cookie parameters for a CURL handle
	 * @param curl The CURL handle to configure
	 */
	static void setSessionConfig(CURL *curl);

	/**
	 * @brief URL encodes a string value using CURL
	 * @param curl The CURL handle to use for encoding
	 * @param value The string to encode
	 * @return The URL encoded string
	 */
	static const std::string urlEncode(CURL *curl, const std::string &value);

	/**
	 * @brief Parses a Netscape cookie format line
	 * @param line Cookie line in Netscape format
	 * @param cookie Output parameter to store parsed cookie
	 * @return true if parsing succeeded, false otherwise
	 */
	static bool parseNetscapeCookie(const std::string &line, Cookie &cookie);

	/**
	 * @brief Reads cookies from memory storage
	 * @return Map of cookie names to Cookie structures
	 */
	static std::map<std::string, Cookie> readCookiesFromMemory();

	/**
	 * @brief Reads cookies from file storage
	 * @return Map of cookie names to Cookie structures
	 */
	static std::map<std::string, Cookie> readCookiesFromFile();

private:
	static ClientSSLConfig m_sslConfig;
	static SessionConfig m_sessionConfig;
	static std::mutex m_sessionMutex;
	static std::string m_memoryCookies; // Store cookies in memory as string
};

namespace curlpp
{
	std::string unescape(const std::string &url);
}
