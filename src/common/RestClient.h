#pragma once

#include <map>
#include <memory>
#include <mutex>

#include "Utility.h"
#include <curl/curl.h>

struct CurlResponse
{
	long status_code = 0;
	std::string text;
	std::map<std::string, std::string> header;
	void raise_for_status();
};

struct ClientSSLConfig
{
	ClientSSLConfig();
	void AbsConfigPath(std::string workingHome);
	static std::string HomeDir(const std::string &workingHome, std::string filePath);
	unsigned long m_ssl_version;
	bool m_verify_client;			  // client certificate verification
	bool m_verify_server;			  // server's certificate matches the host name
	std::string m_certificate;		  // certificate file (PEM format)
	std::string m_private_key;		  // private key file (PEM format)
	std::string m_private_key_passwd; // private key password
	std::string m_ca_location;		  // trusted CA file or directory
};

class RestClient
{
public:
	/**
	 * Make an HTTP request. Note: The response headers are returned in lower case.
	 * @param host Server host address.
	 * @param mtd HTTP method.
	 * @param path Request path.
	 * @param body Request body.
	 * @param header Request headers.
	 * @param query Query parameters.
	 * @return Response result.
	 */
	static std::shared_ptr<CurlResponse> request(
		const std::string &host,
		const web::http::method &mtd,
		const std::string &path,
		const std::string &body,
		std::map<std::string, std::string> header,
		std::map<std::string, std::string> query);

	/**
	 * Upload a file.
	 * @param host Server host address.
	 * @param path Upload path.
	 * @param file File path.
	 * @param header Request headers.
	 * @return Response result.
	 */
	static std::shared_ptr<CurlResponse> upload(
		const std::string &host,
		const std::string &path,
		const std::string &file,
		std::map<std::string, std::string> header);

	/**
	 * Download a file.
	 * @param host Server host address.
	 * @param path Download path.
	 * @param remoteFile Remote file path.
	 * @param localFile Local file path.
	 * @param header Request headers.
	 * @return Response result.
	 */
	static std::shared_ptr<CurlResponse> download(
		const std::string &host,
		const std::string &path,
		const std::string &remoteFile,
		const std::string &localFile,
		std::map<std::string, std::string> header);

	/**
	 * Set default SSL configuration.
	 * @param sslConfig SSL configuration.
	 */
	static void defaultSslConfiguration(const ClientSSLConfig &sslConfig);

private:
	/**
	 * Configure SSL.
	 * @param curl CURL handle.
	 */
	static void setSslConfig(CURL *curl);

private:
	static ClientSSLConfig m_sslConfig;
};

namespace curlpp
{
	std::string unescape(const std::string &url);
}