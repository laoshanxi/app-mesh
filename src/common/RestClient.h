#pragma once

#include <map>
#include <memory>
#include <mutex>

#include "Utility.h"

namespace curlpp
{
	class Easy;
};

struct CurlResponse
{
	long status_code;
	std::string text;
	std::map<std::string, std::string> header;
};

struct ClientSSLConfig
{
	ClientSSLConfig();
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
	static std::shared_ptr<CurlResponse> request(const std::string host, const web::http::method &mtd, const std::string &path, nlohmann::json *body, std::map<std::string, std::string> header, std::map<std::string, std::string> query);
	static std::shared_ptr<CurlResponse> upload(const std::string host, const std::string &path, const std::string file, std::map<std::string, std::string> header);
	static std::shared_ptr<CurlResponse> download(const std::string host, const std::string &path, const std::string remoteFile, const std::string localFile, std::map<std::string, std::string> header);

	static void defaultSslConfiguration(const ClientSSLConfig &sslConfig);

private:
	static void setSslConfig(curlpp::Easy &request);

private:
	static ClientSSLConfig m_sslConfig;
};
