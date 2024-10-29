#include "RestClient.h"
#include "Utility.h"

#include <fstream>
#include <mutex>

#include <curlpp/Easy.hpp>
#include <curlpp/Exception.hpp>
#include <curlpp/Infos.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/cURLpp.hpp>
#include <log4cpp/Priority.hh>
#include <openssl/ssl.h>

static const std::string HTTP_USER_AGENT_HEADER_NAME = "User-Agent";
static const std::string HTTP_USER_AGENT = "appmeshsdk/cpp";
ClientSSLConfig RestClient::m_sslConfig;
ClientSSLConfig::ClientSSLConfig()
	: m_ssl_version(CURL_SSLVERSION_LAST - 1), m_verify_client(false), m_verify_server(false)
{
	const static char fname[] = "ClientSSLConfig::ClientSSLConfig() ";

	// Get OpenSSL version at runtime
	const static unsigned long openssl_version = SSLeay();
	// Determine appropriate CURLOPT_SSLVERSION based on OpenSSL version
	if (openssl_version >= 0x10101000L)
		m_ssl_version = CURL_SSLVERSION_TLSv1_3; // TLSv1.3 supported
	else if (openssl_version >= 0x10100000L)
		m_ssl_version = CURL_SSLVERSION_TLSv1_2; // TLSv1.2 supported
	else
		LOG_WAR << fname << "OpenSSL version too old, consider upgrading.";
}

std::shared_ptr<CurlResponse>
RestClient::request(const std::string &host, const web::http::method &mtd, const std::string &path, nlohmann::json *body, std::map<std::string, std::string> header, std::map<std::string, std::string> query)
{
	// only initialize once
	static std::once_flag executeOnceFlag;
	std::call_once(executeOnceFlag, []()
				   { curlpp::initialize(CURL_GLOBAL_ALL); });

	auto url = (fs::path(host) / path).string();

	curlpp::Easy request;
	auto response = std::make_shared<CurlResponse>();

	// Set timeouts
	request.setOpt(new curlpp::Options::ConnectTimeout(10));
	request.setOpt(new curlpp::Options::Timeout(60));
	setSslConfig(request);

	// Set response stream
	std::ostringstream responseStream;
	curlpp::options::WriteStream ws(&responseStream);
	request.setOpt(ws);

	// Prepare headers
	std::list<std::string> headers;
	for (const auto &h : header)
		headers.push_back(std::string(h.first) + ": " + h.second);
	headers.push_back(std::string(HTTP_USER_AGENT_HEADER_NAME) + ": " + HTTP_USER_AGENT);

	// output headers
	std::map<std::string, std::string> outputHeaders;
	request.setOpt(curlpp::Options::HeaderFunction(
		[&outputHeaders](char *ptr, size_t size, size_t nitems)
		{
			std::string oneHeader;
			const auto incomingSize = size * nitems;
			oneHeader.append(ptr, incomingSize);
			if (incomingSize > 3)
			{
				auto kvPair = Utility::splitString(oneHeader, ":");
				if (kvPair.size() == 2)
					outputHeaders[Utility::stdStringTrim(kvPair[0])] = Utility::stdStringTrim(kvPair[1]);
				else
					LOG_DBG << "failed to parse response header: " << oneHeader;
			}
			return incomingSize;
		}));

	// Append query parameters to URL
	if (!query.empty())
	{
		url += "?";
		for (auto it = query.begin(); it != query.end(); ++it)
		{
			if (it != query.begin())
				url += "&";
			url += it->first + "=" + it->second;
		}
	}
	request.setOpt(new curlpp::Options::Url(url));

	// Set HTTP method and body if needed
	request.setOpt(new curlpp::options::CustomRequest(mtd));

	if (body)
	{
		std::istringstream strStream(body->dump());
		headers.push_back(std::string(web::http::header_names::content_type) + ": " + web::http::mime_types::application_json);
		if (mtd == web::http::methods::PUT || mtd == web::http::methods::POST)
		{
			// Set the data
			request.setOpt(new curlpp::options::PostFields(strStream.str()));
			// Set the size of the data
			request.setOpt(new curlpp::options::PostFieldSize(strStream.str().size()));
		}
		else
		{
			headers.push_back(std::string(web::http::header_names::content_length) + ": " + std::to_string(strStream.str().size()));
			request.setOpt(new curlpp::Options::ReadStream(&strStream));
		}
	}

	request.setOpt(new curlpp::Options::HttpHeader(headers));
	request.perform();

	// Fill response object
	response->status_code = curlpp::infos::ResponseCode::get(request);
	response->text = responseStream.str();
	response->header = std::move(outputHeaders);

	return response;
}

std::shared_ptr<CurlResponse>
RestClient::upload(const std::string &host, const std::string &path, const std::string file, std::map<std::string, std::string> header)
{
	const auto url = (fs::path(host) / path).string();

	curlpp::Easy request;
	auto response = std::make_shared<CurlResponse>();

	request.setOpt(new curlpp::Options::ConnectTimeout(10));
	request.setOpt(new curlpp::Options::Timeout(300));
	setSslConfig(request);

	request.setOpt(new curlpp::Options::Url(url));

	// Set response stream
	std::ostringstream responseStream;
	curlpp::options::WriteStream ws(&responseStream);
	request.setOpt(ws);

	// Prepare headers
	std::list<std::string> headers;
	for (const auto &h : header)
		headers.push_back(std::string(h.first) + ": " + h.second);
	request.setOpt(new curlpp::Options::HttpHeader(headers));

	// File upload setup
	curlpp::Forms form;
	std::ifstream fileStream(file, std::ios::in | std::ios::binary);
	if (!fileStream)
		throw std::invalid_argument("input file not exist");
	form.push_back(new curlpp::FormParts::File("file", file));
	form.push_back(new curlpp::FormParts::Content("filename", file));
	request.setOpt(new curlpp::options::HttpPost(form));

	request.perform();

	// Fill response object
	response->status_code = curlpp::infos::ResponseCode::get(request);
	response->text = responseStream.str();

	return response;
}

std::shared_ptr<CurlResponse>
RestClient::download(const std::string &host, const std::string &path, const std::string remoteFile, const std::string localFile, std::map<std::string, std::string> header)
{
	const auto url = (fs::path(host) / path).string();

	curlpp::Easy request;
	auto response = std::make_shared<CurlResponse>();

	request.setOpt(new curlpp::Options::ConnectTimeout(10));
	request.setOpt(new curlpp::Options::Timeout(300));
	setSslConfig(request);

	request.setOpt(new curlpp::Options::Url(url));

	// Prepare headers
	std::list<std::string> headers;
	for (const auto &h : header)
		headers.push_back(std::string(h.first) + ": " + h.second);
	request.setOpt(new curlpp::Options::HttpHeader(headers));

	// output headers
	std::map<std::string, std::string> outputHeaders;
	request.setOpt(curlpp::Options::HeaderFunction(
		[&outputHeaders](char *ptr, size_t size, size_t nitems)
		{
			std::string oneHeader;
			const auto incomingSize = size * nitems;
			oneHeader.append(ptr, incomingSize);
			if (incomingSize > 3)
			{
				auto kvPair = Utility::splitString(oneHeader, ":");
				if (kvPair.size() == 2)
					outputHeaders[Utility::stdStringTrim(kvPair[0])] = Utility::stdStringTrim(kvPair[1]);
				else
					LOG_DBG << "failed to parse response header: " << oneHeader;
			}
			return incomingSize;
		}));

	// Create output file stream for download
	std::ofstream outputFile(localFile, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!outputFile.is_open())
		throw std::invalid_argument("failed to write file to local");
	curlpp::options::WriteStream ws(&outputFile);
	request.setOpt(ws);

	request.perform();

	// Fill response object
	response->status_code = curlpp::infos::ResponseCode::get(request);
	response->header = std::move(outputHeaders);

	return response;
}

void RestClient::defaultSslConfiguration(const ClientSSLConfig &sslConfig)
{
	m_sslConfig = sslConfig;
}

void RestClient::setSslConfig(curlpp::Easy &request)
{
	// For HTTPS connections, omitting the version will prefer HTTP/2 but fall back to HTTP/1.1 if needed.
	// request.setOpt(new curlpp::Options::HttpVersion(CURL_HTTP_VERSION_2TLS));
	request.setOpt(new curlpp::Options::Verbose(log4cpp::Category::getRoot().getPriority() == log4cpp::Priority::DEBUG));
	request.setOpt(new curlpp::Options::SslVerifyPeer(m_sslConfig.m_verify_client || m_sslConfig.m_verify_server));
	request.setOpt(new curlpp::Options::SslVerifyHost(m_sslConfig.m_verify_server));
	request.setOpt(new curlpp::Options::SslVersion(m_sslConfig.m_ssl_version));
	if (m_sslConfig.m_verify_client && !m_sslConfig.m_certificate.empty() && !m_sslConfig.m_private_key.empty())
	{
		request.setOpt(new curlpp::Options::SslCert(m_sslConfig.m_certificate));
		request.setOpt(new curlpp::Options::SslKey(m_sslConfig.m_private_key));
		if (!m_sslConfig.m_private_key_passwd.empty())
			request.setOpt(new curlpp::Options::SslKeyPasswd(m_sslConfig.m_private_key_passwd));
	}
	if (m_sslConfig.m_verify_server && !m_sslConfig.m_ca_location.empty())
	{
		if (Utility::isDirExist(m_sslConfig.m_ca_location))
			request.setOpt(new curlpp::Options::CaPath(m_sslConfig.m_ca_location));
		else if (Utility::isFileExist(m_sslConfig.m_ca_location))
			request.setOpt(new curlpp::Options::CaInfo(m_sslConfig.m_ca_location));
	}
}
