#include "RestClient.h"
#include "Utility.h"

#include <mutex>

#include <curlpp/Easy.hpp>
#include <curlpp/Exception.hpp>
#include <curlpp/Infos.hpp>
#include <curlpp/Options.hpp>
#include <curlpp/cURLpp.hpp>

std::mutex RestClient::m_restLock;
ClientSSLConfig RestClient::m_sslConfig;
ClientSSLConfig::ClientSSLConfig()
	: m_ssl_version(CURL_SSLVERSION_TLSv1_2), m_verify_peer(true), m_verify_host(true)
{
}

std::shared_ptr<CurlResponse>
RestClient::request(const std::string host, const web::http::method &mtd, const std::string &path, nlohmann::json *body, std::map<std::string, std::string> header, std::map<std::string, std::string> query)
{
	std::lock_guard<std::mutex> guard(m_restLock);
	auto url = (fs::path(host) / path).string();

	curlpp::Cleanup cleaner;
	curlpp::Easy request;
	auto response = std::make_shared<CurlResponse>();

	// timeout
	request.setOpt(new curlpp::Options::ConnectTimeout(10));
	request.setOpt(new curlpp::Options::Timeout(60));
	request.setOpt(new curlpp::Options::Verbose(false));
	applySslConfiguration(request);

	// Save response body to a stringstream
	std::ostringstream responseStream;
	curlpp::options::WriteStream ws(&responseStream);
	request.setOpt(ws);

	// input headers
	std::list<std::string> headers;
	for (const auto &h : header)
		headers.push_back(std::string(h.first) + ": " + h.second);

	// output headers
	std::map<std::string, std::string> outputHeaders;
	request.setOpt(curlpp::Options::HeaderFunction(
		[&outputHeaders](char *ptr, size_t size, size_t nitems)
		{
			std::string oneHeader;
			const auto incomingSize = size * nitems;
			oneHeader.append(ptr, incomingSize);

			auto kvPair = Utility::splitString(oneHeader, ":");
			if (kvPair.size() == 2)
				outputHeaders[Utility::stdStringTrim(kvPair[0])] = Utility::stdStringTrim(kvPair[1]);
			else
				LOG_WAR << "failed to parse response header: " << oneHeader;
			return incomingSize;
		}));

	// querys
	int queryIndex = 0;
	for (const auto &q : query)
	{
		if (queryIndex == 0)
			url += "?";
		else
			url += "&";
		url += (std::string(q.first) + "=" + q.second);
		queryIndex++;
	}
	request.setOpt(new curlpp::Options::Url(url));

	// HTTP method
	request.setOpt(new curlpp::options::CustomRequest(mtd));

	if (body)
	{
		std::istringstream strStream(body->dump());
		if (mtd == web::http::methods::PUT || mtd == web::http::methods::POST)
		{
			// Set the data
			request.setOpt(new curlpp::options::PostFields(strStream.str()));
			// Set the size of the data
			request.setOpt(new curlpp::options::PostFieldSize(strStream.str().size()));
		}
		else
		{
			headers.push_back(std::string(web::http::header_names::content_type) + ": " + web::http::mime_types::application_json);
			headers.push_back(std::string(web::http::header_names::content_length) + ": " + std::to_string(strStream.str().size()));
			request.setOpt(new curlpp::Options::ReadStream(&strStream));
		}
	}

	request.setOpt(new curlpp::Options::HttpHeader(headers));
	request.perform();

	// Get the HTTP response code
	response->status_code = curlpp::infos::ResponseCode::get(request);
	response->text = responseStream.str();
	response->header = outputHeaders;

	return response;
}

std::shared_ptr<CurlResponse> RestClient::upload(const std::string host, const std::string &path, const std::string file, std::map<std::string, std::string> header)
{
	std::lock_guard<std::mutex> guard(m_restLock);
	auto url = (fs::path(host) / path).string();

	curlpp::Cleanup cleaner;
	curlpp::Easy request;
	auto response = std::make_shared<CurlResponse>();

	request.setOpt(new curlpp::Options::ConnectTimeout(10));
	request.setOpt(new curlpp::Options::Timeout(300));
	request.setOpt(new curlpp::Options::Verbose(false));
	applySslConfiguration(request);

	request.setOpt(new curlpp::Options::Url(url));

	// Redirect response body to a stringstream
	std::ostringstream responseStream;
	curlpp::options::WriteStream ws(&responseStream);
	request.setOpt(ws);

	// input headers
	std::list<std::string> headers;
	for (const auto &h : header)
		headers.push_back(std::string(h.first) + ": " + h.second);
	request.setOpt(new curlpp::Options::HttpHeader(headers));

	curlpp::Forms form;
	std::ifstream fileStream(file, std::ios::in | std::ios::binary);
	if (!fileStream)
		throw std::invalid_argument("input file not exist");
	form.push_back(new curlpp::FormParts::File("file", file));
	form.push_back(new curlpp::FormParts::Content("filename", file));
	request.setOpt(new curlpp::options::HttpPost(form));

	request.perform();

	// Get the HTTP response code
	response->status_code = curlpp::infos::ResponseCode::get(request);
	response->text = responseStream.str();

	return response;
}

std::shared_ptr<CurlResponse> RestClient::download(const std::string host, const std::string &path, const std::string remoteFile, const std::string localFile, std::map<std::string, std::string> header)
{
	std::lock_guard<std::mutex> guard(m_restLock);
	auto url = (fs::path(host) / path).string();

	curlpp::Cleanup cleaner;
	curlpp::Easy request;
	auto response = std::make_shared<CurlResponse>();

	request.setOpt(new curlpp::Options::ConnectTimeout(10));
	request.setOpt(new curlpp::Options::Timeout(300));
	request.setOpt(new curlpp::Options::Verbose(false));
	applySslConfiguration(request);

	request.setOpt(new curlpp::Options::Url(url));

	// input headers
	std::list<std::string> headers;
	for (const auto &h : header)
		headers.push_back(std::string(h.first) + ": " + h.second);
	request.setOpt(new curlpp::Options::HttpHeader(headers));

	// Create a file stream to write the downloaded content
	std::ofstream outputFile(localFile, std::ios::out | std::ios::binary | std::ios::trunc);
	if (!outputFile.is_open())
		throw std::invalid_argument("failed to write file to local");
	curlpp::options::WriteStream ws(&outputFile);
	request.setOpt(ws);

	request.perform();

	// Get the HTTP response code
	response->status_code = curlpp::infos::ResponseCode::get(request);

	return response;
}

void RestClient::defaultSslConfiguration(const ClientSSLConfig &sslConfig)
{
	std::lock_guard<std::mutex> guard(m_restLock);
	m_sslConfig = sslConfig;
}

void RestClient::applySslConfiguration(curlpp::Easy &request)
{
	request.setOpt(new curlpp::Options::SslVerifyPeer(m_sslConfig.m_verify_peer));
	request.setOpt(new curlpp::Options::SslVerifyHost(m_sslConfig.m_verify_host));
	request.setOpt(new curlpp::Options::SslVersion(m_sslConfig.m_ssl_version));
	if (!m_sslConfig.m_certificate.empty() && !m_sslConfig.m_private_key.empty())
	{
		request.setOpt(new curlpp::Options::SslCert(m_sslConfig.m_certificate));
		request.setOpt(new curlpp::Options::SslKey(m_sslConfig.m_private_key));
		if (!m_sslConfig.m_private_key_passwd.empty())
			request.setOpt(new curlpp::Options::SslKeyPasswd(m_sslConfig.m_private_key_passwd));
	}
	if (!m_sslConfig.m_ca_location.empty())
		if (Utility::isDirExist(m_sslConfig.m_ca_location))
			request.setOpt(new curlpp::Options::CaPath(m_sslConfig.m_ca_location));
		else if (Utility::isFileExist(m_sslConfig.m_ca_location))
			request.setOpt(new curlpp::Options::CaInfo(m_sslConfig.m_ca_location));
}
