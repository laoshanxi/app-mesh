#include "RestClient.h"
#include <cpr/cpr.h>

std::shared_ptr<cpr::Response> RestClient::request(const std::string url, const web::http::method &mtd, const std::string &path, nlohmann::json *body, std::map<std::string, std::string> header, std::map<std::string, std::string> query)
{
	// header
	cpr::Header cprHeader;
	for (const auto &h : header)
		cprHeader.insert({h.first, h.second});

	// query
	cpr::Parameters cprParam;
	for (const auto &q : query)
		cprParam.Add({q.first, q.second});

	cpr::SslOptions sslOpts = cpr::Ssl(cpr::ssl::VerifyHost{false}, cpr::ssl::VerifyPeer{false});
	cpr::Body cprBody;
	if (body)
	{
		cprBody = body->dump();
		cprHeader.insert({web::http::header_names::content_type, web::http::mime_types::application_json});
	}

	auto resp = std::make_shared<cpr::Response>();
	if (mtd == web::http::methods::GET)
	{
		*resp = cpr::Get(cpr::Url{url, path}, sslOpts, cprHeader, cprParam, cpr::Timeout{1000 * REST_REQUEST_TIMEOUT_SECONDS});
	}
	else if (mtd == web::http::methods::POST)
	{
		*resp = cpr::Post(cpr::Url{url, path}, sslOpts, cprHeader, cprParam, cprBody, cpr::Timeout{1000 * REST_REQUEST_TIMEOUT_SECONDS});
	}
	else if (mtd == web::http::methods::PUT)
	{
		*resp = cpr::Put(cpr::Url{url, path}, sslOpts, cprHeader, cprParam, cprBody, cpr::Timeout{1000 * REST_REQUEST_TIMEOUT_SECONDS});
	}
	else if (mtd == web::http::methods::DEL)
	{
		*resp = cpr::Delete(cpr::Url{url, path}, sslOpts, cprHeader, cprParam, cpr::Timeout{1000 * REST_REQUEST_TIMEOUT_SECONDS});
	}

	return resp;
}

std::shared_ptr<cpr::Response> RestClient::upload(const std::string url, const std::string &path, const std::string file, std::map<std::string, std::string> header)
{
	auto resp = std::make_shared<cpr::Response>();
	// header
	cpr::Header cprHeader;
	for (const auto &h : header)
		cprHeader.insert({h.first, h.second});

	cpr::SslOptions sslOpts = cpr::Ssl(cpr::ssl::VerifyHost{false}, cpr::ssl::VerifyPeer{false});
	cpr::Multipart cprMultipart{{"filename", boost::filesystem::path(file).filename().string()}, {"file", cpr::File(file)}};
	*resp = cpr::Post(cpr::Url{url, path}, sslOpts, cprHeader, cprMultipart, cpr::Timeout{1000 * REST_REQUEST_TIMEOUT_SECONDS * 10});
	return resp;
}

std::shared_ptr<cpr::Response> RestClient::download(const std::string url, const std::string &path, const std::string remoteFile, const std::string localFile, std::map<std::string, std::string> header)
{
	auto resp = std::make_shared<cpr::Response>();
	// header
	cpr::Header cprHeader;
	for (const auto &h : header)
		cprHeader.insert({h.first, h.second});

	cpr::SslOptions sslOpts = cpr::Ssl(cpr::ssl::VerifyHost{false}, cpr::ssl::VerifyPeer{false});
	std::ofstream stream(localFile, std::ios::binary | std::ios::trunc);
	*resp = cpr::Download(stream, sslOpts, cpr::Url{url, path}, cprHeader, cpr::Timeout{1000 * REST_REQUEST_TIMEOUT_SECONDS * 10});
	return resp;
}
