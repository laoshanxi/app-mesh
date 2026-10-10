// src/common/RestClient.cpp
// Backend-agnostic parts of the HTTP client facade. The request() transport
// lives in RestClientDrogon.cpp (C++17 tier) or RestClientLws.cpp (lower tiers).
#include <mutex>

#include "RestClient.h"
#include "UriParser.hpp"
#include "Utility.h"

void HttpResponse::raise_for_status()
{
	if (status_code < web::http::status_codes::OK || status_code >= web::http::status_codes::MultipleChoices)
		throw std::runtime_error("HTTP request failed with status code: " + std::to_string(status_code) + " response: " + text);
}

ClientSSLConfig RestClient::m_sslConfig;
std::mutex RestClient::m_sslMutex;

ClientSSLConfig::ClientSSLConfig()
	: m_verify_client(false), m_verify_server(false)
{
}

void ClientSSLConfig::ResolveAbsolutePaths(std::string workingHome)
{
	m_certificate = ResolveAbsolutePath(workingHome, m_certificate);
	m_private_key = ResolveAbsolutePath(workingHome, m_private_key);
	m_ca_location = ResolveAbsolutePath(workingHome, m_ca_location);
}

std::string ClientSSLConfig::ResolveAbsolutePath(const std::string &workingHome, std::string filePath)
{
	if (!workingHome.empty() && !filePath.empty() && !Utility::startWith(filePath, workingHome))
	{
		return (fs::path(workingHome) / filePath).lexically_normal().string();
	}
	return filePath;
}

std::string RestClient::joinUrl(const std::string &host, const std::string &path)
{
	if (path.empty())
		return host;
	std::string url = host;
	if (!url.empty() && url.back() != '/' && path.front() != '/')
		url += '/';
	return url + path;
}

bool RestClient::parseRequestTarget(const std::string &host, const std::string &path,
	const std::map<std::string, std::string> &query, RequestTarget &out, std::string &error)
{
	const Uri uri = Uri::parse(host);
	out.useSSL = uri.scheme == "https";
	if (uri.host.empty() || (!uri.scheme.empty() && uri.scheme != "http" && !out.useSSL))
	{
		error = "unsupported or invalid host URL: " + host;
		return false;
	}
	out.host = uri.host;
	out.port = uri.port >= 0 ? uri.port : (out.useSSL ? 443 : 80);

	// Request target: path plus percent-encoded query string.
	out.target = path.empty() ? std::string("/") : path;
	if (out.target.front() != '/')
		out.target.insert(out.target.begin(), '/');
	if (!query.empty())
	{
		out.target += '?';
		bool first = true;
		for (const auto &q : query)
		{
			if (!first)
				out.target += '&';
			out.target += Utility::encodeURIComponent(q.first) + "=" + Utility::encodeURIComponent(q.second);
			first = false;
		}
	}

	out.hostHeader = uri.host;
	if ((out.useSSL && out.port != 443) || (!out.useSSL && out.port != 80))
		out.hostHeader += ":" + std::to_string(out.port);
	return true;
}

ClientSSLConfig RestClient::resolveSslConfig(const ClientSSLConfig *sslConfig)
{
	if (sslConfig != nullptr)
		return *sslConfig;
	std::lock_guard<std::mutex> lock(m_sslMutex);
	return m_sslConfig;
}

void RestClient::defaultSslConfiguration(const ClientSSLConfig &sslConfig)
{
	std::lock_guard<std::mutex> lock(m_sslMutex);
	m_sslConfig = sslConfig;
}
