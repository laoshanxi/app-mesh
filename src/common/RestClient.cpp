#include <curl/curl.h>
#include <fstream>
#include <log4cpp/Priority.hh>
#include <mutex>
#include <openssl/ssl.h>

#include "FileWrapper.hpp"
#include "RestClient.h"
#include "Utility.h"

constexpr const char *HTTP_USER_AGENT_HEADER = "User-Agent";
constexpr const char *HTTP_USER_AGENT = "appmeshsdk/cpp";
constexpr long CONNECT_TIMEOUT_SECONDS = 10L;
constexpr long REQUEST_TIMEOUT_SECONDS = 200L;

void CurlResponse::raise_for_status()
{
	if (status_code < web::http::status_codes::OK || status_code >= web::http::status_codes::MultipleChoices)
		throw std::runtime_error("HTTP request failed with status code: " + std::to_string(status_code) + " response: " + text);
}

// RAII wrapper for CURL cleanup
class CurlHandle
{
public:
	CurlHandle() : curl(curl_easy_init())
	{
		curl_easy_setopt(curl, CURLOPT_NOPROXY, "*"); // Disable proxy for all requests
	}
	~CurlHandle()
	{
		if (curl)
			curl_easy_cleanup(curl);
	}
	operator CURL *() { return curl; }
	CURL *get() { return curl; }
	bool isValid() const { return curl != nullptr; }

private:
	CURL *curl;
};

class CurlForm
{
public:
	CurlForm(CURL *curl_handle)
	{
		mime = curl_mime_init(curl_handle);
	}

	// Non-copyable
	CurlForm(const CurlForm &) = delete;
	CurlForm &operator=(const CurlForm &) = delete;

	~CurlForm()
	{
		if (mime)
			curl_mime_free(mime);
	}

	// Add form fields to the multipart form
	void addFile(std::string field_name, std::string file_path)
	{
		auto part = curl_mime_addpart(mime);
		curl_mime_name(part, field_name.data());
		curl_mime_filedata(part, file_path.data());
	}

	// Add additional form fields (non-file data)
	void addField(std::string name, std::string value)
	{
		auto part = curl_mime_addpart(mime);
		curl_mime_name(part, name.data());
		curl_mime_data(part, value.data(), CURL_ZERO_TERMINATED);
	}

	curl_mime *getMime() const noexcept
	{
		return mime;
	}

private:
	curl_mime *mime = nullptr;
};

// RAII wrapper for curl_slist
class CurlHeaderList
{
public:
	~CurlHeaderList()
	{
		if (list)
			curl_slist_free_all(list);
	}
	void append(const std::string &header)
	{
		list = curl_slist_append(list, header.c_str());
	}
	struct curl_slist *get() { return list; }

private:
	struct curl_slist *list = nullptr;
};

class CurlGlobalInitializer
{
public:
	CurlGlobalInitializer()
	{
		curl_global_init(CURL_GLOBAL_ALL);
	}

	~CurlGlobalInitializer()
	{
		curl_global_cleanup();
	}

	static CurlGlobalInitializer &instance()
	{
		static CurlGlobalInitializer init;
		return init;
	}
};

// Response body write callback
size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userParam)
{
	const size_t total_size = size * nmemb;
	userParam->append(static_cast<char *>(contents), total_size);
	return total_size;
}

// Header callback to parse headers
size_t HeaderCallback(char *buffer, size_t size, size_t nitems, std::map<std::string, std::string> *userHeader)
{
	const std::string header(buffer, size * nitems);
	// Skip empty lines and HTTP status line
	if (header.find(':') != std::string::npos && userHeader != nullptr)
	{
		auto pair = Utility::splitString(header, ":");
		if (pair.size() == 2)
		{
			auto key = Utility::stdStringTrim(pair[0]);
			auto value = Utility::stdStringTrim(pair[1]);
			(*userHeader)[key] = value;
		}
	}
	return size * nitems;
}

ClientSSLConfig RestClient::m_sslConfig;

ClientSSLConfig::ClientSSLConfig()
	: m_ssl_version(CURL_SSLVERSION_TLSv1_2), m_verify_client(false), m_verify_server(false)
{
	if (SSLeay() >= 0x10101000L)
	{
		m_ssl_version = CURL_SSLVERSION_TLSv1_3;
	}

#if defined(_WIN32)
	// Force TLS 1.2 on Windows to avoid compatibility issues
	m_ssl_version = CURL_SSLVERSION_TLSv1_2;
#endif
}

void ClientSSLConfig::ResolveAbsolutePaths(std::string workingHome)
{
	m_certificate = ResolveAbsolutePath(workingHome, m_certificate);
	m_private_key = ResolveAbsolutePath(workingHome, m_private_key);
	m_ca_location = ResolveAbsolutePath(workingHome, m_ca_location);
}

std::string ClientSSLConfig::ResolveAbsolutePath(const std::string &workingHome, std::string filePath)
{
	if (!workingHome.empty())
	{
		return (fs::path(workingHome) / filePath).lexically_normal().string();
	}
	return filePath;
}

std::shared_ptr<CurlResponse> RestClient::request(
	const std::string &host,
	const web::http::method &mtd,
	const std::string &path,
	const std::string &body,
	std::map<std::string, std::string> header,
	std::map<std::string, std::string> query,
	std::map<std::string, std::string> formData)
{
	CurlGlobalInitializer::instance();

	auto response = std::make_shared<CurlResponse>();
	CurlHandle curl;
	if (!curl.isValid())
	{
		response->text = "Failed to initialize CURL handle";
		return response;
	}

	// Build URL with query parameters
	auto url = (fs::path(host) / path).string();
	if (!query.empty())
	{
		url += "?";
		for (const auto &q : query)
		{
			url += url.back() == '?' ? "" : "&";
			url += urlEncode(curl, q.first) + "=" + urlEncode(curl, q.second);
		}
	}

	// Setup headers
	CurlHeaderList headers;
	headers.append(std::string(HTTP_USER_AGENT_HEADER) + ": " + HTTP_USER_AGENT);
	for (const auto &h : header)
	{
		headers.append(h.first + ": " + h.second);
	}

	// Configure CURL options
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECONDS);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, REQUEST_TIMEOUT_SECONDS);
	curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, mtd.c_str());
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response->text);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response->header);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L); // Disable signals for multi-threaded applications

	// Handle form data if provided (takes precedence over body)
	std::string formString;
	if (!formData.empty() && (mtd == web::http::methods::POST || mtd == web::http::methods::PUT))
	{
		bool first = true;
		for (const auto &field : formData)
		{
			if (!first)
				formString += "&";
			formString += urlEncode(curl, field.first) + "=" + urlEncode(curl, field.second);
			first = false;
		}

		// Set the Content-Type: application/x-www-form-urlencoded
		headers.append(std::string(web::http::header_names::content_type) + ": " + web::http::mime_types::application_x_www_form_urlencoded);

		// Set the form data as POST fields
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, formString.c_str());
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, formString.size());
	}
	// Handle JSON body if no form data is provided
	else if (!body.empty())
	{
		// Add Content-Type header for JSON
		headers.append(std::string(web::http::header_names::content_type) + ": " + web::http::mime_types::application_json);

		if (mtd == web::http::methods::PUT || mtd == web::http::methods::POST)
		{
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, body.size());
		}
	}

	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
	setSslConfig(curl);

	// Perform the request
	CURLcode result = curl_easy_perform(curl);
	if (result != CURLE_OK)
	{
		response->text = curl_easy_strerror(result);
		LOG_ERR << "Error in CURL request: " << response->text << " for URL: " << url;
	}
	else
	{
		// Get the HTTP response code
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code);
	}
	return response;
}

std::shared_ptr<CurlResponse> RestClient::upload(
	const std::string &host,
	const std::string &path,
	const std::string &file,
	std::map<std::string, std::string> header,
	const std::string &fieldName)
{
	CurlGlobalInitializer::instance();

	auto response = std::make_shared<CurlResponse>();

	if (!Utility::isFileExist(file))
	{
		response->text = "File does not exist: " + file;
		return response;
	}

	CurlHandle curl;
	if (!curl.isValid())
	{
		response->text = "Failed to initialize CURL handle";
		return response;
	}

	// Setup headers
	CurlHeaderList headers;
	headers.append(std::string(HTTP_USER_AGENT_HEADER) + ": " + HTTP_USER_AGENT);
	for (const auto &h : header)
	{
		headers.append(h.first + ": " + h.second);
	}

	// Create a multipart form
	CurlForm form(curl);
	form.addFile(fieldName, file);

	// Configure CURL options
	const std::string url = (fs::path(host) / path).string();
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
	curl_easy_setopt(curl, CURLOPT_MIMEPOST, form.getMime()); // Use the MIME API
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECONDS);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, REQUEST_TIMEOUT_SECONDS * 5);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	// Setup the response handling
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response->text);
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response->header);

	// SSL configuration
	setSslConfig(curl);

	// Perform the request
	CURLcode result = curl_easy_perform(curl);
	if (result != CURLE_OK)
	{
		response->text = curl_easy_strerror(result);
		LOG_ERR << "Error in CURL request: " << response->text << " for URL: " << url << " on upload file: " << file;
	}
	else
	{
		// Get the HTTP response code
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code);
	}
	return response;
}

std::shared_ptr<CurlResponse> RestClient::download(
	const std::string &host,
	const std::string &path,
	const std::string &remoteFile,
	const std::string &localFile,
	std::map<std::string, std::string> header)
{
	CurlGlobalInitializer::instance();

	auto response = std::make_shared<CurlResponse>();
	CurlHandle curl;

	if (!curl.isValid())
	{
		response->text = "Failed to initialize CURL handle";
		return response;
	}

	// Open the file for writing
	FileWrapper output_file(localFile, "wb");

	// Setup headers
	CurlHeaderList headers;
	headers.append(std::string(HTTP_USER_AGENT_HEADER) + ": " + HTTP_USER_AGENT);
	for (const auto &h : header)
	{
		headers.append(h.first + ": " + h.second);
	}

	// Configure CURL options
	const std::string url = (fs::path(host) / path).string();
	curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers.get());
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, CONNECT_TIMEOUT_SECONDS);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, REQUEST_TIMEOUT_SECONDS * 5);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

	// Setup the write function and user data
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
					 [](void *ptr, size_t size, size_t nmemb, void *userdata) -> size_t
					 {
						 FILE *file = static_cast<FILE *>(userdata);
						 size_t total_size = size * nmemb;
						 size_t written = fwrite(ptr, 1, total_size, file);
						 if (written != total_size)
						 {
							 return 0; // Signal CURL to abort if the write failed
						 }
						 return written;
					 });
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, output_file.get());

	// Setup the header callback
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &response->header);

	// SSL configuration
	setSslConfig(curl);

	// Perform the request
	CURLcode result = curl_easy_perform(curl);
	if (result != CURLE_OK)
	{
		response->text = curl_easy_strerror(result);
		LOG_ERR << "Error in CURL request: " << response->text << " for URL: " << url << " on download file: " << remoteFile;
	}
	else
	{
		// Get the HTTP response code
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response->status_code);
	}
	return response;
}

void RestClient::defaultSslConfiguration(const ClientSSLConfig &sslConfig)
{
	m_sslConfig = sslConfig;
}

void RestClient::setSslConfig(CURL *curl)
{
	curl_easy_setopt(curl, CURLOPT_VERBOSE, log4cpp::Category::getRoot().getPriority() == log4cpp::Priority::DEBUG);

	const bool verify = m_sslConfig.m_verify_client || m_sslConfig.m_verify_server;
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, verify);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, m_sslConfig.m_verify_server ? 2L : 0L);
	curl_easy_setopt(curl, CURLOPT_SSLVERSION, m_sslConfig.m_ssl_version);

#if defined(_WIN32)
	// Disable Windows certificate store
	curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NATIVE_CA);
	curl_easy_setopt(curl, CURLOPT_SSL_OPTIONS, CURLSSLOPT_NO_REVOKE);
#endif

	// Client certificate configuration
	if (m_sslConfig.m_verify_client &&
		!m_sslConfig.m_certificate.empty() &&
		!m_sslConfig.m_private_key.empty())
	{
		curl_easy_setopt(curl, CURLOPT_SSLCERT, m_sslConfig.m_certificate.c_str());
		curl_easy_setopt(curl, CURLOPT_SSLCERTTYPE, "PEM");
		curl_easy_setopt(curl, CURLOPT_SSLKEY, m_sslConfig.m_private_key.c_str());
		curl_easy_setopt(curl, CURLOPT_SSLKEYTYPE, "PEM");

		if (!m_sslConfig.m_private_key_passwd.empty())
		{
			curl_easy_setopt(curl, CURLOPT_KEYPASSWD, m_sslConfig.m_private_key_passwd.c_str());
		}
	}

	// Server verification configuration
	if (m_sslConfig.m_verify_server && !m_sslConfig.m_ca_location.empty())
	{
		if (Utility::isDirExist(m_sslConfig.m_ca_location))
		{
			curl_easy_setopt(curl, CURLOPT_CAPATH, m_sslConfig.m_ca_location.c_str());
		}
		else if (Utility::isFileExist(m_sslConfig.m_ca_location))
		{
			curl_easy_setopt(curl, CURLOPT_CAINFO, m_sslConfig.m_ca_location.c_str());
		}
	}
}

const std::string RestClient::urlEncode(CURL *curl, const std::string &value)
{
	char *encoded = curl_easy_escape(curl, value.c_str(), static_cast<int>(value.length()));
	std::string result = encoded ? std::string(encoded) : value;
	curl_free(encoded);
	return result;
}

namespace curlpp
{
	std::string unescape(const std::string &url)
	{
		std::string buffer;
		char *p = curl_unescape(url.c_str(), (int)url.size());
		if (!p)
		{
			throw std::runtime_error("unable to escape the string"); // we got an error
		}
		else
		{
			buffer = p;
			curl_free(p);
		}
		return buffer;
	}
}