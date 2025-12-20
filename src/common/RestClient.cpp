// src/common/RestClient.cpp
#include <ctime>
#include <curl/curl.h>
#include <fstream>
#include <mutex>
#include <openssl/ssl.h>
#include <sstream>

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
		if (curl)
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

// RAII wrapper for curl_slist cleanup
class CurlSlistRAII
{
public:
	CurlSlistRAII() = default;
	~CurlSlistRAII()
	{
		if (ptr)
			curl_slist_free_all(ptr);
	}

	// Implicit conversion operator for direct use with CURL functions
	operator curl_slist *() const { return ptr; }
	curl_slist **operator&() { return &ptr; }

	// Get raw pointer
	curl_slist *get() const { return ptr; }

private:
	curl_slist *ptr = nullptr;
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
SessionConfig RestClient::m_sessionConfig;
std::mutex RestClient::m_sessionMutex;
std::string RestClient::m_memoryCookies;

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
	if (!workingHome.empty() && !filePath.empty() && !Utility::startWith(filePath, workingHome))
	{
		return (fs::path(workingHome) / filePath).lexically_normal().string();
	}
	return filePath;
}

void RestClient::setSessionConfiguration(const SessionConfig &sessionConfig)
{
	std::lock_guard<std::mutex> lock(m_sessionMutex);
	m_sessionConfig = sessionConfig;

	// Clear existing cookies when changing session configuration
	m_memoryCookies.clear();
}

SessionConfig RestClient::getSessionConfiguration()
{
	std::lock_guard<std::mutex> lock(m_sessionMutex);
	return m_sessionConfig;
}

void RestClient::clearSession()
{
	std::lock_guard<std::mutex> lock(m_sessionMutex);

	// Clear memory cookies
	m_memoryCookies.clear();

	// Delete cookie file
	if (!m_sessionConfig.cookie_file.empty())
	{
		Utility::removeFile(m_sessionConfig.cookie_file);
	}
}

void RestClient::setSessionConfig(CURL *curl)
{
	std::lock_guard<std::mutex> lock(m_sessionMutex);

	if (!m_sessionConfig.enable_session)
	{
		return; // Session disabled
	}

	if (m_sessionConfig.use_memory_cookies)
	{
		// Enable in-memory cookie engine
		curl_easy_setopt(curl, CURLOPT_COOKIEFILE, ""); // Enable cookie engine

		// Restore previously stored cookies
		if (!m_memoryCookies.empty())
			curl_easy_setopt(curl, CURLOPT_COOKIELIST, m_memoryCookies.c_str());
	}
	else if (!m_sessionConfig.cookie_file.empty())
	{
		// Use persistent cookie file
		curl_easy_setopt(curl, CURLOPT_COOKIEFILE, m_sessionConfig.cookie_file.c_str()); // Read cookies
		curl_easy_setopt(curl, CURLOPT_COOKIEJAR, NULL);								 // Write cookies
	}
}

// Helper function to save cookies after a request
static void saveCookiesAfterRequest(CURL *curl, const SessionConfig &config, std::string &memoryCookies, std::mutex &mutex)
{
	if (!config.enable_session)
	{
		return;
	}

	CurlSlistRAII cookies;
	curl_easy_getinfo(curl, CURLINFO_COOKIELIST, &cookies);

	if (!cookies.get())
	{
		return;
	}

	if (config.use_memory_cookies)
	{
		std::lock_guard<std::mutex> lock(mutex);
		memoryCookies.clear();
		struct curl_slist *nc = cookies.get();
		while (nc)
		{
			memoryCookies += std::string(nc->data) + "\n";
			nc = nc->next;
		}
	}
	else if (!config.cookie_file.empty())
	{
		// For file-based cookies, force write
		curl_easy_setopt(curl, CURLOPT_COOKIEJAR, config.cookie_file.c_str()); // Write cookies
		curl_easy_setopt(curl, CURLOPT_COOKIELIST, "FLUSH");
	}
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
	setSessionConfig(curl); // Configure session/cookie handling

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

		// Save cookies after successful request
		if (response->header.count("Set-Cookie") != 0)
		{
			saveCookiesAfterRequest(curl, m_sessionConfig, m_memoryCookies, m_sessionMutex);
		}
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

	// SSL and Session configuration
	setSslConfig(curl);
	setSessionConfig(curl); // Configure session/cookie handling

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
	std::unique_ptr<FILE, void (*)(FILE *)> output_file(fopen(localFile.c_str(), "w+b"), [](FILE *fp)
														{ if (fp) fclose(fp); });
	if (!output_file)
	{
		throw std::invalid_argument("failed to open file for writing.");
		// response->text = "Failed to open file for writing: " + localFile;
		// return response;
	}

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

	// SSL and Session configuration
	setSslConfig(curl);
	setSessionConfig(curl); // Configure session/cookie handling

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

		if (response->status_code != 200 && response->text.empty())
		{
			rewind(output_file.get());
			fseek(output_file.get(), 0, SEEK_END);
			long size = ftell(output_file.get());
			rewind(output_file.get());
			if (size > 0)
			{
				response->text.assign(size, '\0');
				size_t read_bytes = fread(&response->text[0], 1, size, output_file.get());
				if (read_bytes != static_cast<size_t>(size))
				{
					response->text.resize(read_bytes);
				}
			}
		}
	}
	return response;
}

void RestClient::defaultSslConfiguration(const ClientSSLConfig &sslConfig)
{
	std::lock_guard<std::mutex> lock(m_sessionMutex);
	m_sslConfig = sslConfig;
}

void RestClient::setSslConfig(CURL *curl)
{
	bool verbose = spdlog::default_logger()->level() <= spdlog::level::debug;
	curl_easy_setopt(curl, CURLOPT_VERBOSE, verbose);

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
			throw std::runtime_error("unable to unescape the string");
		}
		else
		{
			buffer = p;
			curl_free(p);
		}
		return buffer;
	}
}

// Helper function to check if a cookie is expired
bool RestClient::isCookieExpired(const Cookie &cookie)
{
	// A cookie with expiration of 0 is a session cookie (never expires until session ends)
	if (cookie.expiration == 0)
	{
		return false;
	}

	// Get current timestamp
	std::time_t now = std::time(nullptr);

	// Check if cookie has expired
	return cookie.expiration < now;
}

// Parse Netscape cookie format line
// Format: domain flag path secure expiration name value
// Example: .example.com	TRUE	/	FALSE	0	token_name	token_value
// HttpOnly cookies have #HttpOnly_ prefix in domain
bool RestClient::parseNetscapeCookie(const std::string &line, Cookie &cookie)
{
	// Skip comments and empty lines
	if (line.empty() || line[0] == '#')
	{
		// Check for HttpOnly format: #HttpOnly_domain
		if (line.find("#HttpOnly_") == 0)
		{
			cookie.httponly = true;
			// Continue parsing the rest without the prefix
			std::string modifiedLine = line.substr(10); // Remove "#HttpOnly_"
			std::istringstream iss(modifiedLine);

			std::string flag_str, secure_str, expiration_str;

			if (!(iss >> cookie.domain >> flag_str >> cookie.path >> secure_str >> expiration_str >> cookie.name))
			{
				return false;
			}

			// Read the rest as value (may contain spaces)
			std::getline(iss, cookie.value);
			cookie.value = Utility::stdStringTrim(cookie.value);

			cookie.include_subdomains = (flag_str == "TRUE");
			cookie.secure = (secure_str == "TRUE");

			try
			{
				cookie.expiration = std::stoll(expiration_str);
			}
			catch (const std::exception &)
			{
				cookie.expiration = 0;
			}

			return true;
		}
		return false;
	}

	std::istringstream iss(line);
	std::string flag_str, secure_str, expiration_str;

	if (!(iss >> cookie.domain >> flag_str >> cookie.path >> secure_str >> expiration_str >> cookie.name))
	{
		return false;
	}

	// Read the rest as value (may contain spaces)
	std::getline(iss, cookie.value);
	cookie.value = Utility::stdStringTrim(cookie.value);

	cookie.include_subdomains = (flag_str == "TRUE");
	cookie.secure = (secure_str == "TRUE");

	try
	{
		cookie.expiration = std::stoll(expiration_str);
	}
	catch (const std::exception &)
	{
		cookie.expiration = 0;
	}

	cookie.httponly = false;

	return true;
}

// Read cookies from memory storage
std::map<std::string, Cookie> RestClient::readCookiesFromMemory()
{
	std::map<std::string, Cookie> cookies;
	std::lock_guard<std::mutex> lock(m_sessionMutex);

	if (m_memoryCookies.empty())
	{
		return cookies;
	}

	std::istringstream stream(m_memoryCookies);
	std::string line;

	while (std::getline(stream, line))
	{
		Cookie cookie;
		if (parseNetscapeCookie(line, cookie))
		{
			// Skip expired cookies
			if (!isCookieExpired(cookie))
			{
				cookies[cookie.name] = cookie;
			}
		}
	}

	return cookies;
}

// Read cookies from file storage
std::map<std::string, Cookie> RestClient::readCookiesFromFile()
{
	std::map<std::string, Cookie> cookies;
	std::lock_guard<std::mutex> lock(m_sessionMutex);

	if (m_sessionConfig.cookie_file.empty() || !Utility::isFileExist(m_sessionConfig.cookie_file))
	{
		return cookies;
	}

	std::ifstream file(m_sessionConfig.cookie_file);
	if (!file.is_open())
	{
		LOG_ERR << "Failed to open cookie file: " << m_sessionConfig.cookie_file;
		return cookies;
	}

	std::string line;
	while (std::getline(file, line))
	{
		Cookie cookie;
		if (parseNetscapeCookie(line, cookie))
		{
			// Skip expired cookies
			if (!isCookieExpired(cookie))
			{
				cookies[cookie.name] = cookie;
			}
		}
	}

	file.close();
	return cookies;
}

// Get all cookies
std::map<std::string, Cookie> RestClient::getAllCookies()
{
	// Check session configuration first without holding lock too long
	SessionConfig config;
	{
		std::lock_guard<std::mutex> lock(m_sessionMutex);
		config = m_sessionConfig;
	}

	if (!config.enable_session)
	{
		return {};
	}

	if (config.use_memory_cookies)
	{
		return readCookiesFromMemory();
	}
	else
	{
		return readCookiesFromFile();
	}
}

// Get specific cookie value by name
std::string RestClient::getCookie(const std::string &cookieName)
{
	auto cookies = getAllCookies();
	auto it = cookies.find(cookieName);

	if (it != cookies.end())
	{
		return it->second.value;
	}

	return std::string();
}

// Get specific cookie with full details
bool RestClient::getCookieDetails(const std::string &cookieName, Cookie &cookie)
{
	auto cookies = getAllCookies();
	auto it = cookies.find(cookieName);

	if (it != cookies.end())
	{
		cookie = it->second;
		return true;
	}

	return false;
}
