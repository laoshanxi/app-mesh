// src/daemon/rest/Data.cpp
#include <algorithm>
#include <cctype>
#include <chrono>
#include <tuple>

#include <msgpack.hpp>
#include <nlohmann/json.hpp>

#include "../../common/JwtHelper.h"
#include "../../common/Utility.h"
#include "../Configuration.h"
#include "Data.h"

Response::Response()
	: http_status(0)
{
}

Response::~Response()
{
}

std::unique_ptr<msgpack::sbuffer> Response::serialize() const
{
	// pack
	auto sbuf = std::make_unique<msgpack::sbuffer>();
	msgpack::pack(*sbuf, *this);
	return sbuf;
}

bool Response::deserialize(const std::uint8_t *data, std::size_t dataSize)
{
	const static char fname[] = "Response::deserialize() ";
	try
	{
		msgpack::unpacked result;
		msgpack::unpack(result, reinterpret_cast<const char *>(data), dataSize);
		msgpack::object obj = result.get();
		obj.convert(*this);
		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "failed with error: " << e.what();
	}
	return false;
}

// setAuthCookie extracts auth response fields and creates a Set-Cookie header.
// It does not decode or verify JWT claims; that remains in RestBase.
bool Response::setAuthCookie()
{
	JwtHelper::TokenResponse tokenResponse;
	if (!JwtHelper::extractTokenResponse(this->body, tokenResponse))
		return false;

	// Create cookie string
	std::string cookieValue = std::string(COOKIE_TOKEN) + "=" + tokenResponse.accessToken + "; Path=/; HttpOnly; SameSite=Strict";

	// TODO: Determine HTTPS dynamically
	bool isSecure = true;
	if (isSecure)
	{
		cookieValue += "; Secure";
	}

	// Set expiration if available
	if (tokenResponse.expiresIn > 0)
	{
		cookieValue += "; Max-Age=" + std::to_string(tokenResponse.expiresIn);
	}

	this->headers["Set-Cookie"] = cookieValue;
	return true;
}

void Response::clearAuthCookie()
{
	// Expire the auth cookie immediately (follows agent_response.go clearAuthCookie pattern)
	std::string cookieValue = std::string(COOKIE_TOKEN) + "=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0";

	// TODO: Determine HTTPS dynamically
	bool isSecure = true;
	if (isSecure)
	{
		cookieValue += "; Secure";
	}

	this->headers["Set-Cookie"] = cookieValue;
}

static bool wantsSetCookie(const HttpHeaderMap *requestHeaders)
{
	if (requestHeaders == nullptr)
		return false;

	auto setCookie = Utility::stdStringTrim(requestHeaders->get(HTTP_HEADER_KEY_X_SET_COOKIE));
	std::transform(setCookie.begin(), setCookie.end(), setCookie.begin(), ::tolower);
	return setCookie == "true" || setCookie == "1";
}

// Forward declaration (defined after Request methods)
static std::string getCookieValue(const std::string &cookieHeader, const std::string &cookieName);

// Check if the request carries an auth cookie (client is using cookie mode)
static bool hasAuthCookie(const HttpHeaderMap *requestHeaders)
{
	if (requestHeaders == nullptr)
		return false;

	// HttpHeaderMap uses case-insensitive lookup, so "cookie" matches "Cookie"
	auto cookieHeader = requestHeaders->get("cookie");
	if (cookieHeader.empty())
		return false;

	return !getCookieValue(cookieHeader, COOKIE_TOKEN).empty();
}

bool Response::handleAuthCookies(const HttpHeaderMap *requestHeaders)
{
	const static char fname[] = "Response::handleAuthCookies() ";

	// Only proceed for successful responses
	if (this->http_status != web::http::status_codes::OK)
		return false;

	const std::string &requestUri = this->request_uri;

	// Login/auth/totp_validate: set cookie only when explicitly requested via X-Set-Cookie header
	if (requestUri == "/appmesh/login" ||
		requestUri == "/appmesh/auth" ||
		requestUri == "/appmesh/totp/validate")
	{
		if (!wantsSetCookie(requestHeaders))
			return false;

		bool result = this->setAuthCookie();
		LOG_DBG << fname << "setAuthCookie result: " << (result ? "success" : "no cookie set");
		return result;
	}

	// Token renew/TOTP setup: always refresh cookie if the request carried one
	if (requestUri == "/appmesh/token/renew" ||
		requestUri == "/appmesh/totp/setup")
	{
		if (!hasAuthCookie(requestHeaders))
			return false;

		bool result = this->setAuthCookie();
		LOG_DBG << fname << "setAuthCookie (renew/setup) result: " << (result ? "success" : "no cookie set");
		return result;
	}

	// Logoff: clear cookie if one exists
	if (requestUri == "/appmesh/self/logoff")
	{
		if (!hasAuthCookie(requestHeaders))
			return false;

		this->clearAuthCookie();
		LOG_DBG << fname << "clearAuthCookie on logoff";
		return true;
	}

	return false;
}

void Response::applyCorsHeaders()
{
	if (Configuration::instance()->getCorsDisabled())
		return;

	headers["Access-Control-Allow-Origin"] = "*";
	headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS";
	headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type";
	// Note: Removed Access-Control-Allow-Credentials as it conflicts with wildcard origin
}

void Response::applySecurityHeaders()
{
	headers["X-Content-Type-Options"] = "nosniff";
	headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains";
}

std::unique_ptr<msgpack::sbuffer> Request::serialize() const
{
	auto sbuf = std::make_unique<msgpack::sbuffer>();
	msgpack::pack(*sbuf, *this);
	return sbuf;
}

bool Request::deserialize(const ByteBuffer &data)
{
	const static char fname[] = "Request::deserialize() ";
	try
	{
		msgpack::unpacked result;
		msgpack::unpack(result, reinterpret_cast<const char *>(data.data()), data.size());
		msgpack::object obj = result.get();
		obj.convert(*this);
		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "failed with error: " << e.what();
	}
	return false;
}

bool Request::contain_body() const
{
	auto it = headers.find("content-length");
	if (it != headers.end())
	{
		char *end;
		errno = 0;
		long long len = std::strtoll(it->second.c_str(), &end, 10);
		if (errno == 0 && end != it->second.c_str())
		{
			return len > 0;
		}
		return false;
	}

	it = headers.find("transfer-encoding");
	if (it != headers.end())
	{
		return it->second.find("chunked") != std::string::npos;
	}

	return false;
}

static std::string trim(const std::string &str)
{
	size_t start = str.find_first_not_of(" \t\r\n");
	if (start == std::string::npos)
		return "";
	size_t end = str.find_last_not_of(" \t\r\n");
	return str.substr(start, end - start + 1);
}

static std::string getCookieValue(const std::string &cookieHeader, const std::string &cookieName)
{
	// Match on the cookie-name boundary, not a substring, so e.g. "x_appmesh_auth_token"
	// cannot be mistaken for "appmesh_auth_token". Split the header on ';' and compare names.
	size_t pos = 0;
	while (pos < cookieHeader.size())
	{
		size_t sep = cookieHeader.find(';', pos);
		const std::string pair = cookieHeader.substr(pos, sep == std::string::npos ? std::string::npos : sep - pos);

		const size_t eq = pair.find('=');
		if (eq != std::string::npos && trim(pair.substr(0, eq)) == cookieName)
			return trim(pair.substr(eq + 1));

		if (sep == std::string::npos)
			break;
		pos = sep + 1;
	}
	return "";
}

// Inject Authorization from the auth cookie for cookie-authenticated clients (header-based SDKs
// already set Authorization and skip this). CSRF is enforced separately by the daemon's Origin
// check (see Worker::isCsrfViolation); do not add token validation here.
bool Request::convertCookieToAuthorization()
{
	const static char fname[] = "Request::convertCookieToAuthorization() ";

	// Skip if Authorization header already present
	if (headers.contains(HTTP_HEADER_JWT_Authorization))
		return false;

	// Check for Cookie header
	const auto cookieHeader = headers.get("cookie");
	if (cookieHeader.empty())
		return false;

	// Extract auth token cookie
	std::string authCookieValue = getCookieValue(cookieHeader, COOKIE_TOKEN);
	if (authCookieValue.empty())
		return false;

	// Inject Authorization header
	headers[HTTP_HEADER_JWT_Authorization] = JwtHelper::buildBearerAuthorization(authCookieValue);

	LOG_DBG << fname << "Converted cookie to Authorization header for UUID: " << uuid;
	return true;
}
