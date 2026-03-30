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
	headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type, X-CSRF-Token";
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
	std::string searchPattern = cookieName + "=";
	size_t startPos = cookieHeader.find(searchPattern);
	if (startPos == std::string::npos)
		return "";

	startPos += searchPattern.size();
	size_t endPos = cookieHeader.find(';', startPos);
	if (endPos == std::string::npos)
	{
		return trim(cookieHeader.substr(startPos));
	}
	return trim(cookieHeader.substr(startPos, endPos - startPos));
}

// Convert cookie to Authorization header (follows agent_request.go validateCSRFToken pattern)
// Returns true if cookie was converted to header, false otherwise
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

	// Note: For simple implementation, we skip CSRF validation
	// Full implementation would check:
	// 1. Extract CSRF token from cookie (COOKIE_CSRF_TOKEN)
	// 2. Compare with X-CSRF-Token header
	// 3. Verify HMAC if both present
	// For now, we just inject the Authorization header
	// Inject Authorization header
	headers[HTTP_HEADER_JWT_Authorization] = JwtHelper::buildBearerAuthorization(authCookieValue);

	LOG_DBG << fname << "Converted cookie to Authorization header for UUID: " << uuid;
	return true;
}
