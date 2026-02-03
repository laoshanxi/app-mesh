// src/daemon/rest/Data.cpp
#include <chrono>
#include <errno.h>
#include <tuple>

#include <msgpack.hpp>

#include "../../common/Utility.h"
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
		Response resp = obj.as<Response>();
		*this = resp;
		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "failed with error: " << e.what();
	}
	return false;
}

// setAuthCookie extracts JWT token from response body and creates a Set-Cookie header
// Follows agent_response.go setAuthCookie pattern
bool Response::setAuthCookie()
{
	// Parse JWT from response body
	nlohmann::json jsonResponse;
	try
	{
		jsonResponse = nlohmann::json::parse(this->body);
	}
	catch (const std::exception &)
	{
		return false;
	}

	std::string accessToken;
	if (jsonResponse.contains(HTTP_HEADER_JWT_access_token))
	{
		accessToken = jsonResponse[HTTP_HEADER_JWT_access_token].get<std::string>();
	}

	// Validate token presence
	if (accessToken.empty())
		return false;

	double expireSeconds = 0;
	if (jsonResponse.contains(HTTP_BODY_KEY_JWT_expire_seconds))
	{
		expireSeconds = jsonResponse[HTTP_BODY_KEY_JWT_expire_seconds].get<double>();
	}

	// Trim "Bearer " prefix if present
	if (accessToken.find(HTTP_HEADER_JWT_BearerSpace) == 0)
	{
		accessToken = accessToken.substr(7);
	}

	// Create cookie string
	std::string cookieValue = COOKIE_TOKEN + std::string("=") + accessToken + "; Path=/; HttpOnly; SameSite=Strict";
	// TODO: Check if using HTTPS (for Secure flag)
	bool isSecure = true;
	if (isSecure)
	{
		cookieValue += "; Secure";
	}

	// Set expiration if available
	if (expireSeconds > 0)
	{
		cookieValue += "; Max-Age=" + std::to_string(static_cast<int>(expireSeconds));
	}

	this->headers["Set-Cookie"] = cookieValue;
	return true;
}

bool Response::handleAuthCookies()
{
	const static char fname[] = "Response::handleAuthCookies() ";

	// Only proceed for successful responses
	if (this->http_status != web::http::status_codes::OK)
		return false;

	// Check if response path indicates a login/auth endpoint (where cookie should be set)
	const std::string &requestUri = this->request_uri;
	bool shouldSetCookie = false;

	// Check for login/auth paths (or check if response has access_token)
	if (requestUri == "/appmesh/login" || requestUri == "/appmesh/auth" || requestUri == "/appmesh/totp/validate")
	{
		shouldSetCookie = true;
	}

	if (!shouldSetCookie)
		return false;

	bool result = this->setAuthCookie();

	LOG_DBG << fname << "setAuthCookie result: " << (result ? "success" : "no cookie set");
	return result;
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
		msgpack::unpack(result, reinterpret_cast<const char *>(data->data()), data->size());

		msgpack::object obj = result.get();
		obj.convert(*this); // directly fill into *this

		return true;
	}
	catch (const std::exception &e)
	{
		LOG_ERR << fname << "failed with error: " << e.what();
	}
	return false;
}

bool Request::contain_body()
{
	auto it = headers.find("content-length");
	if (it != headers.end())
	{
		char *end;
		long long len = std::strtoll(it->second.c_str(), &end, 10);
		return len > 0;
	}

	it = headers.find("transfer-encoding");
	if (it != headers.end())
	{
		return it->second.find("chunked") != std::string::npos;
	}

	return false;
}

// Helper function to extract cookie value from Cookie header
static std::string getCookieValue(const std::string &cookieHeader, const std::string &cookieName)
{
	std::string searchPattern = cookieName + "=";
	size_t startPos = cookieHeader.find(searchPattern);
	if (startPos == std::string::npos)
		return "";

	startPos += searchPattern.size();
	size_t endPos = cookieHeader.find(";", startPos);
	if (endPos == std::string::npos)
	{
		return cookieHeader.substr(startPos);
	}
	return cookieHeader.substr(startPos, endPos - startPos);
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

	// Trim whitespace
	while (!authCookieValue.empty() && authCookieValue.back() == ' ')
		authCookieValue.pop_back();
	while (!authCookieValue.empty() && authCookieValue.front() == ' ')
		authCookieValue = authCookieValue.substr(1);

	// Inject Authorization header
	headers[HTTP_HEADER_JWT_Authorization] = HTTP_HEADER_JWT_BearerSpace + authCookieValue;

	LOG_DBG << fname << "Converted cookie to Authorization header for UUID: " << uuid;
	return true;
}
