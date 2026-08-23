#include "Security.h"

#include "../../common/Utility.h"
#include "SecurityOidc.h"

#include <algorithm>
#include <cctype>

std::shared_ptr<Security> Security::m_instance = nullptr;
std::recursive_mutex Security::m_mutex;

void Security::init()
{
	const static char fname[] = "Security::init() ";
	auto instance = std::make_shared<SecurityOidc>();
	instance->initialize();
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	m_instance = std::move(instance);
	LOG_INF << fname << "OIDC authentication and App Mesh authorization initialized";
}

std::shared_ptr<Security> Security::instance()
{
	std::lock_guard<std::recursive_mutex> guard(m_mutex);
	if (!m_instance)
		throw std::logic_error("Security accessed before initialization");
	return m_instance;
}

Principal Security::authenticateBearerAuthorization(const std::string &authorization)
{
	const auto value = Utility::stdStringTrim(authorization);
	if (value.size() > 8 * 1024)
		throw std::domain_error("Authorization header is too large");
	const auto separator = value.find(' ');
	if (separator == std::string::npos)
		throw std::domain_error("Authorization header must use the Bearer scheme");
	auto scheme = value.substr(0, separator);
	std::transform(scheme.begin(), scheme.end(), scheme.begin(),
		[](unsigned char c) { return static_cast<char>(std::tolower(c)); });
	if (scheme != "bearer")
		throw std::domain_error("Authorization header must use the Bearer scheme");
	const auto token = Utility::stdStringTrim(value.substr(separator + 1));
	if (token.empty() || token.find_first_of(" \t\r\n") != std::string::npos)
		throw std::domain_error("Bearer token is empty or malformed");
	return instance()->authenticate(token);
}

void Security::requirePermission(const std::string &principalId, const std::string &permission)
{
	if (principalId.empty())
		throw std::domain_error("No authenticated principal is bound to the transport");
	const auto granted = instance()->permissions(principalId);
	if (!permission.empty() && granted.count(permission) == 0)
		throw AuthorizationException(Utility::stringFormat(
			"Permission denied: principal '%s' lacks required permission '%s'",
			principalId.c_str(), permission.c_str()));
}
