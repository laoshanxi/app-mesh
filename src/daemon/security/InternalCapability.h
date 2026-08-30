#pragma once

#include <cstdint>
#include <set>
#include <string>

/// Daemon-local authorization capability for the managed Workflow process.
///
/// This is deliberately not a JWT or OAuth access token.  It is accepted only on
/// a loopback TCP connection and is additionally bound to the current Workflow
/// process UUID.  The signing key never leaves the daemon.
class InternalCapability
{
public:
	enum class Audience
	{
		WorkflowControl,
		WorkflowRun,
	};

	struct Claims
	{
		Audience audience;
		std::string workflowId;
		std::string runId;
		std::string ownerPrincipalId;
		std::string processUuid;
		std::set<std::string> operations;
		std::int64_t issuedAt;
		std::int64_t expiresAt;
	};

	static InternalCapability &instance();

	std::string issue(Audience audience, const std::string &workflowId,
		const std::string &runId, const std::string &ownerPrincipalId,
		const std::string &processUuid, const std::set<std::string> &operations,
		std::int64_t ttlSeconds) const;

	Claims verify(const std::string &capability, const std::string &requiredOperation) const;

	static const char *audienceName(Audience audience);

private:
	InternalCapability();

	std::string sign(const std::string &message) const;
	static std::string base64UrlEncode(const std::string &value);
	static std::string base64UrlDecode(const std::string &value);

	const std::string m_signingKey;

	InternalCapability(const InternalCapability &) = delete;
	InternalCapability &operator=(const InternalCapability &) = delete;
};
