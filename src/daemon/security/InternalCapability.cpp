#include "InternalCapability.h"

#include <algorithm>
#include <chrono>
#include <stdexcept>

#include <openssl/hmac.h>

#include <nlohmann/json.hpp>

#include "../../common/Password.h"
#include "../../common/Utility.h"

namespace
{
	constexpr const char *CAPABILITY_PREFIX = "amcap1.";
	constexpr std::size_t MAX_CAPABILITY_SIZE = 8192;
	constexpr std::int64_t MAX_CAPABILITY_TTL_SECONDS = 300;
	constexpr std::int64_t MAX_CLOCK_SKEW_SECONDS = 30;
	constexpr std::size_t MAX_OPERATIONS = 16;

	std::int64_t nowSeconds()
	{
		return std::chrono::duration_cast<std::chrono::seconds>(
			std::chrono::system_clock::now().time_since_epoch()).count();
	}

	InternalCapability::Audience parseAudience(const std::string &value)
	{
		if (value == InternalCapability::audienceName(InternalCapability::Audience::WorkflowControl))
			return InternalCapability::Audience::WorkflowControl;
		if (value == InternalCapability::audienceName(InternalCapability::Audience::WorkflowRun))
			return InternalCapability::Audience::WorkflowRun;
		throw std::domain_error("internal capability audience is invalid");
	}

	std::string bytesToHex(const unsigned char *data, std::size_t size)
	{
		static const char hex[] = "0123456789abcdef";
		std::string result(size * 2, '0');
		for (std::size_t i = 0; i < size; ++i)
		{
			result[i * 2] = hex[(data[i] >> 4) & 0x0f];
			result[i * 2 + 1] = hex[data[i] & 0x0f];
		}
		return result;
	}
}

InternalCapability &InternalCapability::instance()
{
	static InternalCapability singleton;
	return singleton;
}

InternalCapability::InternalCapability()
	: m_signingKey(generatePassword(64, true, true, true, true))
{
}

const char *InternalCapability::audienceName(Audience audience)
{
	switch (audience)
	{
	case Audience::WorkflowControl:
		return "appmesh-internal-workflow-control";
	case Audience::WorkflowRun:
		return "appmesh-internal-workflow-run";
	}
	throw std::invalid_argument("unknown internal capability audience");
}

std::string InternalCapability::issue(Audience audience, const std::string &workflowId,
	const std::string &runId, const std::string &ownerPrincipalId,
	const std::string &processUuid, const std::set<std::string> &operations,
	std::int64_t ttlSeconds) const
{
	if (workflowId.empty() || runId.empty() || ownerPrincipalId.empty() || processUuid.empty())
		throw std::invalid_argument("internal capability bindings must be non-empty");
	if (operations.empty() || operations.size() > MAX_OPERATIONS)
		throw std::invalid_argument("internal capability operations are invalid");
	if (ttlSeconds <= 0 || ttlSeconds > MAX_CAPABILITY_TTL_SECONDS)
		throw std::invalid_argument("internal capability lifetime must be between 1 and 300 seconds");

	const auto issuedAt = nowSeconds();
	nlohmann::json payload;
	payload["v"] = 1;
	payload["aud"] = audienceName(audience);
	payload["workflow_id"] = workflowId;
	payload["run_id"] = runId;
	payload["owner_principal_id"] = ownerPrincipalId;
	payload["process_uuid"] = processUuid;
	payload["operations"] = operations;
	payload["iat"] = issuedAt;
	payload["exp"] = issuedAt + ttlSeconds;

	const auto encoded = base64UrlEncode(payload.dump());
	const std::string signingInput = std::string(CAPABILITY_PREFIX) + encoded;
	return signingInput + "." + sign(signingInput);
}

InternalCapability::Claims InternalCapability::verify(
	const std::string &capability, const std::string &requiredOperation) const
{
	if (capability.size() <= std::char_traits<char>::length(CAPABILITY_PREFIX) ||
		capability.size() > MAX_CAPABILITY_SIZE ||
		capability.compare(0, std::char_traits<char>::length(CAPABILITY_PREFIX), CAPABILITY_PREFIX) != 0)
		throw std::domain_error("internal capability format is invalid");

	const auto signatureSeparator = capability.rfind('.');
	if (signatureSeparator == std::string::npos ||
		signatureSeparator <= std::char_traits<char>::length(CAPABILITY_PREFIX) ||
		signatureSeparator + 1 >= capability.size())
		throw std::domain_error("internal capability format is invalid");

	const auto signingInput = capability.substr(0, signatureSeparator);
	const auto receivedSignature = capability.substr(signatureSeparator + 1);
	if (!Utility::secureCompare(sign(signingInput), receivedSignature))
		throw std::domain_error("internal capability signature is invalid");

	try
	{
		const auto encodedPayload = signingInput.substr(std::char_traits<char>::length(CAPABILITY_PREFIX));
		const auto payload = nlohmann::json::parse(base64UrlDecode(encodedPayload));
		if (!payload.is_object() || payload.at("v").get<int>() != 1)
			throw std::domain_error("internal capability version is invalid");

		Claims claims{
			parseAudience(payload.at("aud").get<std::string>()),
			payload.at("workflow_id").get<std::string>(),
			payload.at("run_id").get<std::string>(),
			payload.at("owner_principal_id").get<std::string>(),
			payload.at("process_uuid").get<std::string>(),
			{},
			payload.at("iat").get<std::int64_t>(),
			payload.at("exp").get<std::int64_t>()};

		const auto &operations = payload.at("operations");
		if (!operations.is_array() || operations.empty() || operations.size() > MAX_OPERATIONS)
			throw std::domain_error("internal capability operations are invalid");
		for (const auto &operation : operations)
		{
			if (!operation.is_string() || operation.get<std::string>().empty())
				throw std::domain_error("internal capability operation is invalid");
			claims.operations.insert(operation.get<std::string>());
		}

		if (claims.workflowId.empty() || claims.runId.empty() ||
			claims.ownerPrincipalId.empty() || claims.processUuid.empty())
			throw std::domain_error("internal capability binding is invalid");
		const auto now = nowSeconds();
		if (claims.issuedAt > now + MAX_CLOCK_SKEW_SECONDS || claims.expiresAt <= now ||
			claims.expiresAt <= claims.issuedAt ||
			claims.expiresAt - claims.issuedAt > MAX_CAPABILITY_TTL_SECONDS)
			throw std::domain_error("internal capability is expired or has an invalid lifetime");
		if (!requiredOperation.empty() && claims.operations.count(requiredOperation) == 0)
			throw std::domain_error("internal capability does not allow this operation");
		return claims;
	}
	catch (const std::domain_error &)
	{
		throw;
	}
	catch (const std::exception &)
	{
		throw std::domain_error("internal capability payload is invalid");
	}
}

std::string InternalCapability::sign(const std::string &message) const
{
	unsigned char output[EVP_MAX_MD_SIZE] = {0};
	unsigned int outputLength = 0;
	if (HMAC(EVP_sha256(), m_signingKey.data(), static_cast<int>(m_signingKey.size()),
		reinterpret_cast<const unsigned char *>(message.data()), message.size(),
		output, &outputLength) == nullptr)
		throw std::runtime_error("could not sign internal capability");
	return bytesToHex(output, outputLength);
}

std::string InternalCapability::base64UrlEncode(const std::string &value)
{
	auto encoded = Utility::encode64(value);
	std::replace(encoded.begin(), encoded.end(), '+', '-');
	std::replace(encoded.begin(), encoded.end(), '/', '_');
	while (!encoded.empty() && encoded.back() == '=')
		encoded.pop_back();
	return encoded;
}

std::string InternalCapability::base64UrlDecode(const std::string &value)
{
	if (value.empty() || value.find_first_not_of(
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != std::string::npos)
		throw std::domain_error("internal capability encoding is invalid");
	auto encoded = value;
	std::replace(encoded.begin(), encoded.end(), '-', '+');
	std::replace(encoded.begin(), encoded.end(), '_', '/');
	encoded.append((4 - encoded.size() % 4) % 4, '=');
	return Utility::decode64(encoded);
}
