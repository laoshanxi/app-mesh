#include "RequestSignature.h"

#include <algorithm>
#include <chrono>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <vector>

#include "../../common/Utility.h"
#include "Security.h"

namespace
{
	constexpr std::int64_t MAX_TIMESTAMP_SKEW_SECONDS = 3600;

	bool isDigits(const std::string &value)
	{
		return !value.empty() && value.size() <= 12 &&
			   std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
	}

	bool isHex(const std::string &value)
	{
		return !value.empty() && value.size() <= 128 &&
			   std::all_of(value.begin(), value.end(), [](unsigned char c) {
				   return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
			   });
	}
} // namespace

bool RequestSignature::isNonceShape(const std::string &value)
{
	return !value.empty() && value.size() <= 128 && value.find_first_of(" \t\r\n") == std::string::npos;
}

RequestSignature::Verification RequestSignature::verify(const std::string &method, const std::string &path,
														const std::string &query, const std::uint8_t *body,
														std::size_t bodySize, const std::string &keyId,
														const std::string &timestamp, const std::string &nonce,
														const std::string &signature, std::chrono::seconds window)
{
	Verification result;
	result.signedRequest = !keyId.empty() || !timestamp.empty() || !nonce.empty() || !signature.empty();
	std::string secret;
	if (!Security::instance()->apiKeySecret(keyId, result.principalId, secret))
	{
		// Do not disclose whether the key exists.
		result.principalId.clear();
		result.reason = "unknown request signing key";
		return result;
	}
	auto checked = verifyWithSecret(secret, method, path, query, body, bodySize, timestamp, nonce, signature, window);
	if (checked.valid)
		checked.principalId = result.principalId;
	return checked;
}

RequestSignature::Verification RequestSignature::verifyWithSecret(const std::string &secret, const std::string &method,
																  const std::string &path, const std::string &query,
																  const std::uint8_t *body, std::size_t bodySize,
																  const std::string &timestamp,
																  const std::string &nonce,
																  const std::string &signature,
																  std::chrono::seconds window)
{
	Verification result;
	result.signedRequest = !timestamp.empty() || !nonce.empty() || !signature.empty();

	if (timestamp.empty() || nonce.empty() || signature.empty())
	{
		result.reason = "incomplete request signature headers";
		return result;
	}
	if (!isNonceShape(nonce) || !isDigits(timestamp) || !isHex(signature))
	{
		result.reason = "malformed request signature headers";
		return result;
	}

	const auto now = std::chrono::duration_cast<std::chrono::seconds>(
						 std::chrono::system_clock::now().time_since_epoch())
						 .count();
	const auto claimed = std::stoll(timestamp);
	const auto acceptance = std::min(std::max<std::int64_t>(window.count(), 1), MAX_TIMESTAMP_SKEW_SECONDS) + 30;
	if (claimed < now - acceptance || claimed > now + acceptance)
	{
		result.reason = "request signature timestamp is outside the acceptance window";
		return result;
	}

	const auto canonical = canonicalString(method, path, query, sha256Hex(body, bodySize), timestamp, nonce);
	if (!Utility::secureCompare(sign(secret, canonical), signature))
	{
		result.reason = "request signature does not match the request";
		return result;
	}
	result.valid = true;
	return result;
}

std::string RequestSignature::canonicalQuery(const std::map<std::string, std::string> &query)
{
	std::vector<const std::pair<const std::string, std::string> *> pairs;
	pairs.reserve(query.size());
	for (const auto &entry : query)
		pairs.push_back(&entry);
	std::sort(pairs.begin(), pairs.end(),
			  [](const auto *a, const auto *b) { return a->first != b->first ? a->first < b->first : a->second < b->second; });

	std::string canonical;
	for (const auto *entry : pairs)
	{
		if (!canonical.empty())
			canonical.push_back('&');
		canonical.append(entry->first).push_back('=');
		canonical.append(entry->second);
	}
	return canonical;
}

std::string RequestSignature::canonicalString(const std::string &method, const std::string &path,
											  const std::string &query, const std::string &bodySha256Hex,
											  const std::string &timestamp, const std::string &nonce)
{
	std::string canonical;
	canonical.reserve(method.size() + path.size() + query.size() + bodySha256Hex.size() + timestamp.size() +
					  nonce.size() + 6);
	canonical.append(method).push_back('\n');
	canonical.append(path).push_back('\n');
	canonical.append(query).push_back('\n');
	canonical.append(bodySha256Hex).push_back('\n');
	canonical.append(timestamp).push_back('\n');
	canonical.append(nonce);
	return canonical;
}

std::string RequestSignature::sign(const std::string &secret, const std::string &canonical)
{
	unsigned char output[EVP_MAX_MD_SIZE] = {0};
	unsigned int outputLength = 0;
	if (HMAC(EVP_sha256(), secret.data(), static_cast<int>(secret.size()),
			 reinterpret_cast<const unsigned char *>(canonical.data()), canonical.size(), output, &outputLength) ==
		nullptr)
		throw std::runtime_error("could not sign request");
	return Utility::toHex(output, outputLength);
}

std::string RequestSignature::sha256Hex(const void *data, std::size_t size)
{
	unsigned char digest[EVP_MAX_MD_SIZE] = {0};
	unsigned int digestLength = 0;
	if (EVP_Digest(data, size, digest, &digestLength, EVP_sha256(), nullptr) != 1)
		throw std::runtime_error("could not hash request body");
	return Utility::toHex(digest, digestLength);
}
