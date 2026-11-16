#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>

/// HMAC-SHA256 request signature verification (anti-tamper layer).
///
/// The signature is an integrity layer on top of the existing bearer
/// authentication, not a replacement for it: a valid signature proves the
/// request bytes (method, path, query, body, timestamp, nonce) were produced
/// by a holder of the API key secret and were not modified in flight.
/// Authorization is still decided by the bearer token.
///
/// Canonical string (both sides must build this byte-for-byte):
///   METHOD + "\n" + path + "\n" + sortedQuery + "\n" + sha256hex(body) + "\n"
///   + timestamp + "\n" + nonce
/// - path: the request URI path as carried (before '?', not percent-decoded)
/// - sortedQuery: query map entries "k=v" joined with '&', sorted by key then
///   value; empty string when there is no query
/// - body: raw request bytes; streamed file uploads sign the empty string
///   (documented exemption)
class RequestSignature
{
public:
	struct Verification
	{
		bool signedRequest = false; // the four signature headers were present
		bool valid = false;
		std::string principalId; // API key owner, set when valid
		std::string reason;      // human-readable failure detail
	};

	/// Verifies one request. `window` bounds the accepted |now - X-Timestamp|
	/// distance; it is clamped to [1, 3600] seconds by the caller configuration.
	static Verification verify(const std::string &method, const std::string &path, const std::string &query,
							   const std::uint8_t *body, std::size_t bodySize, const std::string &keyId,
							   const std::string &timestamp, const std::string &nonce, const std::string &signature,
							   std::chrono::seconds window);
	/// Same check with the secret supplied by the caller (unit tests; the key
	/// lookup is the only difference from verify()).
	static Verification verifyWithSecret(const std::string &secret, const std::string &method, const std::string &path,
										 const std::string &query, const std::uint8_t *body, std::size_t bodySize,
										 const std::string &timestamp, const std::string &nonce,
										 const std::string &signature, std::chrono::seconds window);

	/// Sorted "k=v&k2=v2" form used in the canonical string.
	static std::string canonicalQuery(const std::map<std::string, std::string> &query);
	static std::string canonicalString(const std::string &method, const std::string &path, const std::string &query,
									   const std::string &bodySha256Hex, const std::string &timestamp,
									   const std::string &nonce);
	/// Test and documentation helper mirroring the client-side signing step.
	static std::string sign(const std::string &secret, const std::string &canonical);
	static std::string sha256Hex(const void *data, std::size_t size);

	/// Nonce wire shape: non-empty, at most 128 bytes, no embedded whitespace.
	/// Shared by the signature layer and the replay layer so a replay-only
	/// deployment cannot feed unbounded nonce material into the guard.
	static bool isNonceShape(const std::string &value);
};
