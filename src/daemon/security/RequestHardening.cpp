#include "RequestHardening.h"

#include "../../common/Utility.h"
#include <algorithm>
#include <chrono>

#include "../Configuration.h"
#include "InternalCapability.h"
#include "RequestSignature.h"
#include "Security.h"

namespace
{
	std::int64_t nowSeconds()
	{
		return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
			.count();
	}

	bool isInternalCapabilityBearer(const std::string &bearer)
	{
		const auto capability = Utility::bearerCredential(bearer);
		return capability.size() > std::char_traits<char>::length(InternalCapability::PREFIX) &&
			   capability.compare(0, std::char_traits<char>::length(InternalCapability::PREFIX),
								  InternalCapability::PREFIX) == 0;
	}

	bool isDigits(const std::string &value)
	{
		return !value.empty() && value.size() <= 12 &&
			   std::all_of(value.begin(), value.end(), [](unsigned char c) { return c >= '0' && c <= '9'; });
	}

	// Cluster-internal policy replication: the follower's pull carries the
	// shared replication token, not a client bearer or signature. The endpoint
	// has its own constant-time token check behind TLS; the hardening layers
	// would only sever the pull loop between nodes.
	bool isReplicationPull(const std::string &path, const std::string &bearer)
	{
		return path == "/appmesh/auth/replication/policy" && !bearer.empty();
	}
} // namespace

RequestHardening &RequestHardening::instance()
{
	static RequestHardening singleton;
	return singleton;
}

namespace
{
	bool isFileRoute(const std::string &path)
	{
		return path == "/appmesh/file/download" || path == "/appmesh/file/upload" || path == "/appmesh/file/delete";
	}
} // namespace

std::string RequestHardening::canonicalFileRoute(const std::string &path, const std::uint8_t *&body,
												 std::size_t &bodySize)
{
	auto signingPath = path;
	if (signingPath == "/appmesh/file/download/ws" || signingPath == "/appmesh/file/upload/ws")
		signingPath.resize(signingPath.size() - 3);
	if (isFileRoute(signingPath))
	{
		body = nullptr;
		bodySize = 0;
	}
	return signingPath;
}

RequestHardening::Decision RequestHardening::evaluate(const Input &input)
{
	Decision decision;
	const auto config = Configuration::instance();
	if (!config)
		return decision; // unit-test environment; the daemon always installs one
	const auto replayMode = config->getRequestReplayProtection();
	const auto signatureMode = config->getRequestSignature();
	if (replayMode == "off" && signatureMode == "off")
		return decision;

	const auto window = std::min(std::max(config->getRequestReplayWindowSeconds(), 10), 3600);
	const bool hasSignatureHeaders = !input.keyId.empty() || !input.timestamp.empty() || !input.nonce.empty() ||
									 !input.signature.empty();
	// Signature enforcement targets authenticated client traffic. Internal
	// workflow capabilities are loopback-only and TTL-bound; public routes
	// (no credential at all) stay reachable for browsers and probes.
	const bool authenticated = !input.bearer.empty() || !input.transportPrincipal.empty();
	if (isInternalCapabilityBearer(input.bearer))
		return decision;
	if (isReplicationPull(input.path, input.bearer))
		return decision;
	if (!authenticated && !hasSignatureHeaders)
		return decision;

	// 1. Signature layer (anti-tamper).
	bool signatureValid = false;
	if (signatureMode != "off")
	{
		if (hasSignatureHeaders)
		{
			const auto verification =
				RequestSignature::verify(input.method, input.path, RequestSignature::canonicalQuery(input.query),
										  input.body, input.bodySize, input.keyId, input.timestamp, input.nonce,
										  input.signature, std::chrono::seconds(window));
			if (!verification.valid)
			{
				if (signatureMode == "enforce")
				{
					decision.action = Decision::Action::Reject;
					decision.status = 401;
					decision.reason = verification.reason;
					return decision;
				}
				decision.audit = true;
				decision.reason = "invalid request signature: " + verification.reason;
			}
			else
				signatureValid = true;
		}
		else if (authenticated)
		{
			// The agent's bearer-only precheck cannot sign; exempting it exposes
			// only whether the bearer is valid, and the handler still checks it.
			const bool agentPrecheck = input.agentPrecheck && input.method == "GET" &&
									   input.path == "/appmesh/principal/self";
			if (!agentPrecheck)
			{
				if (signatureMode == "enforce")
				{
					decision.action = Decision::Action::Reject;
					decision.status = 401;
					decision.reason = "request signature required";
					return decision;
				}
				// Audit counts unsigned traffic too, so operators see what enforce would cut.
				decision.audit = true;
				decision.reason = "request signature required";
			}
		}
	}

	// Only accountable identities reach the guard; anonymous traffic would
	// otherwise bloat the cache or churn out legitimate nonces.
	if (!authenticated && !signatureValid)
		return decision;

	// 2. Replay layer (nonce dedup). The namespace pins a nonce to one
	// identity so parallel users cannot cross-block each other.
	if (replayMode != "off")
	{
		auto nonce = input.nonce;
		if (nonce.empty() && input.persistentTransport)
			nonce = input.fallbackNonce; // WSS/TCP per-message uuid
		if (!nonce.empty() && !RequestSignature::isNonceShape(nonce))
			// Replay-only deployments have no signature layer to validate the
			// shape: malformed nonces skip dedup instead of feeding the guard
			// unbounded material.
			nonce.clear();
		if (nonce.empty())
		{
			if (replayMode == "enforce" && authenticated)
			{
				decision.action = Decision::Action::Reject;
				decision.status = 401;
				decision.reason = "request nonce required";
				return decision;
			}
		}
		else
		{
			// A stale timestamp is rejected only when the client sent one; the
			// dedup window alone bounds requests that do not. The same +30s
			// grace as the signature verifier keeps the two layers from
			// disagreeing on a timestamp at the window edge.
			const auto acceptance = window + 30;
			if (isDigits(input.timestamp))
			{
				const auto claimed = std::stoll(input.timestamp);
				const auto now = nowSeconds();
				if (claimed < now - acceptance || claimed > now + acceptance)
				{
					if (replayMode == "enforce")
					{
						decision.action = Decision::Action::Reject;
						decision.status = 401;
						decision.reason = "request timestamp is outside the replay window";
						return decision;
					}
					decision.audit = true;
					if (decision.reason.empty())
						decision.reason = "stale request timestamp";
				}
			}
			// Namespace by the credential the authenticators see, so scheme
			// or spacing variants of one bearer share one namespace; an API
			// key names its own bucket when no bearer is present.
			std::string namespaceKey;
			if (!input.transportPrincipal.empty())
				namespaceKey = input.transportPrincipal;
			else
			{
				const auto credential = Utility::bearerCredential(input.bearer);
				if (!credential.empty())
					namespaceKey =
						"bearer:" + RequestSignature::sha256Hex(credential.data(), credential.size()).substr(0, 16);
			}
			if (namespaceKey.empty())
				// The key id is hashed (like the bearer credential) so a hostile
				// oversized X-Request-Key cannot bloat a cache entry.
				namespaceKey = input.keyId.empty()
								   ? "anonymous"
								   : "key:" + RequestSignature::sha256Hex(input.keyId.data(), input.keyId.size()).substr(0, 16);
			// Memory window equals the timestamp acceptance window: forgetting
			// earlier would re-admit a replay whose timestamp still passes.
			if (m_guard.check(namespaceKey, nonce, std::chrono::seconds(acceptance)) == ReplayGuard::Verdict::Duplicate)
			{
				if (replayMode == "enforce")
				{
					decision.action = Decision::Action::Reject;
					decision.status = 409;
					decision.reason = "replayed request nonce";
					return decision;
				}
				decision.audit = true;
				if (decision.reason.empty())
					decision.reason = "replayed request nonce";
			}
		}
	}
	return decision;
}
