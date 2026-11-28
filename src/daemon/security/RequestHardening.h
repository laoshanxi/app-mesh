#pragma once

#include <cstdint>
#include <map>
#include <string>

#include "ReplayGuard.h"

/// Per-request anti-replay and signature enforcement (REST.RequestReplayProtection
/// / REST.RequestSignature). This is the shared decision point for every
/// transport: Worker::process feeds it the deserialized request, and the
/// transfer handlers feed it the streamed-upload view (no body binding).
///
/// evaluate() is pure: it never replies, it decides. Callers own the response.
class RequestHardening
{
public:
	struct Input
	{
		std::string method; // upper-case HTTP method
		std::string path;   // request path as carried, query stripped
		std::map<std::string, std::string> query;
		const std::uint8_t *body = nullptr; // null + zero size on streamed endpoints
		std::size_t bodySize = 0;
		std::string bearer;             // raw Authorization value, empty when absent
		std::string transportPrincipal; // WSS-pinned principal, empty otherwise
		/// TCP/WSS transports can receive event frames; their per-message uuid
		/// doubles as the replay nonce so old clients need no change.
		bool persistentTransport = false;
		std::string fallbackNonce; // request uuid
		// The four signature headers, empty when absent.
		std::string keyId;
		std::string timestamp;
		std::string nonce;
		std::string signature;
		/// X-Appmesh-Agent-Precheck == "1": the separate agent's forwarding
		/// precheck marker (see the signature-required exemption in evaluate).
		bool agentPrecheck = false;
	};

	struct Decision
	{
		enum class Action
		{
			Allow,
			Reject,
		};
		Action action = Action::Allow;
		int status = 0;      // HTTP status on Reject
		std::string reason;  // rejection / audit detail
		bool audit = false;  // true when a violation was detected but tolerated
	};

	static RequestHardening &instance();

	/// Canonical signing view of a file route: the WSS data-channel "/ws"
	/// suffix selects the transfer channel, not the resource, so it is not
	/// part of the signed path; the five file routes hash the empty body by
	/// spec, whatever the frame carries. Returns the path to sign and clears
	/// body/bodySize when the route hashes empty. Non-file paths pass through.
	static std::string canonicalFileRoute(const std::string &path, const std::uint8_t *&body, std::size_t &bodySize);

	RequestHardening() = default;

	Decision evaluate(const Input &input);

	/// Exposed for tests and for the daemon's own loopback internal capabilities,
	/// which are loopback-only and TTL-bound (see InternalCapability).
	const ReplayGuard &guard() const { return m_guard; }

private:
	ReplayGuard m_guard;

	RequestHardening(const RequestHardening &) = delete;
	RequestHardening &operator=(const RequestHardening &) = delete;
};
