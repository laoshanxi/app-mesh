// src/daemon/rest/ForwardingStream.h
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

/// Connection parameters of one outbound forwarding hop.
struct ForwardingConnectOptions
{
	std::string host;	// peer host name, also the expected TLS host name
	int port = -1;
	std::string ca;		// resolved CA file; empty means the default trust store
	bool verifyPeer = false;
	std::string bearer;	// Authorization header value; empty when the request had none
	std::string clientCert;	// resolved client certificate for mTLS peers; empty when unconfigured
	std::string clientKey;	// resolved private key of the client certificate
	int timeoutSeconds = 10;
};

/// Outbound transport of one daemon-to-daemon forwarding connection:
/// TcpClientStream (TCP API) or LwsForwardingStream (WSS, tiers without Drogon).
/// Framing is transport specific; request/response correlation stays in ForwardingManager.
class ForwardingStream
{
public:
	using DataCallback = std::function<void(std::vector<std::uint8_t> &&)>;
	using CloseCallback = std::function<void()>;

	virtual ~ForwardingStream() = default;

	/// Both callbacks must be set before connect(); they fire on the transport thread.
	virtual void onData(DataCallback cb) = 0;
	virtual void onClose(CloseCallback cb) = 0;

	/// Blocking connect, bounded by options.timeoutSeconds.
	virtual bool connect(const ForwardingConnectOptions &options) = 0;

	/// False only when the connection is gone; never for transient backpressure.
	virtual bool send(const char *data, std::size_t len) = 0;

	/// Idempotent; safe before connect() and after a close.
	virtual void shutdown() = 0;
	virtual bool connected() const = 0;

	/// True when the peer pins the identity presented at the upgrade, so one
	/// connection cannot serve two bearers.
	virtual bool pinsHandshakePrincipal() const { return false; }
};
