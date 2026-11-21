// src/common/lwsservice/SseStream.h
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>

#include "../../daemon/rest/SseSink.h"
#include "../TimerHandler.h"

//
// Server-sent-events sink over an lws plain-HTTP connection.
//
// The stream is bound to one live HTTP wsi from the moment the request is
// accepted, so there is no attach phase: every sendEvent/sendComment hands a
// frame to WebSocketService (through the shared outgoing queue), and the IO
// loop writes it as one HTTP/1.1 chunk on the next WRITEABLE callback. Frames
// emitted before the response headers flush are buffered per connection by the
// service (bounded); every send runs under one mutex, so events, the terminal
// close and heartbeats stay strictly ordered.
//
class SseStream : public SseSink, public TimerHandler
{
public:
	// wsi: the serving connection; reqId/sessionId: the ABA pair the service
	// uses to drop frames for a recycled connection. id: registry key chosen by
	// the creator. heartbeatMs: keep-alive cadence (0 disables). Lifetime is
	// bounded by the endpoint owner, not this sink.
	SseStream(void *wsi, uint64_t reqId, uint64_t sessionId, std::string id, long heartbeatMs);
	~SseStream() override;

	SseStream(const SseStream &) = delete;
	SseStream &operator=(const SseStream &) = delete;

	const std::string &id() const { return m_id; }

	// One-shot hook fired by the first close(), outside the sink mutex so the
	// owner can tear down without re-entering under a lock. Call before startTimers().
	void setOnClosed(std::function<void()> onClosed);

	// Starts the heartbeat timer; call once after construction.
	void startTimers();

	// SseSink
	bool sendEvent(const std::string &eventName, const std::string &dataJson) override;
	bool sendComment(const std::string &text) override;
	void close() override;
	bool isOpen() const override;

private:
	bool sendFrameLocked(const std::string &frame);
	void closeLocked();

	void *const m_wsi;
	const uint64_t m_reqId;
	const uint64_t m_sessionId;
	const std::string m_id;
	const long m_heartbeatMs;
	mutable std::mutex m_mutex;
	bool m_closed{false};
	std::function<void()> m_onClosed; // fired once by close(), outside m_mutex
	std::atomic_long m_heartbeatTimerId{INVALID_TIMER_ID};
};
