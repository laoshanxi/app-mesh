// src/daemon/rest/drogon/SseStream.h
#pragma once

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

#include <drogon/HttpResponse.h>

#include "../../../common/TimerHandler.h"
#include "../SseSink.h"

// Server-sent-events sink over a drogon async chunked response.
//
// Frames emitted before the response stream attaches are buffered (bounded)
// and flushed in order; every send runs under one mutex, so events, the
// terminal close and heartbeats stay strictly ordered.
class SseStream : public SseSink, public TimerHandler
{
public:
	// id: registry key chosen by the creator; heartbeatMs: keep-alive cadence
	// (0 disables). Lifetime is bounded by the endpoint owner, not this sink.
	SseStream(std::string id, long heartbeatMs);
	~SseStream() override;

	SseStream(const SseStream &) = delete;
	SseStream &operator=(const SseStream &) = delete;

	const std::string &id() const { return m_id; }

	// One-shot hook fired by the first close(), outside the sink mutex so the
	// owner can tear down without re-entering under a lock. Call before startTimers().
	void setOnClosed(std::function<void()> onClosed);

	// Starts the heartbeat timer; call once after construction.
	void startTimers();
	// Takes ownership of the drogon response stream and flushes buffered frames.
	void attachStream(drogon::ResponseStreamPtr stream);

	// SseSink
	bool sendEvent(const std::string &eventName, const std::string &dataJson) override;
	bool sendComment(const std::string &text) override;
	void close() override;
	bool isOpen() const override;

private:
	bool sendFrameLocked(const std::string &frame);
	void closeLocked();

	const std::string m_id;
	const long m_heartbeatMs;
	mutable std::mutex m_mutex;
	drogon::ResponseStreamPtr m_stream; // arrives asynchronously from the IO loop
	std::deque<std::string> m_pending;  // frames buffered until the stream attaches
	std::size_t m_pendingBytes{0};
	bool m_closed{false};
	std::function<void()> m_onClosed; // fired once by close(), outside m_mutex
	std::atomic_long m_heartbeatTimerId{INVALID_TIMER_ID};
};
