// src/common/lwsservice/SseStream.cpp
#include "SseStream.h"

#include "../Utility.h"
#include "WebSocketService.h"

SseStream::SseStream(void *wsi, uint64_t reqId, uint64_t sessionId, std::string id, long heartbeatMs)
	: m_wsi(wsi), m_reqId(reqId), m_sessionId(sessionId), m_id(std::move(id)), m_heartbeatMs(heartbeatMs)
{
}

SseStream::~SseStream()
{
	// Teardown must never let an exception escape the implicitly noexcept
	// destructor: canceling the heartbeat posts into the timer io thread.
	try
	{
		{
			std::lock_guard<std::mutex> lock(m_mutex);
			closeLocked();
		}
		cancelTimer(m_heartbeatTimerId);
		// Drop the registry entry first: a reused marker id must never resolve stale.
		SseStreamRegistry::instance()->erase(m_id);
	}
	catch (...)
	{
	}
}

void SseStream::setOnClosed(std::function<void()> onClosed)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	m_onClosed = std::move(onClosed);
}

void SseStream::startTimers()
{
	if (m_heartbeatMs > 0)
	{
		// Weak capture: the timer registration already pins this object, so a
		// strong capture would make teardown self-referential.
		const std::weak_ptr<SseStream> weak = std::static_pointer_cast<SseStream>(TimerHandler::shared_from_this());
		registerTimer(m_heartbeatTimerId, static_cast<std::size_t>(m_heartbeatMs), static_cast<std::size_t>(m_heartbeatMs),
					  "sse-heartbeat",
					  [weak]()
					  {
						  auto sink = weak.lock();
						  if (!sink)
							  return false;
						  if (sink->sendComment("ping"))
							  return true;
						  // Failed keep-alive means the peer is gone: close so the
						  // owner unsubscribes instead of idling to the timeout.
						  sink->close();
						  return false;
					  });
	}
}

bool SseStream::sendEvent(const std::string &eventName, const std::string &dataJson)
{
	// dataJson arrives pre-serialized; the JSON dump escapes newlines, so a frame never splits.
	std::lock_guard<std::mutex> lock(m_mutex);
	if (m_closed)
		return false;
	return sendFrameLocked("event: " + eventName + "\ndata: " + dataJson + "\n\n");
}

bool SseStream::sendComment(const std::string &text)
{
	std::lock_guard<std::mutex> lock(m_mutex);
	if (m_closed)
		return false;
	return sendFrameLocked(": " + text + "\n\n");
}

void SseStream::close()
{
	std::function<void()> onClosed;
	{
		std::lock_guard<std::mutex> lock(m_mutex);
		closeLocked(); // idempotent; a prior internal close keeps this a no-op
		if (m_onClosed)
			onClosed = std::move(m_onClosed); // one-shot, even across threads
	}
	// Fired without m_mutex held: the hook re-enters this sink and must not
	// deadlock against a concurrent sendEvent.
	if (onClosed)
		onClosed();
}

bool SseStream::isOpen() const
{
	std::lock_guard<std::mutex> lock(m_mutex);
	return !m_closed;
}

bool SseStream::sendFrameLocked(const std::string &frame)
{
	if (m_closed)
		return false;
	// A closed/recycled connection drops the frame in the service; a failed
	// keep-alive is how the heartbeat detects a gone peer.
	WebSocketService::instance()->enqueueSseFrame(m_wsi, m_reqId, m_sessionId, frame, false);
	return true;
}

void SseStream::closeLocked()
{
	if (m_closed)
		return;
	m_closed = true;
	// Stop the heartbeat here so teardown does not wait out the next tick.
	cancelTimer(m_heartbeatTimerId);
	// Empty frame body marks the terminal chunk; the service flushes the
	// already-queued frames first, so ordering is preserved.
	WebSocketService::instance()->enqueueSseFrame(m_wsi, m_reqId, m_sessionId, "", true);
}
