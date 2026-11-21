// src/daemon/rest/drogon/SseStream.cpp
#include "SseStream.h"

#include "../../../common/StreamLogger.h"

#include <utility>

namespace
{
	// Cap on frames buffered before the response stream attaches.
	constexpr std::size_t MAX_PENDING_FRAMES_BYTES = 1024 * 1024;
}

SseStream::SseStream(std::string id, long heartbeatMs) : m_id(std::move(id)), m_heartbeatMs(heartbeatMs) {}

SseStream::~SseStream()
{
	// Teardown must never let an exception escape the implicitly noexcept
	// destructor: canceling the heartbeat posts into the io loop (allocating),
	// and a failing allocation here would terminate the whole daemon.
	try
	{
		{
			std::lock_guard lock(m_mutex);
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
	std::lock_guard lock(m_mutex);
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

void SseStream::attachStream(drogon::ResponseStreamPtr stream)
{
	std::lock_guard lock(m_mutex);
	if (!stream)
		return;
	if (m_closed)
	{
		// The endpoint finished before the IO loop delivered the stream: still
		// flush the buffered frames, then close the chunked transfer.
		m_stream = std::move(stream);
		while (!m_pending.empty())
		{
			if (!m_stream->send(m_pending.front()))
				break;
			m_pendingBytes -= m_pending.front().size();
			m_pending.pop_front();
		}
		m_pending.clear();
		m_pendingBytes = 0;
		m_stream->close();
		m_stream.reset();
		return;
	}
	m_stream = std::move(stream);
	while (!m_pending.empty())
	{
		if (!sendFrameLocked(m_pending.front()))
		{
			closeLocked();
			return;
		}
		m_pendingBytes -= m_pending.front().size();
		m_pending.pop_front();
	}
}

bool SseStream::sendEvent(const std::string &eventName, const std::string &dataJson)
{
	// dataJson arrives pre-serialized; jsoncpp escapes newlines, so a frame never splits.
	std::lock_guard lock(m_mutex);
	if (m_closed)
		return false;
	return sendFrameLocked("event: " + eventName + "\ndata: " + dataJson + "\n\n");
}

bool SseStream::sendComment(const std::string &text)
{
	std::lock_guard lock(m_mutex);
	if (m_closed)
		return false;
	return sendFrameLocked(": " + text + "\n\n");
}

void SseStream::close()
{
	std::function<void()> onClosed;
	{
		std::lock_guard lock(m_mutex);
		closeLocked(); // idempotent; a prior internal close keeps this a no-op
		if (m_onClosed)
			// Explicit: a moved-from std::function can stay callable under the SBO.
			onClosed = std::exchange(m_onClosed, nullptr);
	}
	// Fired without m_mutex held: the hook re-enters this sink and must not
	// deadlock against a concurrent sendEvent.
	if (onClosed)
		onClosed();
}

bool SseStream::isOpen() const
{
	std::lock_guard lock(m_mutex);
	return !m_closed;
}

bool SseStream::sendFrameLocked(const std::string &frame)
{
	if (m_closed)
		return false;
	if (!m_stream)
	{
		// A client that never lets the response start must not pin worker
		// memory: refuse the stream instead of buffering past the cap.
		if (m_pendingBytes + frame.size() > MAX_PENDING_FRAMES_BYTES)
		{
			const static char fname[] = "SseStream::sendFrameLocked() ";
			LOG_WAR << fname << "pending frame buffer overflow, closing stream <" << m_id << ">";
			closeLocked();
			return false;
		}
		m_pendingBytes += frame.size();
		m_pending.push_back(frame);
		return true;
	}
	return m_stream->send(frame);
}

void SseStream::closeLocked()
{
	if (m_closed)
		return;
	m_closed = true;
	// Stop the heartbeat here so teardown does not wait out the next tick.
	cancelTimer(m_heartbeatTimerId);
	if (m_stream)
	{
		m_pending.clear();
		m_pendingBytes = 0;
		m_stream->close(); // terminal chunk, then the transport drops the connection
		m_stream.reset();
	}
	// No response stream yet: attachStream() flushes the buffered frames later.
}
