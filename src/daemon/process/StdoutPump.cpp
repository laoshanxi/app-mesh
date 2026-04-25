// src/daemon/process/StdoutPump.cpp
#include "StdoutPump.h"

#include <cerrno>
#include <utility>

#include <ace/OS_NS_Thread.h>
#include <ace/OS_NS_errno.h>
#include <ace/OS_NS_unistd.h>
#include <ace/Reactor.h>

#include <nlohmann/json.hpp>

#include "../../common/StreamLogger.h"
#include "../rest/EventDispatcher.h"

namespace
{
	constexpr size_t PUMP_READ_BUF = 64 * 1024;
	constexpr size_t COALESCE_BYTE_THRESHOLD = 256 * 1024; // emit immediately when batch fills 256 KB
	constexpr int COALESCE_WINDOW_MS = 200;				   // otherwise flush every 200 ms
}

StdoutPump::StdoutPump(std::string appName, ACE_HANDLE pipeRead, ACE_HANDLE diskWrite, std::shared_ptr<std::recursive_mutex> diskMutex)
	: m_appName(std::move(appName)),
	  m_pipeRead(pipeRead),
	  m_diskWrite(diskWrite),
	  m_diskMutex(std::move(diskMutex)),
	  m_acceptedBytes(0),
	  m_stopped(false)
{
	this->reference_counting_policy().value(ACE_Event_Handler::Reference_Counting_Policy::ENABLED);
}

StdoutPump::~StdoutPump()
{
	if (m_pipeRead != ACE_INVALID_HANDLE)
		ACE_OS::close(m_pipeRead);
}

int StdoutPump::handle_input(ACE_HANDLE)
{
	const static char fname[] = "StdoutPump::handle_input() ";

	// ACE Reference_Counting_Policy already pinned us before this call; no
	// custom inflight guard is needed.
	if (m_stopped.load(std::memory_order_acquire))
		return -1;

	char buf[PUMP_READ_BUF];
	int returnCode = 0;
	bool needFlushRemaining = false;

	while (true)
	{
		if (m_pipeRead == ACE_INVALID_HANDLE)
		{
			returnCode = -1;
			needFlushRemaining = true;
			break;
		}

		ssize_t n = ACE_OS::read(m_pipeRead, buf, sizeof(buf));
		if (n > 0)
		{
			// Tee to disk per-read so the on-disk log keeps streaming.
			{
				std::lock_guard<std::recursive_mutex> dg(*m_diskMutex);
				const size_t total = static_cast<size_t>(n);
				size_t written = 0;
				while (written < total)
				{
					ssize_t w = ACE_OS::write(m_diskWrite, buf + written, total - written);
					if (w <= 0)
					{
						LOG_WAR << fname << "disk write failed for app=" << m_appName << " errno=" << ACE_OS::last_error();
						break;
					}
					written += static_cast<size_t>(w);
				}
			}

			// Append to coalesce buffer; flush immediately on byte threshold,
			// otherwise arm the timer. Dispatch happens OUTSIDE the lock so a
			// slow ws fanout cannot stall reactor threads competing for m_coalesceMu.
			std::string out;
			long start = 0;
			bool needDispatch = false;
			{
				std::lock_guard<std::mutex> cg(m_coalesceMu);
				if (m_batch.empty())
					m_batchStart = m_acceptedBytes.load(std::memory_order_relaxed);
				m_batch.append(buf, static_cast<size_t>(n));
				m_acceptedBytes.fetch_add(n, std::memory_order_release);
				if (m_batch.size() >= COALESCE_BYTE_THRESHOLD)
				{
					extractBatchLocked(out, start);
					needDispatch = true;
				}
				else
				{
					scheduleCoalesceTimerLocked();
				}
			}
			if (needDispatch)
				dispatchPayload(start, std::move(out));
			continue;
		}

		if (n == 0)
		{
			LOG_DBG << fname << "EOF on pipe for app=" << m_appName;
			returnCode = -1;
			needFlushRemaining = true;
			break;
		}

		const int err = ACE_OS::last_error();
#if defined(_WIN32)
		if (err == EAGAIN || err == EWOULDBLOCK || err == WSAEWOULDBLOCK)
#else
		if (err == EAGAIN || err == EWOULDBLOCK)
#endif
		{
			returnCode = 0;
			break;
		}
		if (err == EINTR)
			continue;
		LOG_WAR << fname << "read failed for app=" << m_appName << " errno=" << err;
		returnCode = -1;
		needFlushRemaining = true;
		break;
	}

	if (needFlushRemaining)
	{
		std::string out;
		long start = 0;
		{
			std::lock_guard<std::mutex> cg(m_coalesceMu);
			extractBatchLocked(out, start);
		}
		dispatchPayload(start, std::move(out));
	}
	return returnCode;
}

int StdoutPump::handle_timeout(const ACE_Time_Value &, const void *)
{
	// ACE pins us via add_reference before this call.
	if (m_stopped.load(std::memory_order_acquire))
		return 0;

	std::string out;
	long start = 0;
	{
		std::lock_guard<std::mutex> cg(m_coalesceMu);
		m_timerId = -1; // ACE has already removed the one-shot timer
		extractBatchLocked(out, start);
	}
	dispatchPayload(start, std::move(out));
	return 0;
}

void StdoutPump::scheduleCoalesceTimerLocked()
{
	if (m_timerId >= 0)
		return; // timer already armed
	auto *reactor = ACE_Reactor::instance();
	if (!reactor)
		return;
	ACE_Time_Value delay(0, COALESCE_WINDOW_MS * 1000);
	long id = reactor->schedule_timer(this, nullptr, delay);
	if (id >= 0)
		m_timerId = id;
}

void StdoutPump::extractBatchLocked(std::string &out, long &start)
{
	if (m_timerId >= 0)
	{
		if (auto *reactor = ACE_Reactor::instance())
			reactor->cancel_timer(m_timerId);
		m_timerId = -1;
	}
	out.clear();
	if (m_batch.empty())
		return;
	out.swap(m_batch);
	start = m_batchStart;
	m_batchStart = 0;
}

void StdoutPump::dispatchPayload(long start, std::string &&payload)
{
	if (payload.empty())
		return;
	const static char fname[] = "StdoutPump::dispatchPayload() ";
	auto *dispatcher = EventDispatcher::instance();
	if (!dispatcher || !dispatcher->hasStdoutSubscriber(m_appName))
		return;
	try
	{
		nlohmann::json data;
		data["output"] = std::move(payload);
		data["position"] = start;
		data["finished"] = false;
		dispatcher->dispatch(m_appName, AppEventType::STDOUT_OUTPUT, data);
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "dispatch failed for app=" << m_appName << ": " << e.what();
	}
}

void StdoutPump::finalSyncDrain()
{
	const static char fname[] = "StdoutPump::finalSyncDrain() ";
	if (m_pipeRead == ACE_INVALID_HANDLE)
		return;

	char buf[PUMP_READ_BUF];
	while (true)
	{
		ssize_t n = ACE_OS::read(m_pipeRead, buf, sizeof(buf));
		if (n <= 0)
			break; // EOF, EAGAIN, or unrecoverable error

		{
			std::lock_guard<std::recursive_mutex> dg(*m_diskMutex);
			const size_t total = static_cast<size_t>(n);
			size_t written = 0;
			while (written < total)
			{
				ssize_t w = ACE_OS::write(m_diskWrite, buf + written, total - written);
				if (w <= 0)
				{
					LOG_WAR << fname << "disk write failed for app=" << m_appName << " errno=" << ACE_OS::last_error();
					break;
				}
				written += static_cast<size_t>(w);
			}
		}

		std::lock_guard<std::mutex> cg(m_coalesceMu);
		if (m_batch.empty())
			m_batchStart = m_acceptedBytes.load(std::memory_order_relaxed);
		m_batch.append(buf, static_cast<size_t>(n));
		m_acceptedBytes.fetch_add(n, std::memory_order_release);
	}
}

void StdoutPump::cancelCoalesceTimerAndFlush()
{
	std::string out;
	long start = 0;
	{
		std::lock_guard<std::mutex> cg(m_coalesceMu);
		extractBatchLocked(out, start);
	}
	dispatchPayload(start, std::move(out));
}

int StdoutPump::handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask)
{
	const static char fname[] = "StdoutPump::handle_close() ";
	LOG_DBG << fname << "app=" << m_appName << " mask=" << close_mask;

	(void)handle;
	if (m_pipeRead != ACE_INVALID_HANDLE)
	{
		ACE_OS::close(m_pipeRead);
		m_pipeRead = ACE_INVALID_HANDLE;
	}
	return 0;
}
