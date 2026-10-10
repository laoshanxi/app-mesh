// src/daemon/process/StdoutPump.cpp
#include "StdoutPump.h"

#if !defined(_WIN32)

#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <utility>

#include <boost/asio/buffer.hpp>
#include <boost/asio/error.hpp>

#include <nlohmann/json.hpp>

#include "../../common/StreamLogger.h"
#include "../../common/Utility.h"
#include "../rest/EventDispatcher.h"
#include "ProcessService.h"

namespace
{
	constexpr size_t PUMP_READ_BUF = 64 * 1024;
	constexpr size_t COALESCE_BYTE_THRESHOLD = 256 * 1024; // emit immediately when batch fills 256 KB
	constexpr int COALESCE_WINDOW_MS = 200;				   // otherwise flush every 200 ms
}

StdoutPump::StdoutPump(std::string appName, int pipeReadFd, int diskWriteFd, std::shared_ptr<std::mutex> diskMutex)
	: m_appName(std::move(appName)),
	  m_pipeRead(PROCESS_SERVICE::instance()->io()),
	  m_diskWrite(diskWriteFd),
	  m_diskMutex(std::move(diskMutex)),
	  m_coalesceTimer(PROCESS_SERVICE::instance()->io())
{
	m_readBuf.resize(PUMP_READ_BUF);
	// The pump owns the read fd from construction; the dtor closes it.
	m_pipeRead.assign(pipeReadFd);
}

void StdoutPump::activate()
{
	if (m_stopped || m_eof)
		return;
	readSome();
}

void StdoutPump::stop()
{
	m_stopped = true;
	// Cancel first so no new completion runs, then drain synchronously.
	m_pipeRead.cancel();
	m_coalesceTimer.cancel();

	while (true)
	{
		const ssize_t n = ::read(m_pipeRead.native_handle(), m_readBuf.data(), m_readBuf.size());
		if (n <= 0)
			break; // EOF, EAGAIN, or unrecoverable error
		teeToDisk(m_readBuf.data(), static_cast<size_t>(n));
		if (m_batch.empty())
			m_batchStart = m_acceptedBytes;
		m_batch.append(m_readBuf.data(), static_cast<size_t>(n));
		m_acceptedBytes += static_cast<long>(n);
	}
	// Final flush emits a carried incomplete UTF-8 tail; no more batches follow.
	flushBatch(true);
}

void StdoutPump::readSome()
{
	// self keeps the pump alive through the in-flight read.
	auto self = shared_from_this();
	m_pipeRead.async_read_some(boost::asio::buffer(m_readBuf),
							   [self](const boost::system::error_code &ec, std::size_t n)
							   { self->onRead(ec, n); });
}

void StdoutPump::onRead(const boost::system::error_code &ec, std::size_t bytesTransferred)
{
	const static char fname[] = "StdoutPump::onRead() ";
	if (m_stopped)
		return;

	if (bytesTransferred > 0)
	{
		// Tee to disk per-read so the on-disk log keeps streaming.
		teeToDisk(m_readBuf.data(), bytesTransferred);
		if (m_batch.empty())
			m_batchStart = m_acceptedBytes;
		m_batch.append(m_readBuf.data(), bytesTransferred);
		m_acceptedBytes += static_cast<long>(bytesTransferred);
		if (m_batch.size() >= COALESCE_BYTE_THRESHOLD)
			flushBatch(false);
		else
			armCoalesceTimer();
	}

	if (!ec)
	{
		readSome();
		return;
	}

	if (ec == boost::asio::error::operation_aborted)
		return; // stop() canceled the chain

	if (ec == boost::asio::error::eof)
		LOG_DBG << fname << "EOF on pipe for app=" << m_appName;
	else
		LOG_WAR << fname << "read failed for app=" << m_appName << " ec=" << ec.message();
	flushBatch(false);
	m_eof = true;
}

void StdoutPump::teeToDisk(const char *data, size_t length)
{
	const static char fname[] = "StdoutPump::teeToDisk() ";
	// REST reader threads share this mutex, so hold it only across the write.
	std::lock_guard guard(*m_diskMutex);
	size_t written = 0;
	while (written < length)
	{
		const ssize_t w = ::write(m_diskWrite, data + written, length - written);
		if (w <= 0)
		{
			LOG_WAR << fname << "disk write failed for app=" << m_appName << " errno=" << errno;
			break;
		}
		written += static_cast<size_t>(w);
	}
}

void StdoutPump::flushBatch(bool flushAll)
{
	if (m_timerArmed)
	{
		m_coalesceTimer.cancel();
		m_timerArmed = false;
	}
	if (m_batch.empty())
		return;

	std::string out;
	out.swap(m_batch);
	const long start = m_batchStart;
	m_batchStart = 0;
	if (!flushAll)
	{
		// A multi-byte character split at the batch boundary would render as one
		// U+FFFD per flush; keep a possible incomplete UTF-8 tail in the batch so
		// the next flush dispatches the whole character.
		const size_t tail = Utility::utf8IncompleteTailBytes(out);
		if (tail > 0)
		{
			m_batch.assign(out, out.size() - tail, tail);
			m_batchStart = start + static_cast<long>(out.size() - tail);
			out.resize(out.size() - tail);
		}
	}
	dispatchPayload(start, std::move(out));
}

void StdoutPump::armCoalesceTimer()
{
	if (m_timerArmed)
		return; // timer already armed
	m_timerArmed = true;
	auto self = shared_from_this();
	m_coalesceTimer.expires_after(std::chrono::milliseconds(COALESCE_WINDOW_MS));
	m_coalesceTimer.async_wait([self](const boost::system::error_code &ec)
							   { self->onCoalesceTimer(ec); });
}

void StdoutPump::onCoalesceTimer(const boost::system::error_code &ec)
{
	m_timerArmed = false;
	if (ec == boost::asio::error::operation_aborted || m_stopped)
		return;
	flushBatch(false);
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
		// Same UTF-8 conversion as the disk-backed output views, so event
		// subscribers and REST clients see identical text.
		payload = Utility::fileBytesToUtf8(payload);
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

#endif // !_WIN32
