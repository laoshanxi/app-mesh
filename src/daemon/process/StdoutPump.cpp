// src/daemon/process/StdoutPump.cpp
#include "StdoutPump.h"

#if !defined(_WIN32)

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <map>
#include <thread>
#include <utility>

#include <json/json.h>

#include "../../common/AtomicHandleGuard.hpp"
#include "../../common/StreamLogger.h"
#include "../../common/Utility.h"
#include "../rest/EventDispatcher.h"

namespace
{
	constexpr size_t PUMP_READ_BUF = 64 * 1024;
	constexpr int PUMP_POLL_MS = 200;                      // poll cadence and coalesce flush window
	constexpr size_t COALESCE_BYTE_THRESHOLD = 256 * 1024; // emit immediately when batch fills 256 KB
} // namespace

// Matches the friend declaration in StdoutPump.h: external linkage.
// One thread polling every live pump's pipe plus a self-pipe for registry
// wakeups. Pumps register shared_ptr copies, so a dispatched pump stays
// alive for the duration of the callback; stop() unregisters and then
// waits for m_pollActive to clear before touching the pipe itself.
class PumpPoller
{
public:
	static PumpPoller &instance()
	{
		// Leaky on purpose: process-exit destruction order versus other
		// daemon singletons is unspecified, and the thread must never be
		// joined from a static destructor. Runtime shutdown joins it via
		// shutdown().
		static PumpPoller *const poller = new PumpPoller();
		return *poller;
	}

	void add(const std::shared_ptr<StdoutPump> &pump)
	{
		{
			std::lock_guard lock(m_mutex);
			if (m_stopped)
				return;
			m_pumps[pump.get()] = pump;
		}
		wake();
	}

	void remove(StdoutPump *key)
	{
		{
			std::lock_guard lock(m_mutex);
			m_pumps.erase(key);
		}
		// Do not hold the registry lock while waiting: the poller takes it
		// after finishing a callback.
		while (key->m_pollActive.load(std::memory_order_acquire))
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
	}

	void shutdown()
	{
		std::thread worker;
		{
			std::lock_guard lock(m_mutex);
			if (m_stopped.exchange(true))
				return;
			worker = std::move(m_thread);
			m_pumps.clear();
		}
		wake();
		if (worker.joinable())
			worker.join();
	}

private:
	PumpPoller()
	{
		if (::pipe(m_wakeFd) != 0)
		{
			m_wakeFd[0] = m_wakeFd[1] = -1;
			// Without a wake pipe registry changes only take effect on the
			// next poll timeout.
		}
		else
		{
			// Both ends nonblocking: the drain loop in run() must never
			// block, and a stalled poller must not block wake() callers.
			for (const int fd : m_wakeFd)
			{
				const int flags = ::fcntl(fd, F_GETFL, 0);
				if (flags >= 0)
					::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
			}
		}
		m_thread = std::thread([this] { run(); });
	}

	void wake()
	{
		if (m_wakeFd[1] != -1)
		{
			const char byte = 1;
			if (::write(m_wakeFd[1], &byte, 1) < 0)
			{
				// Best effort: a byte is already pending or the loop is
				// about to hit its poll timeout.
			}
		}
	}

	void run()
	{
		const static char fname[] = "PumpPoller::run() ";
		while (true)
		{
			// Snapshot the registry, holding shared_ptrs for dispatch.
			std::vector<std::shared_ptr<StdoutPump>> pumps;
			{
				std::lock_guard lock(m_mutex);
				if (m_stopped.load(std::memory_order_acquire))
					return;
				pumps.reserve(m_pumps.size());
				for (const auto &[key, value] : m_pumps)
					pumps.push_back(value);
			}
			std::vector<struct pollfd> fds;
			fds.reserve(pumps.size() + 1);
			for (const auto &pump : pumps)
				fds.push_back({static_cast<int>(pump->m_pipeReadFd), POLLIN, 0});
			if (m_wakeFd[0] != -1)
				fds.push_back({m_wakeFd[0], POLLIN, 0});
			const std::size_t wakeSlot = m_wakeFd[0] != -1 ? fds.size() - 1 : static_cast<std::size_t>(-1);

			const int rc = ::poll(fds.data(), static_cast<nfds_t>(fds.size()), PUMP_POLL_MS);
			if (rc < 0 && errno == EINTR)
				continue;
			if (rc < 0)
			{
				LOG_WAR << fname << "poll failed errno=" << errno;
				continue;
			}
			if (wakeSlot != static_cast<std::size_t>(-1) && (fds[wakeSlot].revents & POLLIN))
			{
				char drained[64];
				while (::read(m_wakeFd[0], drained, sizeof(drained)) > 0)
				{
				}
			}
			std::vector<StdoutPump *> retire;
			for (std::size_t i = 0; i < pumps.size(); ++i)
			{
				const auto &pump = pumps[i];
				if (fds[i].revents & POLLNVAL)
				{
					// A closed fd still registered (only possible through a
					// lost stop race): drop it before it spins the poll.
					LOG_ERR << fname << "fd <" << fds[i].fd << "> for app=" << pump->m_appName
							<< " is closed while registered, dropping from the poll set";
					retire.push_back(pump.get());
					continue;
				}
				if (fds[i].revents & (POLLIN | POLLHUP | POLLERR))
				{
					// A throw out of the callback would terminate the
					// daemon; the pump stays registered and retries on the
					// next event.
					pump->m_pollActive.store(true, std::memory_order_release);
					try
					{
						pump->handleReadable();
					}
					catch (const std::exception &e)
					{
						LOG_CRT << fname << "read callback failed for app=" << pump->m_appName << ": " << e.what();
					}
					pump->m_pollActive.store(false, std::memory_order_release);
					if (pump->m_eof.load(std::memory_order_acquire))
						retire.push_back(pump.get());
				}
			}
			if (!retire.empty())
			{
				// Retired pumps (EOF or dropped) never produce more
				// events; drop them so the poll set keeps shrinking.
				std::lock_guard lock(m_mutex);
				for (auto *pump : retire)
					m_pumps.erase(pump);
			}
			// Coalesce pass: emits batches whose window has aged out even
			// when sibling pipes kept poll() returning data every cycle.
			for (const auto &pump : pumps)
			{
				pump->m_pollActive.store(true, std::memory_order_release);
				try
				{
					pump->flushIdle();
				}
				catch (const std::exception &e)
				{
					LOG_CRT << fname << "flush callback failed for app=" << pump->m_appName << ": " << e.what();
				}
				pump->m_pollActive.store(false, std::memory_order_release);
			}
		}
	}

	std::mutex m_mutex;
	std::map<StdoutPump *, std::shared_ptr<StdoutPump>> m_pumps;
	std::thread m_thread;
	int m_wakeFd[2] = {-1, -1};
	std::atomic<bool> m_stopped{false};
};

void StopStdoutPumpPoller() { PumpPoller::instance().shutdown(); }

StdoutPump::StdoutPump(std::string appName, int pipeReadFd, int diskWriteFd, std::shared_ptr<std::mutex> diskMutex)
	: m_appName(std::move(appName)), m_pipeReadFd(pipeReadFd), m_diskWrite(diskWriteFd), m_diskMutex(std::move(diskMutex))
{
	m_readBuf.resize(PUMP_READ_BUF);
	// Identity for the closed/reused-fd diagnostic in stop().
	if (m_pipeReadFd != INVALID_FD)
	{
		struct stat st;
		if (::fstat(m_pipeReadFd, &st) == 0)
		{
			m_pipeStatDev = st.st_dev;
			m_pipeStatIno = st.st_ino;
			m_pipeStatMode = st.st_mode;
			m_statValid = true;
		}
	}
}

StdoutPump::~StdoutPump()
{
	// Covers a pump that was never stopped (shutdown skips teardown): make
	// the pipe safe to touch, drain, then close.
	if (!m_stopped.load(std::memory_order_acquire))
		stop();
	if (m_pipeReadFd != INVALID_FD)
		::close(m_pipeReadFd);
}

void StdoutPump::activate()
{
	if (m_stopped.load(std::memory_order_acquire) || m_eof.load(std::memory_order_acquire))
		return;
	PumpPoller::instance().add(shared_from_this());
	// stop() may have raced the registration: undo it, or the poller would
	// hold a pump whose dtor is about to close the fd.
	if (m_stopped.load(std::memory_order_acquire))
		PumpPoller::instance().remove(this);
}

void StdoutPump::stop()
{
	const static char fname[] = "StdoutPump::stop() ";
	if (m_stopped.exchange(true, std::memory_order_acq_rel))
		return;
	// Unconditional and idempotent: also detaches a pump whose activate() is
	// still queued or raced, and waits out any in-flight poller callback.
	PumpPoller::instance().remove(this);

	// The fd must still be the pipe created for this run. A mismatch means
	// something closed it behind the pump and the number got recycled: the
	// drain would silently read a foreign object and the child's buffered
	// output is already gone.
	if (m_pipeReadFd != INVALID_FD && m_statValid)
	{
		struct stat now;
		if (::fstat(m_pipeReadFd, &now) != 0)
		{
			LOG_ERR << fname << "pipe fd <" << m_pipeReadFd << "> for app=" << m_appName
					<< " no longer matches the created pipe (fstat errno=" << errno << "): output loss expected";
		}
		else if (now.st_dev != m_pipeStatDev || now.st_ino != m_pipeStatIno || now.st_mode != m_pipeStatMode)
		{
			LOG_ERR << fname << "pipe fd <" << m_pipeReadFd << "> for app=" << m_appName
					<< " no longer matches the created pipe (mode=" << std::oct << now.st_mode << std::dec
					<< " want=" << std::oct << m_pipeStatMode << std::dec << " ino=" << now.st_ino
					<< " want=" << m_pipeStatIno << "): output loss expected";
		}
	}

	// Belt and suspenders: drain synchronously (the poller only exits before
	// EOF when stopped), then final-flush the batch. A bad_alloc mid-drain
	// keeps whatever was accumulated.
	if (m_pipeReadFd != INVALID_FD && !m_eof.load(std::memory_order_acquire))
	{
		try
		{
			while (true)
			{
				const ssize_t n = ::read(m_pipeReadFd, m_readBuf.data(), m_readBuf.size());
				if (n < 0 && errno == EINTR)
					continue; // EINTR: retry
				if (n <= 0)
					break; // EOF, EAGAIN, or unrecoverable error
				accumulate(static_cast<size_t>(n));
			}
		}
		catch (const std::exception &e)
		{
			LOG_CRT << fname << "drain failed for app=" << m_appName << ": " << e.what();
		}
	}
	try
	{
		flushBatch(true); // final flush emits a carried incomplete UTF-8 tail
	}
	catch (const std::exception &e)
	{
		LOG_CRT << fname << "final flush failed for app=" << m_appName << ": " << e.what();
	}
}

void StdoutPump::handleReadable()
{
	const static char fname[] = "StdoutPump::handleReadable() ";
	if (m_stopped.load(std::memory_order_acquire))
		return;
	while (true)
	{
		const ssize_t n = ::read(m_pipeReadFd, m_readBuf.data(), m_readBuf.size());
		if (n < 0 && errno == EINTR)
			continue; // EINTR: retry
		if (n < 0)
		{
			if (errno != EAGAIN && errno != EWOULDBLOCK)
				LOG_WAR << fname << "read failed for app=" << m_appName << " errno=" << errno;
			return; // drained for now
		}
		if (n == 0)
		{
			// EOF: every writer (including grandchildren holding inherited
			// copies) is gone.
			LOG_DBG << fname << "EOF on pipe for app=" << m_appName;
			m_eof.store(true, std::memory_order_release);
			flushBatch(false);
			return;
		}
		accumulate(static_cast<size_t>(n));
		if (m_batch.size() >= COALESCE_BYTE_THRESHOLD)
			flushBatch(false);
	}
}

// Tees one read into the disk file and batches it for the next event flush.
void StdoutPump::accumulate(size_t length)
{
	teeToDisk(m_readBuf.data(), length);
	if (m_batch.empty())
	{
		m_batchStart = m_acceptedBytes.load(std::memory_order_relaxed);
		m_batchSince = std::chrono::steady_clock::now();
	}
	m_batch.append(m_readBuf.data(), length);
	m_acceptedBytes.fetch_add(static_cast<long>(length), std::memory_order_acq_rel);
}

void StdoutPump::flushIdle()
{
	if (m_stopped.load(std::memory_order_acquire) || m_batch.empty())
		return;
	if (std::chrono::steady_clock::now() - m_batchSince < std::chrono::milliseconds(PUMP_POLL_MS))
		return;
	flushBatch(false);
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
		if (w < 0 && errno == EINTR)
			continue; // EINTR: retry
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
		Json::Value data;
		data["output"] = std::move(payload);
		data["position"] = (Json::Int64)start;
		data["finished"] = false;
		dispatcher->dispatch(m_appName, AppEventType::STDOUT_OUTPUT, data);
	}
	catch (const std::exception &e)
	{
		LOG_WAR << fname << "dispatch failed for app=" << m_appName << ": " << e.what();
	}
}

#endif // !_WIN32
