// src/daemon/process/StdoutPump.h
#pragma once

#if !defined(_WIN32)

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

// asio-driven pump on the ProcessService thread: reads child stdout from a
// pipe, tees to disk, dispatches STDOUT_OUTPUT events. All state lives on the
// io thread; the only lock is the shared disk mutex.
class StdoutPump : public std::enable_shared_from_this<StdoutPump>
{
public:
	StdoutPump(std::string appName, int pipeReadFd, int diskWriteFd, std::shared_ptr<std::mutex> diskMutex);
	~StdoutPump() = default; // stream_descriptor dtor closes the read fd

	StdoutPump(const StdoutPump &) = delete;
	StdoutPump &operator=(const StdoutPump &) = delete;

	// io thread only; starts the read chain. No-op when stopped or at EOF.
	void activate();

	// io thread only, idempotent. Cancels the async chain, synchronously drains
	// the pipe, and final-flushes the batch (mirrors the old
	// deregister-before-drain ordering).
	void stop();

	// io thread only; the strategy snapshots it after stop().
	long acceptedBytes() const { return m_acceptedBytes; }

private:
	void readSome();
	void onRead(const boost::system::error_code &ec, std::size_t bytesTransferred);
	void teeToDisk(const char *data, size_t length);
	// flushAll also emits a trailing incomplete character instead of carrying it
	// into a next batch that never comes (teardown path).
	void flushBatch(bool flushAll);
	void armCoalesceTimer();
	void onCoalesceTimer(const boost::system::error_code &ec);
	void dispatchPayload(long start, std::string &&payload);

	const std::string m_appName;
	boost::asio::posix::stream_descriptor m_pipeRead; // owns the fd, closes in dtor
	const int m_diskWrite; // AppProcess owns this handle
	// shared_ptr so the mutex outlives whichever (pump or AppProcess) destructs first.
	const std::shared_ptr<std::mutex> m_diskMutex;
	boost::asio::steady_timer m_coalesceTimer;
	bool m_timerArmed{false};
	bool m_stopped{false};
	bool m_eof{false};
	// Coalesce window — collects reads into a single STDOUT_OUTPUT event,
	// flushed on byte threshold, timer, or teardown.
	std::string m_batch;
	long m_batchStart{0};
	long m_acceptedBytes{0};
	std::vector<char> m_readBuf; // 64 KB, resized in ctor
};

#endif // !_WIN32
