// src/daemon/process/StdoutPump.h
#pragma once

#if !defined(_WIN32)

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <vector>

class PumpPoller;

// Pipe reader for captured stdout: a shared poller thread (see PumpPoller in
// the .cpp) polls every live pump's pipe, tees to disk, and dispatches
// STDOUT_OUTPUT events. The pumps deliberately keep their pipes OFF the asio
// reactor: under concurrent-run launch storms the reactor's completion
// pipeline was observed consuming pipe bytes whose completions never reached
// the handler (zero-byte capture with exit code 0), so stdout correctness no
// longer depends on any reactor state.
class StdoutPump : public std::enable_shared_from_this<StdoutPump>
{
public:
	StdoutPump(std::string appName, int pipeReadFd, int diskWriteFd, std::shared_ptr<std::mutex> diskMutex);
	// The read fd is owned from construction until the pump stops; the
	// destructor covers a pump that never activated.
	~StdoutPump();

	StdoutPump(const StdoutPump &) = delete;
	StdoutPump &operator=(const StdoutPump &) = delete;

	// Registers the pipe with the poller. No-op when stopped or at EOF;
	// registration itself is idempotent, and a stop() racing it is undone.
	void activate();

	// Idempotent. Detaches from the poller (waiting for any in-flight poll
	// callback), synchronously drains any pipe remainder, and final-flushes
	// the batch.
	void stop();

	// Snapshot of the bytes handed to tee so far; the strategy reads it after
	// stop().
	long acceptedBytes() const { return m_acceptedBytes.load(std::memory_order_acquire); }

private:
	friend class PumpPoller;
	void handleReadable();
	// Coalesce flush on the poll timeout pass; skips batches younger than the
	// window so sibling pipe traffic cannot delay events unboundedly.
	void flushIdle();
	void teeToDisk(const char *data, size_t length);
	// Tees one read into the disk file and batches it for the next event flush.
	void accumulate(size_t length);
	// flushAll also emits a trailing incomplete character instead of carrying it
	// into a next batch that never comes (teardown path).
	void flushBatch(bool flushAll);
	void dispatchPayload(long start, std::string &&payload);

	const std::string m_appName;
	int m_pipeReadFd; // owned from construction, closed on pump destruction
	// Identity of the pipe read fd at construction (dev/ino/mode): stop()
	// re-checks it before draining, so an fd closed or recycled behind the
	// pump's back is reported instead of silently reading a foreign object.
	dev_t m_pipeStatDev{0};
	ino_t m_pipeStatIno{0};
	mode_t m_pipeStatMode{0};
	bool m_statValid{false};
	const int m_diskWrite; // AppProcess owns this handle
	// shared_ptr so the mutex outlives whichever (pump or AppProcess) destructs first.
	const std::shared_ptr<std::mutex> m_diskMutex;
	// m_eof, m_stopped, m_pollActive are atomic; every other member is touched
	// only by the poller thread or by stop() after it detached the pump.
	std::atomic<bool> m_eof{false};
	std::atomic<bool> m_stopped{false};
	// Set while the poller thread is inside this pump; stop() waits for it to
	// clear before touching the pipe.
	std::atomic<bool> m_pollActive{false};
	// Coalesce window — collects reads into a single STDOUT_OUTPUT event,
	// flushed on byte threshold, window age, or teardown.
	std::string m_batch;
	long m_batchStart{0};
	std::chrono::steady_clock::time_point m_batchSince{};
	std::atomic<long> m_acceptedBytes{0};
	std::vector<char> m_readBuf; // 64 KB, resized in ctor
};

// Stops the shared poller thread. Called once after the process io thread has
// joined, so late pump teardowns drain without a poller.
void StopStdoutPumpPoller();

#endif // !_WIN32
