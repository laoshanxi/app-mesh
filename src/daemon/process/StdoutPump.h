// src/daemon/process/StdoutPump.h
#pragma once

#include <atomic>
#include <chrono>
#include <mutex>
#include <string>

#include <ace/Event_Handler.h>
#include <ace/OS_NS_unistd.h>

// Reads child stdout from a pipe, tees to disk, and dispatches STDOUT_OUTPUT events.
// Owned by AppProcess via shared_ptr; lifecycle managed by AppProcess::teardownStdoutPump.
class StdoutPump : public ACE_Event_Handler
{
public:
	StdoutPump(std::string appName, ACE_HANDLE pipeRead, ACE_HANDLE diskWrite,
			   std::recursive_mutex &diskMutex);
	~StdoutPump() override;

	StdoutPump(const StdoutPump &) = delete;
	StdoutPump &operator=(const StdoutPump &) = delete;

	ACE_HANDLE get_handle() const override { return m_pipeRead; }
	int handle_input(ACE_HANDLE) override;
	int handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask) override;
	int handle_timeout(const ACE_Time_Value &tv, const void *act) override;

	// Cancel pending coalesce timer + flush remaining batch. Caller must invoke
	// from teardown path before reset; safe to call from any thread.
	void cancelCoalesceTimerAndFlush();

	// Bytes accepted by the pump (written to disk + buffered for dispatch). After
	// the final cancelCoalesceTimerAndFlush() in teardown the buffer is empty, so
	// snapshotting this value at that point yields the true "dispatched" count
	// that flushStdout uses as the on-disk tail offset.
	long acceptedBytes() const { return m_acceptedBytes.load(std::memory_order_relaxed); }

	// Short-circuits future handle_input. Idempotent.
	void stop() { m_stopped.store(true, std::memory_order_release); }

	// Spin until any in-flight handle_input on a reactor thread has returned, or
	// until `timeout` elapses. Returns true if drained, false on timeout.
	// Required before dropping the shared_ptr — ACE_TP_Reactor's remove_handler
	// does not wait for an in-flight dispatch on a different thread.
	bool waitInflight(std::chrono::milliseconds timeout = std::chrono::seconds(5));

private:
	// Extract current batch under m_coalesceMu (cancels timer, swaps buffer).
	// Caller must release m_coalesceMu BEFORE invoking dispatchPayload to avoid
	// holding the coalesce lock across a slow ws fanout.
	void extractBatchLocked(std::string &out, long &start);
	void scheduleCoalesceTimerLocked();
	void dispatchPayload(long start, std::string &&payload);

	const std::string m_appName;
	ACE_HANDLE m_pipeRead;
	ACE_HANDLE m_diskWrite;
	std::recursive_mutex &m_diskMutex;
	std::atomic<long> m_acceptedBytes;
	std::atomic<bool> m_stopped;
	std::atomic<int> m_inflight;

	// Coalesce window: collect reads into a single STDOUT_OUTPUT event, flushed when
	// either (a) the batch reaches a byte threshold, (b) a timer fires, or (c) EOF /
	// teardown drains. Cuts ws fanout from per-line down to a few events per second.
	std::mutex m_coalesceMu;
	std::string m_batch;
	long m_batchStart{0};
	long m_timerId{-1};
};
