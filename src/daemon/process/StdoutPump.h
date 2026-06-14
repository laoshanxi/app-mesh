// src/daemon/process/StdoutPump.h
#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>

#include <ace/Event_Handler.h>
#include <ace/OS_NS_unistd.h>

// Reactor-driven pump: reads child stdout from a pipe, tees to disk, dispatches
// STDOUT_OUTPUT events. Lifecycle managed by ACE Reference_Counting_Policy.
class StdoutPump : public ACE_Event_Handler
{
public:
	StdoutPump(std::string appName, ACE_HANDLE pipeRead, ACE_HANDLE diskWrite,
			   std::shared_ptr<std::recursive_mutex> diskMutex);
	~StdoutPump() override;

	StdoutPump(const StdoutPump &) = delete;
	StdoutPump &operator=(const StdoutPump &) = delete;

	ACE_HANDLE get_handle() const override { return m_pipeRead; }
	int handle_input(ACE_HANDLE) override;
	int handle_close(ACE_HANDLE handle, ACE_Reactor_Mask close_mask) override;
	int handle_timeout(const ACE_Time_Value &tv, const void *act) override;

	// Flush leftover coalesce-buffer to subscribers.
	void cancelCoalesceTimerAndFlush();

	// Bytes already streamed (disk + buffer); after a flush it is the disk tail.
	long acceptedBytes() const { return m_acceptedBytes.load(std::memory_order_relaxed); }

	// Idempotent — short-circuits future handle_input.
	void stop() { m_stopped.store(true, std::memory_order_release); }

	// Synchronously drain remaining pipe bytes when the reactor never woke up
	// (fast-exit child). Call after stop() + remove_handler; waits out any
	// in-flight handle_input.
	void finalSyncDrain();

private:
	// Caller must hold m_coalesceMu; releases timer + swaps buffer out.
	void extractBatchLocked(std::string &out, long &start);
	void scheduleCoalesceTimerLocked();
	// Extract + dispatch under m_dispatchMu: keeps events in position order.
	void flushBatch();
	void dispatchPayload(long start, std::string &&payload);

	const std::string m_appName;
	ACE_HANDLE m_pipeRead; // written only in the ctor; closed only by the dtor
	ACE_HANDLE m_diskWrite;
	// shared_ptr so the mutex outlives whichever (pump or AppProcess) destructs first.
	std::shared_ptr<std::recursive_mutex> m_diskMutex;
	std::atomic<long> m_acceptedBytes;
	std::atomic<bool> m_stopped;

	// Serializes pipe readers (handle_input vs finalSyncDrain).
	// Lock order: m_pipeMu -> m_dispatchMu -> m_coalesceMu.
	std::mutex m_pipeMu;
	// Held across extract+dispatch so flushes cannot reorder.
	std::mutex m_dispatchMu;

	// Coalesce window — collects reads into a single STDOUT_OUTPUT event,
	// flushed on byte threshold, timer, or teardown.
	std::mutex m_coalesceMu;
	std::string m_batch;
	long m_batchStart{0};
	bool m_timerArmed{false};
};
