// src/daemon/process/ProcessService.h
#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

/// Single-threaded asio service owning the process engine I/O: BPv2 exit
/// waits, stdout pipe read chains, and exit cleanup. Everything posted here
/// runs on one thread, so the pump and wait state need no locks. A second
/// single-threaded context runs application exit callbacks, which may block
/// on docker backends and must not stall the engine.
class ProcessService
{
public:
	ProcessService();
	~ProcessService();

	// Non-copyable, non-movable
	ProcessService(const ProcessService &) = delete;
	ProcessService &operator=(const ProcessService &) = delete;
	ProcessService(ProcessService &&) = delete;
	ProcessService &operator=(ProcessService &&) = delete;

	boost::asio::io_context &io();

	/// Queue a task on the io thread; returns immediately.
	void post(std::function<void()> task);

	/// Queue an application exit-callback task; runs off the engine thread so
	/// docker-backed callbacks cannot stall it.
	void postCallback(std::function<void()> task);

	/// Run a task on the io thread and wait for it. Direct call when already
	/// there. A task exception propagates to the calling thread. Returns false
	/// when the service stopped before the task could run.
	bool dispatchSync(const std::function<void()> &task);

	/// Stop the service and join both threads. Best effort, idempotent;
	/// pending handlers are dropped, exactly like the timer service.
	void shutdown();

private:
	/// True when called from the io thread.
	bool onIoThread() const;
	/// True when called from the exit-callback thread.
	bool onCallbackThread() const;

	/// One dispatchSync wait; released by shutdown after the io thread joins.
	struct SyncWaiter;

	boost::asio::io_context m_ioContext;
	boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_workGuard;
	std::thread m_ioThread;
	std::thread::id m_ioThreadId;

	boost::asio::io_context m_callbackContext;
	boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_callbackGuard;
	std::thread m_callbackThread;
	std::thread::id m_callbackThreadId;

	std::atomic<bool> m_stopped{false};
	std::mutex m_syncMutex;								   ///< Guards m_syncWaiters.
	std::vector<std::shared_ptr<SyncWaiter>> m_syncWaiters; ///< dispatchSync waits shutdown must release.
};

/// Process-wide ProcessService singleton (thread-safe function-local static).
struct PROCESS_SERVICE
{
	static ProcessService *instance()
	{
		static ProcessService service;
		return &service;
	}
};
