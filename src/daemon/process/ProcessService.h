// src/daemon/process/ProcessService.h
#pragma once

#include <atomic>
#include <functional>
#include <thread>

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>

/// Single-threaded asio service owning the process engine I/O: BPv2 exit
/// waits, stdout pipe read chains, and exit finalization. Everything posted
/// here runs on one thread, so the pump and wait state need no locks.
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

	/// Run a task on the io thread and wait for it. Direct call when already
	/// there. A task exception propagates to the calling thread.
	void dispatchSync(const std::function<void()> &task);

	/// Stop the service and join the io thread. Best effort, idempotent;
	/// pending handlers are dropped, exactly like the timer service.
	void shutdown();

private:
	/// True when called from the io thread.
	bool onIoThread() const;

	boost::asio::io_context m_ioContext;
	boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_workGuard;
	std::thread m_ioThread;
	std::thread::id m_ioThreadId;
	std::atomic<bool> m_stopped{false};
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
