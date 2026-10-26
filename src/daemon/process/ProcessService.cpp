// src/daemon/process/ProcessService.cpp
#include "ProcessService.h"

#if !defined(_WIN32)
#include "StdoutPump.h"
#endif

#include <algorithm>
#include <condition_variable>
#include <exception>
#include <memory>
#include <stdexcept>
#include <utility>

#include <boost/asio/post.hpp>

#include "../../common/StreamLogger.h"
#include "../../common/Utility.h"

struct ProcessService::SyncWaiter
{
	std::mutex mutex;
	std::condition_variable cv;
	bool done = false;        ///< The task ran.
	bool interrupted = false; ///< Shutdown released the wait.
	std::exception_ptr error;
};

ProcessService *ProcessService::instance()
{
	static ProcessService service;
	return &service;
}

ProcessService::ProcessService()
	: m_workGuard(boost::asio::make_work_guard(m_ioContext)),
	  m_callbackGuard(boost::asio::make_work_guard(m_callbackContext))
{
	const static char fname[] = "ProcessService::ProcessService() ";
	LOG_DBG << fname;
	try
	{
		m_ioThread = std::thread(
			[this]()
			{
				Utility::setThreadName("appmesh-proc");
				m_ioContext.run();
			});
		m_ioThreadId = m_ioThread.get_id();
	}
	catch (const std::exception &ex)
	{
		LOG_CRT << fname << "FATAL: failed to start a process service thread: " << ex.what();
		// A joinable thread left behind would terminate the process on destruction.
		if (m_ioThread.joinable())
			m_ioThread.join();
		throw std::runtime_error("failed to start a process service thread");
	}
}

ProcessService::~ProcessService() { shutdown(); }

boost::asio::io_context &ProcessService::io() { return m_ioContext; }

void ProcessService::post(std::function<void()> task) { boost::asio::post(m_ioContext, std::move(task)); }

void ProcessService::ensureCallbackThread()
{
	std::lock_guard lock(m_callbackMutex);
	// Re-check under the mutex: no thread may be created on the stopped
	// context after shutdown() joined — it would never be joined.
	if (m_stopped.load(std::memory_order_acquire) || m_callbackThread.get_id() != std::thread::id())
		return;
	m_callbackThread = std::thread(
		[this]()
		{
			Utility::setThreadName("appmesh-exit");
			m_callbackContext.run();
		});
	m_callbackThreadId = m_callbackThread.get_id();
}

void ProcessService::postCallback(std::function<void()> task)
{
	if (!m_stopped.load(std::memory_order_acquire))
	{
		try
		{
			ensureCallbackThread();
		}
		catch (const std::exception &ex)
		{
			// Thread creation failed: run the callback inline so waiters still
			// finalize (same fallback as AppProcess uses when posting fails).
			LOG_CRT << "ProcessService::postCallback() FATAL: cannot start the exit-callback thread: " << ex.what();
			task();
			return;
		}
	}
	boost::asio::post(m_callbackContext, std::move(task));
}

bool ProcessService::onIoThread() const { return std::this_thread::get_id() == m_ioThreadId; }

bool ProcessService::onCallbackThread() const
{
	std::lock_guard lock(m_callbackMutex);
	return std::this_thread::get_id() == m_callbackThreadId;
}

bool ProcessService::dispatchSync(const std::function<void()> &task)
{
	if (onIoThread())
	{
		task();
		return true;
	}
	auto waiter = std::make_shared<SyncWaiter>();
	{
		std::lock_guard lock(m_syncMutex);
		if (m_stopped.load(std::memory_order_acquire))
			return false;
		m_syncWaiters.push_back(waiter);
	}
	post(
		[waiter, task]()
		{
			std::exception_ptr error;
			try
			{
				task();
			}
			catch (...)
			{
				error = std::current_exception();
			}
			std::lock_guard lock(waiter->mutex);
			waiter->error = error;
			waiter->done = true;
			waiter->cv.notify_all();
		});
	bool ran = false;
	std::exception_ptr error;
	{
		std::unique_lock lock(waiter->mutex);
		waiter->cv.wait(lock, [waiter]() { return waiter->done || waiter->interrupted; });
		error = waiter->error;
		ran = waiter->done;
	}
	{
		std::lock_guard lock(m_syncMutex);
		m_syncWaiters.erase(std::remove(m_syncWaiters.begin(), m_syncWaiters.end(), waiter), m_syncWaiters.end());
	}
	// Rethrow only after deregistration so a throwing task leaves no stale entry.
	if (error)
		std::rethrow_exception(error);
	return ran;
}

void ProcessService::shutdown()
{
	const static char fname[] = "ProcessService::shutdown() ";
	if (m_stopped.exchange(true))
		return;
	if (onIoThread() || onCallbackThread())
	{
		// Joining our own thread would deadlock; the daemon is exiting anyway.
		LOG_CRT << fname << "called on a service thread, skipping join";
		return;
	}
	m_workGuard.reset();
	m_ioContext.stop();
	if (m_ioThread.joinable())
		m_ioThread.join();
	// The io thread is dead, so queued sync tasks can never run; release their
	// waiters before joining the callback thread, which must not block on one.
	std::vector<std::shared_ptr<SyncWaiter>> waiters;
	{
		std::lock_guard lock(m_syncMutex);
		waiters = std::move(m_syncWaiters);
	}
	for (const auto &waiter : waiters)
	{
		std::lock_guard lock(waiter->mutex);
		waiter->interrupted = true;
		waiter->cv.notify_all();
	}
#if !defined(_WIN32)
	// The io thread is down, so no pump teardown can race the poller anymore;
	// late pump destructors drain their pipes without it.
	StopStdoutPumpPoller();
#endif
	// Stop the callback thread after the engine: no callback can be posted anymore.
	{
		std::lock_guard lock(m_callbackMutex);
		m_callbackGuard.reset();
		m_callbackContext.stop();
		if (m_callbackThread.joinable())
			m_callbackThread.join();
	}
	LOG_INF << fname << "process service threads stopped";
}
