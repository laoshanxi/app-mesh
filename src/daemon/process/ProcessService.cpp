// src/daemon/process/ProcessService.cpp
#include "ProcessService.h"

#include <future>
#include <memory>
#include <stdexcept>
#include <utility>

#include <boost/asio/post.hpp>

#include "../../common/StreamLogger.h"

ProcessService::ProcessService()
	: m_workGuard(boost::asio::make_work_guard(m_ioContext))
{
	const static char fname[] = "ProcessService::ProcessService() ";
	LOG_DBG << fname;
	try
	{
		m_ioThread = std::thread([this]() { m_ioContext.run(); });
		m_ioThreadId = m_ioThread.get_id();
	}
	catch (const std::exception &ex)
	{
		LOG_CRT << fname << "FATAL: failed to start the process io thread: " << ex.what();
		throw std::runtime_error("failed to start the process io thread");
	}
}

ProcessService::~ProcessService()
{
	shutdown();
}

boost::asio::io_context &ProcessService::io()
{
	return m_ioContext;
}

void ProcessService::post(std::function<void()> task)
{
	boost::asio::post(m_ioContext, std::move(task));
}

bool ProcessService::onIoThread() const
{
	return std::this_thread::get_id() == m_ioThreadId;
}

void ProcessService::dispatchSync(const std::function<void()> &task)
{
	if (onIoThread())
	{
		task();
		return;
	}
	auto done = std::make_shared<std::promise<void>>();
	auto future = done->get_future();
	post([task, done]()
		 {
		try
		{
			task();
		}
		catch (...)
		{
			try
			{
				done->set_exception(std::current_exception());
			}
			catch (...)
			{
			}
			return;
		}
		done->set_value(); });
	future.get();
}

void ProcessService::shutdown()
{
	const static char fname[] = "ProcessService::shutdown() ";
	if (m_stopped.exchange(true))
		return;
	if (onIoThread())
	{
		// Joining our own thread would deadlock; the daemon is exiting anyway.
		LOG_CRT << fname << "called on the io thread, skipping join";
		return;
	}
	m_workGuard.reset();
	m_ioContext.stop();
	if (m_ioThread.joinable())
		m_ioThread.join();
	LOG_INF << fname << "process io thread stopped";
}
