// src/daemon/process/PipeStdoutStrategy.cpp
#include "PipeStdoutStrategy.h"
#include "StdoutPump.h"

#include <ace/Reactor.h>

#include "../../common/StreamLogger.h"
#include "../../common/Utility.h"

PipeStdoutStrategy::PipeStdoutStrategy(
	std::string appName, ACE_HANDLE pipeRead,
	ACE_HANDLE diskWrite, std::shared_ptr<std::recursive_mutex> diskMutex)
{
	const static char fname[] = "PipeStdoutStrategy::PipeStdoutStrategy() ";

	auto *pump = new StdoutPump(std::move(appName), pipeRead, diskWrite, std::move(diskMutex));

	if (ACE_Reactor::instance()->register_handler(pump, ACE_Event_Handler::READ_MASK) == -1)
	{
		LOG_WAR << fname << "register_handler failed: " << last_error_msg();
		pump->remove_reference();
		m_tornDown.store(true, std::memory_order_release);
	}
	else
	{
		m_pump = pump;
	}
}

PipeStdoutStrategy::~PipeStdoutStrategy()
{
	const static char fname[] = "PipeStdoutStrategy::~PipeStdoutStrategy() ";
	LOG_DBG << fname << "Entered";
	teardown();
}

long PipeStdoutStrategy::dispatchedBytes() const
{
	if (m_pump && !m_tornDown.load(std::memory_order_acquire))
		return m_pump->acceptedBytes();
	return m_snapshotBytes.load(std::memory_order_acquire);
}

void PipeStdoutStrategy::teardown()
{
	if (m_tornDown.exchange(true, std::memory_order_acq_rel) || !m_pump)
		return;

	auto *pump = m_pump;
	m_pump = nullptr;

	const static char fname[] = "PipeStdoutStrategy::teardown() ";

	pump->stop();

	// Deregister BEFORE draining: no new upcall can start, finalSyncDrain() waits
	// out any in-flight one. DONT_CALL keeps the fd open for the drain.
	ACE_Reactor::instance()->remove_handler(pump, ACE_Event_Handler::READ_MASK | ACE_Event_Handler::DONT_CALL);

	pump->finalSyncDrain();
	pump->cancelCoalesceTimerAndFlush();
	m_snapshotBytes.store(pump->acceptedBytes(), std::memory_order_release);
	ACE_Reactor::instance()->cancel_timer(pump);

	pump->remove_reference();
	LOG_DBG << fname << "bytes=" << m_snapshotBytes.load();
}
