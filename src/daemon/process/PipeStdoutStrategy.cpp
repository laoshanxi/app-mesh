// src/daemon/process/PipeStdoutStrategy.cpp
#include "PipeStdoutStrategy.h"

#if !defined(_WIN32)

#include "ProcessService.h"
#include "StdoutPump.h"

#include "../../common/StreamLogger.h"

PipeStdoutStrategy::PipeStdoutStrategy(std::string appName, int pipeReadFd, int diskWriteFd, std::shared_ptr<std::mutex> diskMutex)
	: m_pump(std::make_shared<StdoutPump>(std::move(appName), pipeReadFd, diskWriteFd, std::move(diskMutex)))
{
}

PipeStdoutStrategy::~PipeStdoutStrategy()
{
	teardown();
}

void PipeStdoutStrategy::activate(TimerHandler &, const std::string &)
{
	// Guard the pump with a local copy: teardown may run concurrently.
	const std::shared_ptr<StdoutPump> pump = m_pump;
	if (!pump || m_tornDown.load(std::memory_order_acquire))
		return;
	PROCESS_SERVICE::instance()->post([pump]() { pump->activate(); });
}

long PipeStdoutStrategy::dispatchedBytes() const
{
	return m_snapshotBytes.load(std::memory_order_acquire);
}

void PipeStdoutStrategy::teardown()
{
	const static char fname[] = "PipeStdoutStrategy::teardown() ";
	if (m_tornDown.exchange(true, std::memory_order_acq_rel))
		return;

	const std::shared_ptr<StdoutPump> pump = std::move(m_pump);
	if (!pump)
		return;

	// stop() runs on the io thread: cancel the chain, drain, final-flush. The
	// sync wait makes the snapshot race-free; shutdown abandons the drain.
	if (PROCESS_SERVICE::instance()->dispatchSync([pump]() { pump->stop(); }))
		m_snapshotBytes.store(pump->acceptedBytes(), std::memory_order_release);
	LOG_DBG << fname << "bytes=" << m_snapshotBytes.load();
}

#endif // !_WIN32
