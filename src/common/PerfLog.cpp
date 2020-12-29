#include "PerfLog.h"
#include "../common/Utility.h"

PerfLog::PerfLog(const std::string &logger)
	: m_start(std::chrono::system_clock::now()), m_logger(logger)
{
}

PerfLog::~PerfLog()
{
	auto duration = std::chrono::system_clock::now() - m_start;
	auto msec = std::chrono::duration_cast<std::chrono::microseconds>(duration).count();
	if (msec >= 100)
	{
		LOG_DBG << m_logger << " cost <" << msec << "> microseconds.";
	}
}
