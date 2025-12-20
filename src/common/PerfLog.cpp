// src/common/PerfLog.cpp
#include "PerfLog.h"
#include "../common/Utility.h"

PerfLog::PerfLog(const std::string &logger)
	: m_start(std::chrono::system_clock::now()), m_logger(logger)
{
}

PerfLog::~PerfLog()
{
	auto duration = std::chrono::system_clock::now() - m_start;
	auto msec = std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();

	if (msec >= 500)
	{
		LOG_DBG << m_logger << " completed in <" << msec << "> ms";
	}
}
