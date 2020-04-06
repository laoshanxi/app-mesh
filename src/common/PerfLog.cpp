#include "PerfLog.h"
#include "../common/Utility.h"

PerfLog::PerfLog(const std::string& logger)
	:m_start(std::chrono::system_clock::now()), m_logger(logger)
{
}

PerfLog::~PerfLog()
{
	auto duration = std::chrono::system_clock::now() - m_start;
	auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
	if (seconds >= 1)
	{
		LOG_DBG << m_logger << " cost <" << seconds << "> seconds.";
	}
	//else
	//{
	//	LOG_DBG << m_logger << " cost <" << seconds << "> seconds.";
	//}
}
