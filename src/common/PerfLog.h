#pragma once

#include <chrono>
#include <string>

/// <summary>
/// Print performance log
/// </summary>
class PerfLog
{
public:
	explicit PerfLog(const std::string &logger);
	virtual ~PerfLog();

private:
	const std::chrono::system_clock::time_point m_start;
	const std::string m_logger;
};