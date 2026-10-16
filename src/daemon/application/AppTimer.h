// src/daemon/application/AppTimer.h
#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <tuple>

// croncpp.h ships as a plain header on the default include path (e.g.
// /usr/local/include), which Apple clang does not treat as a system
// directory, so its file-local helpers would surface as warnings.
#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunneeded-internal-declaration"
#endif
#include <croncpp.h>
#if defined(__clang__)
#pragma clang diagnostic pop
#endif

class DailyLimitation;
//////////////////////////////////////////////////////////////////////////
/// Calculate Application next start time
//////////////////////////////////////////////////////////////////////////
class AppTimer
{
public:
	AppTimer(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime,
			 std::shared_ptr<DailyLimitation> dailyLimit);
	virtual ~AppTimer() {};

	virtual std::chrono::system_clock::time_point
	nextTime(const std::chrono::system_clock::time_point &startFrom = std::chrono::system_clock::now());
	bool isInDailyTimeRange(const std::chrono::system_clock::time_point &target);
	std::chrono::system_clock::time_point adjustDailyTimeRange(std::chrono::system_clock::time_point target);

protected:
	std::chrono::system_clock::time_point applyStartBoundary(const std::chrono::system_clock::time_point &target);

public:
	static std::chrono::system_clock::time_point TIME_UNSET;

protected:
	const std::chrono::system_clock::time_point m_startTime;
	const std::chrono::system_clock::time_point m_endTime;
	std::shared_ptr<DailyLimitation> m_dailyLimit;
};

//////////////////////////////////////////////////////////////////////////
/// Calculate Application next start time for periodic run
//////////////////////////////////////////////////////////////////////////
class AppTimerPeriod : public AppTimer
{
public:
	AppTimerPeriod(const std::chrono::system_clock::time_point &startTime,
				   const std::chrono::system_clock::time_point &endTime, std::shared_ptr<DailyLimitation> dailyLimit,
				   int intervalSeconds);

	std::chrono::system_clock::time_point
	nextTime(const std::chrono::system_clock::time_point &startFrom = std::chrono::system_clock::now()) override;

protected:
	const int m_intervalSeconds;
};

//////////////////////////////////////////////////////////////////////////
/// Calculate Application next start time for cron schedule
//////////////////////////////////////////////////////////////////////////
class AppTimerCron : public AppTimerPeriod
{
public:
	AppTimerCron(const std::chrono::system_clock::time_point &startTime,
				 const std::chrono::system_clock::time_point &endTime, std::shared_ptr<DailyLimitation> dailyLimit,
				 const std::string &cronExpr, int intervalSeconds);

	std::chrono::system_clock::time_point
	nextTime(const std::chrono::system_clock::time_point &startFrom = std::chrono::system_clock::now()) override;

protected:
	const std::string m_cronExpr;
	cron::cronexpr m_cron;
};
