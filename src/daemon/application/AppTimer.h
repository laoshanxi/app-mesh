#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <tuple>

#include <croncpp.h>

class DailyLimitation;
//////////////////////////////////////////////////////////////////////////
/// Calculate Application next start time
//////////////////////////////////////////////////////////////////////////
class AppTimer
{
public:
    AppTimer(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime,
             std::shared_ptr<DailyLimitation> dailyLimit);
    virtual ~AppTimer(){};

    virtual std::chrono::system_clock::time_point nextTime(const std::chrono::system_clock::time_point &now = std::chrono::system_clock::now());
    bool isInDailyTimeRange(const std::chrono::system_clock::time_point &target);
    std::chrono::system_clock::time_point adjustDailyTimeRange(std::chrono::system_clock::time_point target);

protected:
    std::chrono::system_clock::time_point checkStartTime(const std::chrono::system_clock::time_point &target);

public:
    static std::chrono::system_clock::time_point EPOCH_ZERO_TIME;

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
    AppTimerPeriod(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime,
                   std::shared_ptr<DailyLimitation> dailyLimit, int intervalSeconds);

    std::chrono::system_clock::time_point nextTime(const std::chrono::system_clock::time_point &now = std::chrono::system_clock::now()) override;

protected:
    const int m_intervalSeconds;
};

//////////////////////////////////////////////////////////////////////////
/// Calculate Application next start time for cron schedule
//////////////////////////////////////////////////////////////////////////
class AppTimerCron : public AppTimerPeriod
{
public:
    AppTimerCron(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime,
                 std::shared_ptr<DailyLimitation> dailyLimit, const std::string &cronExpr, int intervalSeconds);

    std::chrono::system_clock::time_point nextTime(const std::chrono::system_clock::time_point &now = std::chrono::system_clock::now()) override;

protected:
    const std::string m_cronExpr;
    cron::cronexpr m_cron;
};
