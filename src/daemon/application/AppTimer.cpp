// src/daemon/application/AppTimer.cpp
#include <ace/OS.h>

#include "../../common/DateTime.h"
#include "../../common/Utility.h"
#include "../DailyLimitation.h"
#include "AppTimer.h"

std::chrono::system_clock::time_point AppTimer::TIME_UNSET = std::chrono::system_clock::time_point::min();

//////////////////////////////////////////////////////////////////////////
/// Calculate Application next start time
//////////////////////////////////////////////////////////////////////////
AppTimer::AppTimer(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime,
                   std::shared_ptr<DailyLimitation> dailyLimit)
    : m_startTime(startTime == TIME_UNSET ? (std::chrono::system_clock::now() - std::chrono::hours(24)) : startTime),
      m_endTime(endTime == TIME_UNSET ? std::chrono::system_clock::time_point::max() : endTime),
      m_dailyLimit(std::move(dailyLimit))
{
}

std::chrono::system_clock::time_point AppTimer::nextTime(const std::chrono::system_clock::time_point &startFrom)
{
    auto next = adjustDailyTimeRange(applyStartBoundary(startFrom));
    // check end
    if (next >= m_endTime)
    {
        return TIME_UNSET;
    }
    return next;
}

std::chrono::system_clock::time_point AppTimer::adjustDailyTimeRange(std::chrono::system_clock::time_point target)
{
    const static char fname[] = "AppTimer::adjustDailyTimeRange() ";
    if (m_dailyLimit != nullptr)
    {
        // Convert now to day time [%H:%M:%S], less than 24h
        auto now = DateTime::pickDayTimeUtcDuration(target);
        if (m_dailyLimit->m_startTimeValue < m_dailyLimit->m_endTimeValue)
        {
            // Start less than End means valid range should between start and end.
            if (now < m_dailyLimit->m_startTimeValue)
            {
                auto offset = (m_dailyLimit->m_startTimeValue - now).total_seconds();
                target += std::chrono::seconds(offset);
                LOG_DBG << fname << "day time <" << now << "> with startTime <" << m_dailyLimit->m_startTimeValue << ">, endTime <" << m_dailyLimit->m_endTimeValue << ">, adjusted by <" << offset << "> seconds";
            }
            else if (now >= m_dailyLimit->m_endTimeValue)
            {
                auto offset = (boost::posix_time::hours(24) - now + m_dailyLimit->m_startTimeValue).total_seconds();
                target += std::chrono::seconds(offset);
                LOG_DBG << fname << "day time <" << now << "> with startTime <" << m_dailyLimit->m_startTimeValue << ">, endTime <" << m_dailyLimit->m_endTimeValue << ">, adjusted by <" << offset << "> seconds";
            }
        }
        else if (m_dailyLimit->m_startTimeValue > m_dailyLimit->m_endTimeValue)
        {
            // Start greater than End means from end to start is invalid range (the valid range is across 0:00).
            // Invalid range: [endTime, startTime), Valid range: [startTime, 24:00) + [00:00, endTime)
            if (now >= m_dailyLimit->m_endTimeValue && now < m_dailyLimit->m_startTimeValue)
            {
                // In the invalid range, advance to startTime
                auto offset = (m_dailyLimit->m_startTimeValue - now).total_seconds();
                target += std::chrono::seconds(offset);
                LOG_DBG << fname << "day time <" << now << "> with startTime <" << m_dailyLimit->m_startTimeValue << ">, endTime <" << m_dailyLimit->m_endTimeValue << ">, adjusted by <" << offset << "> seconds";
            }
        }
    }
    return target;
}

bool AppTimer::isInDailyTimeRange(const std::chrono::system_clock::time_point &target)
{
    // const static char fname[] = "Application::isInDailyTimeRange() ";
    //  1. check date range
    if (target < m_startTime || target >= m_endTime)
    {
        return false;
    }
    // 2. check daily range
    if (m_dailyLimit != nullptr)
    {
        // Convert now to day time [%H:%M:%S], less than 24h
        auto now = DateTime::pickDayTimeUtcDuration(target);
        // LOG_DBG << fname << "now: " << now << ", startTime: " << m_dailyLimit->m_startTimeValue << ", endTime: " << m_dailyLimit->m_endTimeValue;
        if (m_dailyLimit->m_startTimeValue < m_dailyLimit->m_endTimeValue)
        {
            // Start less than End means valid range should between start and end.
            return (now >= m_dailyLimit->m_startTimeValue && now < m_dailyLimit->m_endTimeValue);
        }
        else if (m_dailyLimit->m_startTimeValue > m_dailyLimit->m_endTimeValue)
        {
            // Start greater than End means from end to start is invalid range (the valid range is across 0:00).
            return !(now >= m_dailyLimit->m_endTimeValue && now < m_dailyLimit->m_startTimeValue);
        }
    }
    return true;
}

std::chrono::system_clock::time_point AppTimer::applyStartBoundary(const std::chrono::system_clock::time_point &target)
{
    return target < m_startTime ? m_startTime : target;
}

//////////////////////////////////////////////////////////////////////////
/// Calculate Application next start time for periodic run
//////////////////////////////////////////////////////////////////////////
AppTimerPeriod::AppTimerPeriod(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime,
                               std::shared_ptr<DailyLimitation> dailyLimit, int intervalSeconds)
    : AppTimer(startTime, endTime, dailyLimit), m_intervalSeconds(intervalSeconds)
{
}

std::chrono::system_clock::time_point AppTimerPeriod::nextTime(const std::chrono::system_clock::time_point &startFrom)
{
    auto next = applyStartBoundary(startFrom);
    if (next > m_startTime && m_intervalSeconds > 0)
    {
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(next - m_startTime).count();
        next = m_startTime + std::chrono::seconds((elapsed / m_intervalSeconds) * m_intervalSeconds);
        if (next <= startFrom)
        {
            next += std::chrono::seconds(m_intervalSeconds);
        }
    }

    // Daily limitation adjusts a computed occurrence; it does not redefine the interval grid.
    next = adjustDailyTimeRange(next);
    return next < m_endTime ? next : TIME_UNSET;
}

//////////////////////////////////////////////////////////////////////////
/// Calculate Application next start time for cron schedule
//////////////////////////////////////////////////////////////////////////
AppTimerCron::AppTimerCron(const std::chrono::system_clock::time_point &startTime, const std::chrono::system_clock::time_point &endTime,
                           std::shared_ptr<DailyLimitation> dailyLimit, const std::string &cronExpr, int intervalSeconds)
    : AppTimerPeriod(startTime, endTime, dailyLimit, intervalSeconds), m_cronExpr(cronExpr)
{
    m_cron = cron::make_cron(m_cronExpr);
}

std::chrono::system_clock::time_point AppTimerCron::nextTime(const std::chrono::system_clock::time_point &startFrom)
{
    auto next = applyStartBoundary(startFrom);
    // check end
    if (next < m_endTime)
    {
        auto nextStartTimeT = std::chrono::system_clock::to_time_t(next);
        auto nextTimeT = cron::cron_next(m_cron, nextStartTimeT);
        // croncpp supports a seconds field and already returns a strictly later
        // occurrence. A result one second away is valid and must not be skipped.
        next = adjustDailyTimeRange(std::chrono::system_clock::from_time_t(nextTimeT));
        if (next < m_endTime)
        {
            return next;
        }
    }
    return TIME_UNSET;
}
