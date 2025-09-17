#pragma once

#include <atomic>  // std::atomic
#include <chrono>  // std::chrono::system_clock
#include <ctime>   // time_t, time()
#include <fstream> // std::ifstream
#include <mutex>   // std::once_flag, std::call_once
#include <string>  // std::string

#if defined(_WIN32)
#include <windows.h> // Windows types and API
#elif defined(__linux__) || defined(__APPLE__)
#include <sys/types.h>
#include <unistd.h> // pid_t, sysconf
#endif

namespace os
{

    // Snapshot of a process (cross-platform process status).
    struct ProcessStatus
    {
        ProcessStatus(
            pid_t _pid,
            const std::string &_comm,
            char _state,
            pid_t _ppid,
            pid_t _pgrp,
            pid_t _session,
            unsigned long _utime,
            unsigned long _stime,
            long _cutime,
            long _cstime,
            unsigned long long _starttime,
            unsigned long _vsize,
            long _rss)
            : pid(_pid),
              comm(_comm),
              state(_state),
              ppid(_ppid),
              pgrp(_pgrp),
              session(_session),
              utime(_utime),
              stime(_stime),
              cutime(_cutime),
              cstime(_cstime),
              starttime(_starttime),
              vsize(_vsize),
              rss(_rss)
        {
        }

        // Get process start time (platform-specific)
        std::chrono::system_clock::time_point get_starttime() const
        {
#if defined(_WIN32)
            // Windows: starttime already represents time_t
            return std::chrono::system_clock::from_time_t(static_cast<time_t>(starttime));

#elif defined(__linux__)
            static const long ticks_per_second = []
            {
                long tps = sysconf(_SC_CLK_TCK);
                return (tps > 0) ? tps : 100; // Fallback if sysconf fails
            }();

            // Read system uptime fresh each call for accuracy
            double uptime_seconds = 0.0;
            std::ifstream uptime_file("/proc/uptime");
            if (uptime_file)
            {
                uptime_file >> uptime_seconds;
            }

            // System boot time in seconds since epoch
            const time_t system_boot_time = time(nullptr) - static_cast<time_t>(uptime_seconds);

            // Process start time = boot_time + (jiffies / ticks_per_second)
            const double start_time_seconds = static_cast<double>(system_boot_time) +
                                              (static_cast<double>(starttime) / ticks_per_second);

            return std::chrono::system_clock::from_time_t(static_cast<time_t>(start_time_seconds));

#elif defined(__APPLE__)
            // macOS: interpret starttime as epoch time (approximation)
            return std::chrono::system_clock::from_time_t(static_cast<time_t>(starttime));
#endif
        }

        // Process information fields
        const pid_t pid;
        const std::string comm;
        const char state;
        const pid_t ppid;
        const pid_t pgrp;
        const pid_t session;

        const unsigned long utime;
        const unsigned long stime;
        const long cutime;
        const long cstime;
        const unsigned long long starttime;
        const unsigned long vsize;
        const long rss;
    };

} // namespace os
