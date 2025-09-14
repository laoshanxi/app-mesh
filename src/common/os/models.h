#pragma once

#include <string>
#include <sys/types.h> // For pid_t

namespace os
{
    struct Process
    {
        Process(pid_t _pid,
                pid_t _parent,
                pid_t _group,
                const pid_t &_session,
                const uint64_t &_rss_bytes,
                const unsigned long &_utime,
                const unsigned long &_stime,
                const unsigned long &_cutime,
                const unsigned long &_cstime,
                const std::string &_command,
                bool _zombie)
            : pid(_pid),
              parent(_parent),
              group(_group),
              session(_session),
              rss_bytes(_rss_bytes),
              utime(_utime),
              stime(_stime),
              cutime(_cutime),
              cstime(_cstime),
              command(_command),
              zombie(_zombie) {}

        const pid_t pid;
        const pid_t parent;
        const pid_t group;
        const pid_t session;
        // Resident Set Size
        const uint64_t rss_bytes;
        const unsigned long utime;
        const unsigned long stime;
        const unsigned long cutime;
        const unsigned long cstime;
        const std::string command;
        const bool zombie;

        bool operator<(const Process &p) const { return pid < p.pid; }
        bool operator<=(const Process &p) const { return pid <= p.pid; }
        bool operator>(const Process &p) const { return pid > p.pid; }
        bool operator>=(const Process &p) const { return pid >= p.pid; }
        bool operator==(const Process &p) const { return pid == p.pid; }
        bool operator!=(const Process &p) const { return pid != p.pid; }
    };
};
