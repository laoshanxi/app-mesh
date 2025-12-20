// src/common/os/killtree.hpp
#pragma once

#include "jobobject.hpp"

namespace os
{

    // Terminate the "process tree" rooted at the specified pid.
    // Since there is no process tree concept on Windows,
    // internally this function looks up the job object for the given pid
    // and terminates the job. This is possible because `name_job`
    // provides an idempotent one-to-one mapping from pid to name.
    inline bool killtree(
        pid_t pid,
        int signal,
        bool groups = false,
        bool sessions = false)
    {
        const std::string name = os::name_job(pid);

        SharedHandle handle = os::open_job(JOB_OBJECT_TERMINATE, false, name);
        if (handle.get_handle() == nullptr)
        {
            LOG_WAR << "os::killtree: Failed to open job object for pid: " << pid;
            return false;
        }

        if (!os::kill_job(handle))
        {
            LOG_WAR << "os::killtree: Failed to terminate job object for pid: " << pid;
            return false;
        }

        return true;
    }

} // namespace os {
