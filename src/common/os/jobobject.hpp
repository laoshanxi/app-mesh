#pragma once

#include <ace/OS.h>
#include <memory>
#include <string>
#include <windows.h>

#include "../Utility.h"

const mode_t SIGKILL = 0x00000009; // Signal Kill.

// An RAII `HANDLE`.
class SharedHandle : public std::shared_ptr<void>
{

    static_assert(std::is_same<HANDLE, void *>::value, "Expected `HANDLE` to be of type `void*`.");

public:
    // We delete the default constructor so that the callsite is forced to make
    // an explicit decision about what the empty `HANDLE` value should be, as it
    // is not the same for all `HANDLE` types.  For example, `OpenProcess`
    // returns a `nullptr` for an invalid handle, but `CreateFile` returns an
    // `INVALID_HANDLE_VALUE` instead. This inconsistency is inherent in the
    // Windows API.
    SharedHandle() = delete;

    template <typename Deleter>
    SharedHandle(HANDLE handle, Deleter deleter)
        : std::shared_ptr<void>(handle, deleter) {}

    HANDLE get_handle() const { return this->get(); }
};

namespace os
{

    // `name_job` maps a `pid` to a `wstring` name for a job object.
    // Only named job objects are accessible via `OpenJobObject`.
    inline std::string name_job(pid_t pid)
    {
        return Utility::stringFormat("APPMESH_JOB_%d", pid);
    }

    // `open_job` returns a safe shared handle to the named job object `name`.
    // `desired_access` is a job object access rights flag.
    // `inherit_handles` if true, processes created by this
    // process will inherit the handle. Otherwise, the processes do not inherit this handle.
    inline SharedHandle open_job(const DWORD desired_access, const BOOL inherit_handles, const std::string &name)
    {
        const static char fname[] = "os::open_job() ";

        SharedHandle job_handle(
            ::OpenJobObjectA(desired_access, inherit_handles, name.data()),
            ::CloseHandle);

        if (job_handle.get_handle() == nullptr)
        {
            LOG_ERR << fname << "Call to `OpenJobObject` failed for job: " << name << ", error: " << last_error_msg();
        }

        return job_handle;
    }

    inline SharedHandle open_job(const DWORD desired_access, const BOOL inherit_handles, const pid_t pid)
    {
        return open_job(desired_access, inherit_handles, os::name_job(pid));
    }

    // `create_job` function creates a named job object using `name`.
    inline SharedHandle create_job(const std::string &name)
    {
        const static char fname[] = "os::create_job() ";

        SharedHandle job_handle(
            ::CreateJobObjectA(
                nullptr,      // Use a default security descriptor, and the created handle cannot be inherited.
                name.data()), // The name of the job.
            ::CloseHandle);

        if (job_handle.get_handle() == nullptr)
        {
            throw std::runtime_error(Utility::stringFormat("os::create_job: Call to `CreateJobObject` failed for job: %s, error code: %s", name.c_str(), last_error_msg()));
        }

        return job_handle;
    }

    // `assign_job` assigns a process with `pid` to the job object `job_handle`.
    // Every process started by the `pid` process using `CreateProcess`
    // will also be owned by the job object.
    inline bool assign_job(SharedHandle job_handle, pid_t pid)
    {
        const static char fname[] = "os::assign_job() ";

        if (pid <= 0 || job_handle.get_handle() == nullptr)
        {
            LOG_WAR << fname << "Invalid pid or job handle";
            return false;
        }

        // Get process handle for `pid`.
        SharedHandle process_handle(
            ::OpenProcess(
                // Required access rights to assign to a Job Object.
                PROCESS_SET_QUOTA | PROCESS_TERMINATE,
                false, // Don't inherit handle.
                pid),
            ::CloseHandle);

        if (process_handle.get_handle() == nullptr)
        {
            throw std::runtime_error(Utility::stringFormat("os::assign_job: Call to `OpenProcess` failed for pid: %d, error code: %s", pid, last_error_msg()));
        }

        const BOOL result = ::AssignProcessToJobObject(job_handle.get_handle(), process_handle.get_handle());

        if (result == FALSE)
        {
            LOG_WAR << fname << "Call to `AssignProcessToJobObject` failed for pid: " << pid << ", error: " << last_error_msg();
        }

        return result == TRUE;
    }

    // The `kill_job` function wraps the Windows sytem call `TerminateJobObject`
    // for the job object `job_handle`. This will call `TerminateProcess`
    // for every associated child process.
    inline bool kill_job(SharedHandle job_handle)
    {
        const static char fname[] = "os::kill_job() ";

        if (job_handle.get_handle() == nullptr)
        {
            LOG_WAR << fname << "Invalid job handle";
            return false;
        }

        const BOOL result = ::TerminateJobObject(
            job_handle.get_handle(),
            // The exit code to be used by all processes in the job object.
            1);

        if (result == FALSE)
        {
            LOG_WAR << fname << "Call to `TerminateJobObject` failed, error: " << last_error_msg();
        }
        return result == TRUE;
    }
}
