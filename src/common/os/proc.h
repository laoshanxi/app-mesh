// src/common/os/proc.h
#pragma once

#include <optional>

#include <cstddef> // for size_t
#if defined(_WIN32)
#include <process.h> // for _getpid()
#else
#include <unistd.h> // for getpid()
#endif

#include "models.h"

namespace os
{
    /// Process id of the current process.
    inline pid_t getpid()
    {
#if defined(_WIN32)
        return _getpid();
#else
        return ::getpid();
#endif
    }

    // Returns the number of open file descriptors for the specified process.
    size_t getOpenFileDescriptorCount(pid_t pid = getpid());

    // Returns the UID of the specified process; no value on failure.
    std::optional<uid_t> getProcessUid(pid_t pid);

} // namespace os
