// src/common/os/proc.h
#pragma once

#include <ace/OS.h>    // for getpid()
#include <cstddef>     // for size_t
#include <sys/types.h> // for pid_t, uid_t

namespace os
{
    // Returns the number of open file descriptors for the specified process.
    size_t getOpenFileDescriptorCount(pid_t pid = ACE_OS::getpid());

    // Returns the UID of the specified process.
    uid_t getProcessUid(pid_t pid);

} // namespace os
