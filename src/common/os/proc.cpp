// src/common/os/proc.cpp
#include "proc.h"

#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <list>
#include <memory>
#include <numeric>
#include <ostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

#include <ace/OS.h>
#include <boost/filesystem.hpp> // directory_iterator

#include "../Utility.h"
#include "models.h"

namespace os
{

	// Returns the number of open file descriptors for the specified process.
	size_t getOpenFileDescriptorCount(pid_t pid)
	{
		const static char fname[] = "os::getOpenFileDescriptorCount() ";
		size_t result = 0;

		// Check if the pid is valid.
		if (pid <= 0)
		{
			LOG_WAR << fname << "Invalid PID provided: " << pid << ". PID must be greater than zero.";
			return result;
		}

		// Linux: only count entries in /proc/pid/fd/. /proc/pid/maps lines are
		// virtual memory regions (libc, .so segments, anon mappings) — NOT file
		// descriptors. Mixing them in here would inflate the metric by hundreds
		// per process for no reason matching the function's name/contract.
		const auto procFdPath = std::string("/proc/") + std::to_string(pid) + "/fd";
		try
		{
			if (boost::filesystem::exists(procFdPath) && ACE_OS::access(procFdPath.c_str(), R_OK) == 0)
			{
				result = static_cast<size_t>(std::distance(
					boost::filesystem::directory_iterator(procFdPath),
					boost::filesystem::directory_iterator()));
				LOG_DBG << fname << "Found " << result << " file descriptors for process " << pid;
			}
			else
			{
				LOG_WAR << fname << "Path does not exist or is not readable: " << procFdPath;
			}
		}
		catch (const std::exception &e)
		{
			LOG_WAR << fname << "Error accessing " << procFdPath << ": " << e.what();
		}

		return result;
	}

	uid_t getProcessUid(pid_t pid)
	{
		const static char fname[] = "os::getProcessUid() ";

		if (pid <= 0)
		{
			LOG_WAR << fname << "Invalid PID: " << pid;
			return std::numeric_limits<uid_t>::max();
		}

		// Linux implementation using /proc
		std::string procPath = std::string("/proc/") + std::to_string(pid);
		struct stat statBuf;

		// Get the stat information for the /proc/[pid] directory
		// Using lstat to handle symbolic links
		if (lstat(procPath.c_str(), &statBuf) != 0)
		{
			// More specific error reporting
			if (errno == ENOENT)
			{
				LOG_WAR << fname << "Process " << pid << " does not exist";
			}
			else
			{
				LOG_WAR << fname << "Failed to stat " << procPath << ": " << last_error_msg();
			}
			return std::numeric_limits<uid_t>::max();
		}

		// Check if it's a symbolic link
		if (S_ISLNK(statBuf.st_mode))
		{
			LOG_WAR << fname << "Path is a symbolic link: " << procPath;
			return std::numeric_limits<uid_t>::max();
		}

		LOG_DBG << fname << "UID for process " << pid << " is " << statBuf.st_uid;
		return statBuf.st_uid;
	}

} // namespace os
