// src/common/os/process.h
#pragma once

#include <list>
#include <memory>
#include <string>
#include <unordered_set>

#include <ace/OS.h>
#include <ace/OS_NS_unistd.h>

#include "models.h"
#include "procstat.hpp"

namespace os
{
	/// Get the status of a process.
	std::shared_ptr<ProcessStatus> status(pid_t pid);

	/// Get the command line of a process.
	std::string cmdline(pid_t pid = 0);

	/// Get the set of process IDs for the descendants of a given process.
	std::unordered_set<pid_t> child_pids(pid_t rootPid);

	/// Get the set of process IDs for the given process and its descendants.
	std::unordered_set<pid_t> pids(pid_t rootPid = ACE_OS::getpid());

	/// Cross-platform page size.
	size_t pagesize();

	/// Get process information for a given PID.
	std::shared_ptr<Process> process(pid_t pid);

	/// Get process information for a given PID from a pre-fetched list.
	std::shared_ptr<Process> process(pid_t pid, const std::list<Process> &processes);

	/// Get all processes.
	std::list<Process> processes();

} // namespace os
