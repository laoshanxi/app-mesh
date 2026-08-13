// src/common/os/process.h
#pragma once

#include <list>
#include <memory>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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

	/// Cross-platform page size.
	size_t pagesize();

	/// Get a system-wide process snapshot. Callers build the required subtree
	/// from it, which also supports recovered processes that are not our child.
	std::list<Process> processes();
	std::list<Process> processes(const std::vector<pid_t> &rootPids);

	/// Single bulk-query snapshot of rootPid and its descendants. Passing zero
	/// returns every process visible to the current process.
	std::list<Process> processSnapshot(pid_t rootPid);
#if defined(__APPLE__)
	std::list<Process> processSnapshot(const std::vector<pid_t> &rootPids);
#endif

	/// Build a Process from a status snapshot (command falls back to comm when cmdline is empty).
	Process makeProcess(const ProcessStatus &status, const std::string &cmdline);

	/// BFS a parent->children map; returns every descendant of rootPid (rootPid excluded).
	std::unordered_set<pid_t> collectDescendants(pid_t rootPid, const std::unordered_map<pid_t, std::vector<pid_t>> &children);

} // namespace os
