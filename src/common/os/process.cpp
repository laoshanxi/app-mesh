// src/common/os/process.cpp
// Platform-agnostic process utilities.

#include "process.h"

#include <list>
#include <queue>

namespace os
{

	Process makeProcess(const ProcessStatus &status, const std::string &cmdline)
	{
		static const size_t pageSize = os::pagesize();
		return Process(
			status.pid, status.ppid, status.pgrp, status.session,
			static_cast<uint64_t>(status.rss) * pageSize,
			status.utime, status.stime, status.cutime, status.cstime,
			cmdline.length() ? cmdline : status.comm,
			status.state == 'Z');
	}

	std::unordered_set<pid_t> collectDescendants(pid_t rootPid, const std::unordered_map<pid_t, std::vector<pid_t>> &children)
	{
		std::unordered_set<pid_t> result;
		std::queue<pid_t> q;
		q.push(rootPid);
		while (!q.empty())
		{
			const pid_t p = q.front();
			q.pop();
			const auto it = children.find(p);
			if (it == children.end())
				continue;
			for (const pid_t c : it->second)
				if (result.insert(c).second)
					q.push(c);
		}
		return result;
	}

	std::list<Process> processes()
	{
		// This process and all its descendants, gathered in one bulk query.
		return processSnapshot(ACE_OS::getpid());
	}

} // namespace os
