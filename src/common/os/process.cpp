// src/common/os/process.cpp
// Platform-agnostic process utilities.

#include "process.h"

#include <algorithm>
#include <list>
#include <queue>

namespace os
{

	Process makeProcess(const ProcessStatus &status, const std::string &cmdline)
	{
		static const size_t pageSize = os::pagesize();
		return Process(
			status.pid, status.ppid, status.pgrp, status.session,
			static_cast<uint64_t>(std::max<int64_t>(0, status.rss)) * pageSize,
			status.utime, status.stime,
			static_cast<uint64_t>(std::max<int64_t>(0, status.cutime)),
			static_cast<uint64_t>(std::max<int64_t>(0, status.cstime)),
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
		// Recovered applications may not be daemon descendants.
		return processSnapshot(0);
	}

	std::list<Process> processes(const std::vector<pid_t> &rootPids)
	{
		if (rootPids.empty())
			return {};
#if defined(__APPLE__)
		return processSnapshot(rootPids);
#else
		auto snapshot = processSnapshot(0);
		std::unordered_map<pid_t, std::vector<pid_t>> children;
		for (const auto &process : snapshot)
			children[process.parent].push_back(process.pid);
		std::unordered_set<pid_t> selected;
		for (const auto root : rootPids)
		{
			if (root <= 0)
				continue;
			selected.insert(root);
			const auto descendants = collectDescendants(root, children);
			selected.insert(descendants.begin(), descendants.end());
		}
		snapshot.remove_if([&selected](const Process &process) { return selected.count(process.pid) == 0; });
		return snapshot;
#endif
	}

} // namespace os
