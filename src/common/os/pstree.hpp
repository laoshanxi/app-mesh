#pragma once

#include <list>
#include <set>

#include "../../common/Utility.h"
#include "linux.hpp"
#include "process.hpp"

namespace os
{

	// Returns a process tree rooted at the specified pid using the
	// specified list of processes (or an error if one occurs).
	inline std::shared_ptr<ProcessTree> pstree(
		pid_t pid,
		const std::list<Process> &processes)
	{
		const static char fname[] = "os::pstree() ";

		std::list<ProcessTree> children;
		for (const Process &proc : processes)
		{
			if (proc.parent == pid)
			{
				auto tree = pstree(proc.pid, processes);
				if (tree == nullptr)
				{
					return tree;
				}
				children.push_back(*(tree.get()));
			}
		}
		const auto iter = std::find_if(processes.begin(), processes.end(), [&pid](const Process &p)
									   { return p.pid == pid; });
		if (iter != processes.end())
			return std::make_shared<ProcessTree>(ProcessTree(*iter, children));

		LOG_ERR << fname << "No process <" << pid << "> found from tree";
		return nullptr;
	}

	// Returns a process tree for the specified pid (or all processes if
	// pid is none or the current process if pid is 0).
	inline std::shared_ptr<ProcessTree> pstree(pid_t pid = 0, void *ptree = nullptr)
	{
		if (pid == 0)
		{
			pid = getpid();
		}

		if (ptree == nullptr)
		{
			return pstree(pid, os::processes());
		}

		auto processTree = static_cast<std::list<Process> *>(ptree);
		if (processTree->empty())
		{
			// make the cache
			*processTree = os::processes();
		}

		return pstree(pid, *processTree);
	}

} // namespace os
