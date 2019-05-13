#ifndef __STOUT_OS_PSTREE_HPP__
#define __STOUT_OS_PSTREE_HPP__

#include <list>
#include <set>

#include <unistd.h>
#include "process.hpp"
#include "linux.hpp"
#include "../../common/Utility.h"


namespace os {

	// Returns a process tree rooted at the specified pid using the
	// specified list of processes (or an error if one occurs).
	inline std::shared_ptr<ProcessTree> pstree(
		pid_t pid,
		const std::list<Process>& processes)
	{
		const static char fname[] = "os::pstree() ";

		std::list<ProcessTree> children;
		for (const Process& process : processes) {
			if (process.parent == pid) {
				auto tree = pstree(process.pid, processes);
				if (tree == nullptr) {
					return tree;
				}
				children.push_back(*(tree.get()));
			}
		}

		for (const Process& process : processes) {
			if (process.pid == pid) {
				return std::make_shared<ProcessTree>(ProcessTree(process, children));
			}
		}

		LOG_ERR << fname << "No process found at " << pid;
		return nullptr;
	}


	// Returns a process tree for the specified pid (or all processes if
	// pid is none or the current process if pid is 0).
	inline std::shared_ptr<ProcessTree> pstree(pid_t pid = 0)
	{
		if (pid == 0) {
			pid = getpid();
		}

		const std::list<Process> processes = os::processes();

		if (processes.size() == 0) {
			return nullptr;
		}

		return pstree(pid, processes);
	}


	// Returns the minimum list of process trees that include all of the
	// specified pids using the specified list of processes.
	inline std::list<ProcessTree> pstrees(
		const std::set<pid_t>& pids,
		const std::list<Process>& processes)
	{
		std::list<ProcessTree> trees;

		for (pid_t pid : pids) {
			// First, check if the pid is already connected to one of the
			// process trees we've constructed.
			bool disconnected = true;
			for (const ProcessTree& tree : trees) {
				if (tree.contains(pid)) {
					disconnected = false;
					break;
				}
			}

			if (disconnected) {
				auto tree = pstree(pid, processes);
				if (tree == nullptr) {
					return std::list<ProcessTree>();
				}

				// Now see if any of the existing process trees are actually
				// contained within the process tree we just created and only
				// include the disjoint process trees.
				// C++11:
				// trees = trees.filter([](const ProcessTree& t) {
				//   return tree.get().contains(t);
				// });
				std::list<ProcessTree> trees_ = trees;
				trees.clear();
				for (const ProcessTree& t : trees_) {
					if (tree->contains(t.process.pid)) {
						continue;
					}
					trees.push_back(t);
				}
				trees.push_back(*(tree.get()));
			}
		}

		return trees;
	}

} // namespace os {

#endif // __STOUT_OS_PSTREE_HPP__
