// src/common/os/pstree.cpp
#include "pstree.h"

namespace os
{
	std::shared_ptr<ProcessTree> ProcessTree::find(pid_t pid) const
	{
		if (process.pid == pid)
		{
			// make a copy of this
			return std::make_shared<ProcessTree>(*this);
		}

		for (const ProcessTree &tree : children)
		{
			std::shared_ptr<ProcessTree> option = tree.find(pid);
			if (option != nullptr)
			{
				return option;
			}
		}

		return nullptr;
	}

	uint64_t ProcessTree::totalRssMemBytes() const
	{
		uint64_t result = std::accumulate(
			children.begin(), children.end(),
			process.rss_bytes,
			[](const uint64_t &bytes, const ProcessTree &process)
			{ return bytes + process.totalRssMemBytes(); });
		return result;
	}

	uint64_t ProcessTree::totalFileDescriptors() const
	{
		uint64_t result = std::accumulate(
			children.begin(), children.end(),
			static_cast<uint64_t>(os::getOpenFileDescriptorCount(process.pid)),
			[](const uint64_t &files, const ProcessTree &process)
			{ return files + process.totalFileDescriptors(); });
		return result;
	}

	uint64_t ProcessTree::totalCpuTime() const
	{
		// On Linux, the formula to calculate the total CPU time for a process is (not include child process):
		//     total_cpu_time = process.utime + process.stime + process.cutime + process.cstime
		// On macOS, the total CPU time for a process including all threads and child processes as:
		//     total_cpu_time = task_info.pti_total_user + task_info.pti_total_system
		// On Windows, we use the sum of user and kernel time
#if defined(__APPLE__)
		return static_cast<uint64_t>(this->process.cutime + this->process.cstime);
#elif defined(_WIN32)
		return static_cast<uint64_t>(this->process.utime + this->process.stime);
#else
		uint64_t result = std::accumulate(
			children.begin(), children.end(),
			static_cast<uint64_t>(process.utime + process.stime + process.cutime + process.cstime),
			[](const uint64_t &time, const ProcessTree &process)
			{ return time + process.totalCpuTime(); });
		return result;
#endif
	}

	std::list<os::Process> ProcessTree::getProcesses() const
	{
		std::list<os::Process> result;
		result.push_back(this->process);
		for (const auto &tree : children)
		{
			auto childProcesses = tree.getProcesses();
			result.splice(result.end(), childProcesses);
		}
		return result;
	}

	pid_t ProcessTree::findLeafPid() const
	{
		// recurse into children
		for (const auto &child : this->children)
		{
			return child.findLeafPid();
		}

		// no child - this is a leaf
		return this->process.pid;
	}

	bool ProcessTree::contains(pid_t pid) const
	{
		return find(pid) != nullptr;
	}

	ProcessTree::operator Process() const
	{
		return process;
	}

	ProcessTree::operator pid_t() const
	{
		return process.pid;
	}

	ProcessTree::ProcessTree(const Process &_process, const std::list<ProcessTree> &_children)
		: process(_process), children(_children)
	{
	}

	std::ostream &operator<<(std::ostream &stream, const ProcessTree &tree)
	{
		if (tree.children.empty())
		{
			stream << "--- " << tree.process.pid << " ";
			if (tree.process.zombie)
			{
				stream << "(" << tree.process.command << ")";
			}
			else
			{
				stream << tree.process.command;
			}
		}
		else
		{
			stream << "-+- " << tree.process.pid << " ";
			if (tree.process.zombie)
			{
				stream << "(" << tree.process.command << ")";
			}
			else
			{
				stream << tree.process.command;
			}
			size_t size = tree.children.size();
			for (const ProcessTree &child : tree.children)
			{
				std::ostringstream out;
				out << child;
				stream << "\n";
				if (--size != 0)
				{
					stream << " |" << Utility::stringReplace(out.str(), "\n", "\n |");
				}
				else
				{
					stream << " \\" << Utility::stringReplace(out.str(), "\n", "\n  ");
				}
			}
		}
		return stream;
	}

	std::ostream &operator<<(std::ostream &stream, const std::list<os::ProcessTree> &list)
	{
		stream << "[ " << std::endl;
		std::list<os::ProcessTree>::const_iterator iterator = list.begin();
		while (iterator != list.end())
		{
			stream << *iterator;
			if (++iterator != list.end())
			{
				stream << std::endl
					   << std::endl;
			}
		}
		stream << std::endl
			   << "]";
		return stream;
	}

	std::shared_ptr<ProcessTree> pstree(pid_t pid, const std::list<Process> &processes)
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

	std::shared_ptr<ProcessTree> pstree(pid_t pid, void *ptree)
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
