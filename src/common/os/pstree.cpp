// src/common/os/pstree.cpp
#include "pstree.h"

#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

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
		// Linux also exposes waited-child time; macOS and Windows expose own user/system time.
#if defined(__APPLE__) || defined(_WIN32)
		const auto ownCpuTime = static_cast<uint64_t>(process.utime + process.stime);
#else
		const auto ownCpuTime = static_cast<uint64_t>(process.utime + process.stime + process.cutime + process.cstime);
#endif
		return std::accumulate(
			children.begin(), children.end(), ownCpuTime,
			[](const uint64_t &time, const ProcessTree &child)
			{ return time + child.totalCpuTime(); });
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
		// Follow the first-child chain down to a leaf.
		if (!this->children.empty())
			return this->children.front().findLeafPid();
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
		std::unordered_map<pid_t, const Process *> byPid;
		std::unordered_map<pid_t, std::vector<pid_t>> childrenByPid;
		for (const Process &proc : processes)
		{
			byPid[proc.pid] = &proc;
			childrenByPid[proc.parent].push_back(proc.pid);
		}

		std::unordered_set<pid_t> visiting;
		std::function<std::shared_ptr<ProcessTree>(pid_t)> build = [&](pid_t currentPid) {
			const auto process = byPid.find(currentPid);
			if (process == byPid.end() || !visiting.insert(currentPid).second)
				return std::shared_ptr<ProcessTree>();

			std::list<ProcessTree> children;
			const auto childPids = childrenByPid.find(currentPid);
			if (childPids != childrenByPid.end())
			{
				for (const auto childPid : childPids->second)
				{
					auto child = build(childPid);
					if (child)
						children.push_back(*child);
				}
			}
			visiting.erase(currentPid);
			return std::make_shared<ProcessTree>(ProcessTree(*process->second, children));
		};

		auto result = build(pid);
		if (!result)
			LOG_ERR << fname << "No process <" << pid << "> found in process list";
		return result;
	}

	std::shared_ptr<ProcessTree> pstree(pid_t pid, void *ptree)
	{
		if (pid == 0)
		{
			pid = getpid();
		}

		if (ptree == nullptr)
		{
			return pstree(pid, os::processSnapshot(pid));
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
