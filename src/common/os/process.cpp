// src/common/os/process.cpp
// Platform-agnostic process utilities.

#include "process.h"

#include <algorithm>
#include <list>

namespace os
{

	std::unordered_set<pid_t> pids(pid_t rootPid /* = ACE_OS::getpid() */)
	{
		auto result = child_pids(rootPid);
		result.insert(rootPid);
		return result;
	}

	std::shared_ptr<Process> process(pid_t pid)
	{
		static const size_t pageSize = os::pagesize();

		const std::shared_ptr<os::ProcessStatus> processStatus = os::status(pid);
		if (nullptr == processStatus)
		{
			return nullptr;
		}

		std::string commandLine = os::cmdline(pid);

		return std::make_shared<Process>(
			processStatus->pid,
			processStatus->ppid,
			processStatus->pgrp,
			processStatus->session,
			processStatus->rss * pageSize,
			processStatus->utime,
			processStatus->stime,
			processStatus->cutime,
			processStatus->cstime,
			commandLine.length() ? commandLine : processStatus->comm,
			processStatus->state == 'Z');
	}

	std::shared_ptr<Process> process(pid_t pid, const std::list<Process> &processes)
	{
		const auto iter = std::find_if(processes.begin(), processes.end(), [&pid](const Process &p)
									   { return p.pid == pid; });
		if (iter != processes.end())
			return std::make_shared<Process>(*iter);
		return nullptr;
	}

	std::list<Process> processes()
	{
		const auto pidList = os::pids();

		std::list<Process> result;
		for (pid_t pid : pidList)
		{
			auto processPtr = os::process(pid);
			if (processPtr != nullptr)
			{
				result.push_back(*(processPtr.get()));
			}
		}
		return result;
	}

} // namespace os
