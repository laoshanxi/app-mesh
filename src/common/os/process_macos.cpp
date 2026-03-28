// src/common/os/process_macos.cpp
// macOS-specific process utilities using libproc and sysctl.

#include "process.h"

#include <cstring>
#include <libproc.h>
#include <queue>
#include <unordered_map>
#include <sys/proc_info.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <vector>

#include <assert.h>

#include "../Utility.h"

namespace os
{

	size_t pagesize()
	{
		long result = ::sysconf(_SC_PAGESIZE);
		assert(result >= 0);
		return static_cast<size_t>(result);
	}

	std::shared_ptr<ProcessStatus> status(pid_t pid)
	{
		const static char fname[] = "proc::status() ";

		if (pid <= 0)
		{
			return nullptr;
		}

		struct proc_taskinfo task_info;
		struct proc_bsdinfo bsd_info;

		if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task_info, sizeof(task_info)) <= 0)
		{
			LOG_DBG << fname << "Failed to fetch task info for PID: " << pid;
			return nullptr;
		}

		if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info)) <= 0)
		{
			LOG_DBG << fname << "Failed to fetch BSD info for PID: " << pid;
			return nullptr;
		}

		char name[MAXCOMLEN + 1] = {};
		proc_name(pid, name, sizeof(name));

		char state = 'R';
		switch (bsd_info.pbi_status)
		{
		case SSLEEP:
			state = 'S';
			break;
		case SRUN:
			state = 'R';
			break;
		case SSTOP:
			state = 'T';
			break;
		case SZOMB:
			state = 'Z';
			break;
		default:
			state = 'U';
			break;
		}

		return std::make_shared<ProcessStatus>(
			pid,
			std::string(name),
			state,
			bsd_info.pbi_ppid,
			bsd_info.pbi_pgid,
			0,
			task_info.pti_total_user,
			task_info.pti_total_system,
			0,
			0,
			bsd_info.pbi_start_tvsec,
			task_info.pti_virtual_size,
			task_info.pti_resident_size / getpagesize());
	}

	std::string cmdline(pid_t pid /* = 0 */)
	{
		const static char fname[] = "proc::cmdline() ";

		if (pid == 0)
		{
			pid = getpid();
		}

		int mib[3] = {CTL_KERN, KERN_PROCARGS2, static_cast<int>(pid)};
		size_t argmax = 0;
		if (sysctl(mib, 3, nullptr, &argmax, nullptr, 0) != 0 || argmax == 0 || argmax > 64 * 1024)
		{
			LOG_WAR << fname << "sysctl(KERN_PROCARGS2) size query failed for pid " << pid << ": " << last_error_msg();
			return {};
		}

		std::vector<char> buf(argmax);
		if (sysctl(mib, 3, buf.data(), &argmax, nullptr, 0) != 0)
		{
			LOG_WAR << fname << "sysctl(KERN_PROCARGS2) read failed for pid " << pid << ": " << last_error_msg();
			return {};
		}

		char *ptr = buf.data();
		int argc = 0;
		std::memcpy(&argc, ptr, sizeof(argc));
		ptr += sizeof(argc);

		while (ptr < buf.data() + argmax && *ptr != '\0')
			++ptr;
		if (ptr < buf.data() + argmax)
			++ptr;

		std::string out;
		for (int i = 0; i < argc && ptr < buf.data() + argmax; ++i)
		{
			std::string arg = std::string(ptr);
			out += arg;
			if (i != argc - 1)
				out.push_back(' ');
			ptr += arg.size() + 1;
		}

		return out;
	}

	std::unordered_set<pid_t> child_pids(pid_t rootPid)
	{
		std::unordered_set<pid_t> result;
		std::unordered_map<pid_t, std::vector<pid_t>> children;

		int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
		size_t size = 0;
		if (sysctl(mib, 3, nullptr, &size, nullptr, 0) != 0)
			return result;

		std::vector<char> buf(size + sizeof(struct kinfo_proc) * 10);
		if (sysctl(mib, 3, buf.data(), &size, nullptr, 0) != 0)
			return result;

		size_t nproc = size / sizeof(struct kinfo_proc);
		struct kinfo_proc *procs = reinterpret_cast<struct kinfo_proc *>(buf.data());

		for (size_t i = 0; i < nproc; ++i)
		{
			pid_t pid = procs[i].kp_proc.p_pid;
			pid_t ppid = procs[i].kp_eproc.e_ppid;
			children[ppid].push_back(pid);
		}

		std::queue<pid_t> q;
		q.push(rootPid);
		while (!q.empty())
		{
			pid_t p = q.front();
			q.pop();
			auto it = children.find(p);
			if (it == children.end())
				continue;
			for (pid_t c : it->second)
			{
				if (result.insert(c).second)
					q.push(c);
			}
		}
		return result;
	}

} // namespace os
