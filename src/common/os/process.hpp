#pragma once

#include <chrono>
#include <fstream>
#include <list>
#include <memory>
#include <numeric>
#include <ostream>
#include <sstream>
#include <string>
#include <sys/types.h> // For pid_t.

// macOS-specific headers
#if defined(__APPLE__)
#include <libproc.h>
#endif

#include <ace/OS.h>
#include <boost/filesystem.hpp> // directory_iterator

#include "../../common/Utility.h"

namespace os
{
	// https://stackoverflow.com/questions/6583158/finding-open-file-descriptors-for-a-process-linux-c-code
	// https://stackoverflow.com/questions/4470121/how-to-use-lsoflist-opened-files-in-a-c-c-application
	// get process open file descriptors
	inline size_t fileDescriptors(pid_t pid = ::getpid())
	{
		const static char fname[] = "os::fileDescriptors() ";
		size_t result = 0;

		// Check if the pid is valid.
		if (pid <= 0)
		{
			LOG_WAR << fname << "Invalid PID provided: " << pid << ". PID must be greater than zero.";
			return result;
		}

#if defined(__APPLE__)
		// Get file descriptors count
		proc_fdinfo fdinfo[PROC_PIDLISTFD_SIZE];
		int num_fds = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo, PROC_PIDLISTFD_SIZE);

		if (num_fds <= 0)
		{
			LOG_WAR << fname << "Failed to get file descriptors info for pid " << pid
					<< ", error: " << strerror(errno);
		}
		else
		{
			result += num_fds / PROC_PIDLISTFD_SIZE;
			LOG_DBG << fname << "Found " << result << " file descriptors";
		}

		// Get memory mapped files count
		char pathbuf[PROC_PIDPATHINFO_MAXSIZE];
		if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0)
		{
			LOG_WAR << fname << "Failed to get process path for pid " << pid
					<< ", error: " << strerror(errno);
		}

		proc_taskallinfo task_info;
		if (proc_pidinfo(pid, PROC_PIDTASKALLINFO, 0, &task_info, sizeof(task_info)) <= 0)
		{
			LOG_WAR << fname << "Failed to get task info for pid " << pid
					<< ", error: " << strerror(errno);
		}
		else
		{
			// Add number of memory mapped files
			result += task_info.pbsd.pbi_nfiles;
			LOG_DBG << fname << "Total count including memory mapped files: " << result;
		}

#else
		// 1. /proc/pid/fd/
		const auto procFdPath = fs::path("/proc") / std::to_string(pid) / "fd";
		if (fs::exists(procFdPath.string()) && ACE_OS::access(procFdPath.c_str(), R_OK) == 0)
		{
			result += std::distance(boost::filesystem::directory_iterator(procFdPath),
									boost::filesystem::directory_iterator());
		}
		else
		{
			LOG_WAR << fname << "no such path or no permission: " << procFdPath;
		}
		// 2. /proc/pid/maps
		const auto procMapsPath = fs::path("/proc") / std::to_string(pid) / "maps";
		std::ifstream maps(procMapsPath.string(), std::ifstream::in);
		if (maps.is_open())
		{
			std::string line;
			for (; std::getline(maps, line); result++)
				;
		}
		else
		{
			LOG_WAR << fname << "failed to open: " << procMapsPath;
		}
#endif

		return result;
	};

	struct Process
	{
		Process(pid_t _pid,
				pid_t _parent,
				pid_t _group,
				const pid_t &_session,
				const uint64_t &_rss_bytes,
				const unsigned long &_utime,
				const unsigned long &_stime,
				const unsigned long &_cutime,
				const unsigned long &_cstime,
				const std::string &_command,
				bool _zombie)
			: pid(_pid),
			  parent(_parent),
			  group(_group),
			  session(_session),
			  rss_bytes(_rss_bytes),
			  utime(_utime),
			  stime(_stime),
			  cutime(_cutime),
			  cstime(_cstime),
			  command(_command),
			  zombie(_zombie) {}

		const pid_t pid;
		const pid_t parent;
		const pid_t group;
		const pid_t session;
		// Resident Set Size
		const uint64_t rss_bytes;
		const unsigned long utime;
		const unsigned long stime;
		const unsigned long cutime;
		const unsigned long cstime;
		const std::string command;
		const bool zombie;

		bool operator<(const Process &p) const { return pid < p.pid; }
		bool operator<=(const Process &p) const { return pid <= p.pid; }
		bool operator>(const Process &p) const { return pid > p.pid; }
		bool operator>=(const Process &p) const { return pid >= p.pid; }
		bool operator==(const Process &p) const { return pid == p.pid; }
		bool operator!=(const Process &p) const { return pid != p.pid; }
	};

	class ProcessTree
	{
	public:
		// Returns a process subtree rooted at the specified PID, or none if
		// the specified pid could not be found in this process tree.
		std::shared_ptr<ProcessTree> find(pid_t pid) const
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

		// Count the total RES memory usage in the process tree
		uint64_t totalRssMemBytes() const
		{
			uint64_t result = std::accumulate(
				children.begin(), children.end(),
				process.rss_bytes,
				[](const uint64_t &bytes, const ProcessTree &process)
				{ return bytes + process.totalRssMemBytes(); });
			return result;
		}

		uint64_t totalFileDescriptors() const
		{
			uint64_t result = std::accumulate(
				children.begin(), children.end(),
				os::fileDescriptors(process.pid),
				[](const size_t &files, const ProcessTree &process)
				{ return files + process.totalFileDescriptors(); });
			return result;
		}

		// get total CPU time
		uint64_t totalCpuTime() const
		{
			// On Linux, the formula to calculate the total CPU time for a process is (not include child process):
			//     total_cpu_time = process.utime + process.stime + process.cutime + process.cstime
			// On macOS, the total CPU time for a process including all threads and child processes as:
			//     total_cpu_time = task_info.pti_total_user + task_info.pti_total_system
#if defined(__APPLE__)
			return this->process.cutime + this->process.cstime;
#else

			uint64_t result = std::accumulate(
				children.begin(), children.end(),
				process.utime + process.stime + process.cutime + process.cstime,
				[](const size_t &files, const ProcessTree &process)
				{ return files + process.totalCpuTime(); });
			return result;
#endif
		}

		std::list<os::Process> getProcesses() const
		{
			std::list<os::Process> result;
			result.push_back(this->process);
			for (auto tree : children)
			{
				result.merge(tree.getProcesses());
			}
			return result;
		}

		pid_t findLeafPid() const
		{
			// recurse into children
			for (const auto &child : this->children)
			{
				return child.findLeafPid();
			}

			// no child
			return this->process.pid;
		}

		// Checks if the specified pid is contained in this process tree.
		bool contains(pid_t pid) const
		{
			return find(pid) != nullptr;
		}

		operator Process() const
		{
			return process;
		}

		operator pid_t() const
		{
			return process.pid;
		}

		const Process process;
		const std::list<ProcessTree> children;

	private:
		friend std::shared_ptr<ProcessTree> pstree(pid_t, const std::list<Process> &);

		ProcessTree(const Process &_process, const std::list<ProcessTree> &_children)
			: process(_process), children(_children)
		{
		}
	};

	inline std::ostream &operator<<(std::ostream &stream, const ProcessTree &tree)
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

	inline std::ostream &operator<<(std::ostream &stream, const std::list<os::ProcessTree> &list)
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

	inline uid_t getProcessUid(pid_t pid)
	{
		const static char fname[] = "os::getProcessUid() ";

		if (pid <= 0)
		{
			LOG_WAR << fname << "Invalid PID: " << pid;
			return std::numeric_limits<uid_t>::max();
		}

#ifdef __linux__
		// Linux implementation using /proc
		fs::path procPath = fs::path("/proc") / std::to_string(pid);
		struct stat statBuf;

		// Get the stat information for the /proc/[pid] directory
		// Using lstat to handle symbolic links
		if (lstat(procPath.c_str(), &statBuf) != 0)
		{
			// More specific error reporting
			if (errno == ENOENT)
			{
				LOG_WAR << fname << "Process " << pid << " does not exist";
			}
			else
			{
				LOG_WAR << fname << "Failed to stat " << procPath << ": " << std::strerror(errno);
			}
			return std::numeric_limits<uid_t>::max();
		}

		// Check if it's a symbolic link
		if (S_ISLNK(statBuf.st_mode))
		{
			LOG_WAR << fname << "Path is a symbolic link: " << procPath;
			return std::numeric_limits<uid_t>::max();
		}

		LOG_DBG << fname << "UID for process " << pid << " is " << statBuf.st_uid;
		return statBuf.st_uid;

#elif __APPLE__
		// macOS implementation using proc_pidinfo
		struct proc_bsdinfo procInfo;
		if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) <= 0)
		{
			if (errno == ESRCH)
			{
				LOG_WAR << fname << "Process " << pid << " does not exist";
			}
			else
			{
				LOG_WAR << fname << "Failed to get process info for PID " << pid << ": " << std::strerror(errno);
			}
			return std::numeric_limits<uid_t>::max();
		}

		LOG_DBG << fname << "UID for process " << pid << " is " << procInfo.pbi_uid;
		return procInfo.pbi_uid;

#else
		LOG_WAR << fname << "Unsupported platform";
		return std::numeric_limits<uid_t>::max();
#endif
	}

} // namespace os
