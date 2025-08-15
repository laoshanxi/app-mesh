#pragma once

#include <chrono>
#include <fstream>
#include <list>
#include <memory>
#include <numeric>
#include <ostream>
#include <sstream>
#include <string>

// Platform-specific headers
#if defined(_WIN32)
#include <io.h>
#include <process.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <windows.h>
#else
#include <cerrno>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h> // For pid_t.
#include <unistd.h>
#endif

// macOS-specific headers
#if defined(__APPLE__)
#include <libproc.h>
#endif

#include <ace/OS.h>
#include <boost/filesystem.hpp> // directory_iterator

#include "../../common/Utility.h"

namespace os
{
#if defined(_WIN32)
	// RAII wrapper for Windows HANDLE
	class HandleRAII
	{
	private:
		HANDLE handle_;

	public:
		explicit HandleRAII(HANDLE handle = INVALID_HANDLE_VALUE) : handle_(handle) {}

		~HandleRAII()
		{
			if (handle_ != INVALID_HANDLE_VALUE && handle_ != NULL)
			{
				CloseHandle(handle_);
			}
		}

		// Non-copyable
		HandleRAII(const HandleRAII &) = delete;
		HandleRAII &operator=(const HandleRAII &) = delete;

		// Movable
		HandleRAII(HandleRAII &&other) noexcept : handle_(other.handle_)
		{
			other.handle_ = INVALID_HANDLE_VALUE;
		}

		HandleRAII &operator=(HandleRAII &&other) noexcept
		{
			if (this != &other)
			{
				reset();
				handle_ = other.handle_;
				other.handle_ = INVALID_HANDLE_VALUE;
			}
			return *this;
		}

		HANDLE get() const { return handle_; }
		HANDLE release()
		{
			HANDLE temp = handle_;
			handle_ = INVALID_HANDLE_VALUE;
			return temp;
		}

		void reset(HANDLE newHandle = INVALID_HANDLE_VALUE)
		{
			if (handle_ != INVALID_HANDLE_VALUE && handle_ != NULL)
			{
				CloseHandle(handle_);
			}
			handle_ = newHandle;
		}

		bool valid() const
		{
			return handle_ != INVALID_HANDLE_VALUE && handle_ != NULL;
		}

		// Allow implicit conversion to HANDLE for API calls
		operator HANDLE() const { return handle_; }
	};
#endif

	// RAII wrapper for malloc'd memory
	template <typename T>
	class MallocRAII
	{
	private:
		T *ptr_;

	public:
		explicit MallocRAII(T *ptr = nullptr) : ptr_(ptr) {}

		~MallocRAII()
		{
			if (ptr_)
			{
				free(ptr_);
			}
		}

		// Non-copyable
		MallocRAII(const MallocRAII &) = delete;
		MallocRAII &operator=(const MallocRAII &) = delete;

		// Movable
		MallocRAII(MallocRAII &&other) noexcept : ptr_(other.ptr_)
		{
			other.ptr_ = nullptr;
		}

		MallocRAII &operator=(MallocRAII &&other) noexcept
		{
			if (this != &other)
			{
				reset();
				ptr_ = other.ptr_;
				other.ptr_ = nullptr;
			}
			return *this;
		}

		T *get() const { return ptr_; }
		T *release()
		{
			T *temp = ptr_;
			ptr_ = nullptr;
			return temp;
		}

		void reset(T *newPtr = nullptr)
		{
			if (ptr_)
			{
				free(ptr_);
			}
			ptr_ = newPtr;
		}

		bool valid() const { return ptr_ != nullptr; }

		// Allow pointer-like operations
		T &operator*() const { return *ptr_; }
		T *operator->() const { return ptr_; }
		operator T *() const { return ptr_; }
	};

	// Returns the number of open file descriptors for the specified process.
	inline size_t getOpenFileDescriptorCount(pid_t pid = ::getpid())
	{
		const static char fname[] = "os::getOpenFileDescriptorCount() ";
		size_t result = 0;

		// Check if the pid is valid.
		if (pid <= 0)
		{
			LOG_WAR << fname << "Invalid PID provided: " << pid << ". PID must be greater than zero.";
			return result;
		}

#if defined(_WIN32)
		// Windows implementation using RAII
		HandleRAII hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
		if (!hProcess.valid())
		{
			LOG_WAR << fname << "Failed to open process " << pid << ", error: " << GetLastError();
			return result;
		}

		// Get handle count (approximate file descriptors)
		DWORD handleCount = 0;
		if (GetProcessHandleCount(hProcess.get(), &handleCount))
		{
			result = handleCount;
			LOG_DBG << fname << "Found " << result << " handles for process " << pid;
		}
		else
		{
			LOG_WAR << fname << "Failed to get handle count for process " << pid << ", error: " << GetLastError();
		}

#elif defined(__APPLE__)
		// macOS implementation - Fixed buffer size calculation
		constexpr size_t MAX_FDS = 4096; // Reasonable maximum
		std::vector<proc_fdinfo> fdinfo(MAX_FDS);

		int bytes_returned = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, fdinfo.data(),
										  fdinfo.size() * sizeof(proc_fdinfo));

		if (bytes_returned <= 0)
		{
			if (errno == ESRCH)
			{
				LOG_WAR << fname << "Process " << pid << " does not exist";
			}
			else
			{
				LOG_WAR << fname << "Failed to get file descriptors info for pid " << pid
						<< ", error: " << strerror(errno);
			}
		}
		else
		{
			// Calculate actual number of file descriptors
			result = bytes_returned / sizeof(proc_fdinfo);
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
		// Linux implementation
		// 1. /proc/pid/fd/
		const auto procFdPath = std::string("/proc/") + std::to_string(pid) + "/fd";
		try
		{
			if (boost::filesystem::exists(procFdPath) && ACE_OS::access(procFdPath.c_str(), R_OK) == 0)
			{
				result += std::distance(boost::filesystem::directory_iterator(procFdPath),
										boost::filesystem::directory_iterator());
			}
			else
			{
				LOG_WAR << fname << "no such path or no permission: " << procFdPath;
			}
		}
		catch (const std::exception &e)
		{
			LOG_WAR << fname << "Error accessing " << procFdPath << ": " << e.what();
		}

		// 2. /proc/pid/maps
		const auto procMapsPath = std::string("/proc/") + std::to_string(pid) + "/maps";
		std::ifstream maps(procMapsPath, std::ifstream::in);
		if (maps.is_open())
		{
			std::string line;
			size_t mapCount = 0;
			while (std::getline(maps, line))
			{
				mapCount++;
			}
			result += mapCount;
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
				static_cast<uint64_t>(os::getOpenFileDescriptorCount(process.pid)),
				[](const uint64_t &files, const ProcessTree &process)
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

		std::list<os::Process> getProcesses() const
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

		pid_t findLeafPid() const
		{
			// recurse into children
			for (const auto &child : this->children)
			{
				return child.findLeafPid();
			}

			// no child - this is a leaf
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

#if defined(_WIN32)
		// Windows implementation using RAII
		HandleRAII hProcess(OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid));
		if (!hProcess.valid())
		{
			DWORD error = GetLastError();
			if (error == ERROR_INVALID_PARAMETER)
			{
				LOG_WAR << fname << "Process " << pid << " does not exist";
			}
			else
			{
				LOG_WAR << fname << "Failed to open process " << pid << ", error: " << error;
			}
			return std::numeric_limits<uid_t>::max();
		}

		HandleRAII hToken;
		HANDLE tempToken = NULL;
		if (!OpenProcessToken(hProcess.get(), TOKEN_QUERY, &tempToken))
		{
			LOG_WAR << fname << "Failed to open process token for PID " << pid << ", error: " << GetLastError();
			return std::numeric_limits<uid_t>::max();
		}
		hToken.reset(tempToken);

		DWORD tokenLength = 0;
		// First call to get required buffer size
		GetTokenInformation(hToken.get(), TokenUser, NULL, 0, &tokenLength);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
		{
			LOG_WAR << fname << "Failed to get token information size for PID " << pid << ", error: " << GetLastError();
			return std::numeric_limits<uid_t>::max();
		}

		MallocRAII<TOKEN_USER> tokenUser(static_cast<TOKEN_USER *>(malloc(tokenLength)));
		if (!tokenUser.valid())
		{
			LOG_WAR << fname << "Failed to allocate memory for token user";
			return std::numeric_limits<uid_t>::max();
		}

		if (!GetTokenInformation(hToken.get(), TokenUser, tokenUser.get(), tokenLength, &tokenLength))
		{
			LOG_WAR << fname << "Failed to get token information for PID " << pid << ", error: " << GetLastError();
			return std::numeric_limits<uid_t>::max();
		}

		// Convert SID to a simple numeric representation
		// In Windows, we'll use the relative identifier (RID) as the UID equivalent
		PSID_IDENTIFIER_AUTHORITY pIdentifierAuthority = GetSidIdentifierAuthority(tokenUser->User.Sid);
		DWORD subAuthorityCount = *GetSidSubAuthorityCount(tokenUser->User.Sid);
		uid_t uid = 0;

		if (subAuthorityCount > 0)
		{
			uid = *GetSidSubAuthority(tokenUser->User.Sid, subAuthorityCount - 1);
		}

		LOG_DBG << fname << "UID equivalent for process " << pid << " is " << uid;
		return uid;

#elif defined(__linux__)
		// Linux implementation using /proc
		std::string procPath = std::string("/proc/") + std::to_string(pid);
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

#elif defined(__APPLE__)
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
