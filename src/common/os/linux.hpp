#pragma once

// This file contains cross-platform OS utilities for Linux/macOS/Windows.

// Common headers
#include <atomic>
#include <chrono>
#include <fstream>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <queue>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#if defined(_WIN32)
// Windows headers
#define WIN32_LEAN_AND_MEAN
#include <direct.h>
#include <io.h>
#include <ntstatus.h>
#include <pdh.h>
#include <pdhmsg.h>
#include <process.h>
#include <psapi.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <tlhelp32.h>
#include <windows.h>
#include <winioctl.h>
#include <winternl.h>

#include <lmcons.h>
#include <memory>
#include <sddl.h>
#pragma comment(lib, "advapi32.lib")

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "pdh.lib")
#pragma comment(lib, "shlwapi.lib")

// Windows type definitions to match Unix types
typedef unsigned long long uint64_t;

// Windows type declare
typedef NTSTATUS(NTAPI *NtQuerySystemInformation_t)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
typedef NTSTATUS(NTAPI *NtQueryInformationProcess_t)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

static HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
#else
// Unix/Linux/macOS headers
#include <dirent.h> // Directory operations
#include <errno.h>	// Error codes
#include <pwd.h>
#include <stdlib.h>	   // General utilities
#include <sys/stat.h>  // File status and permissions
#include <sys/types.h> // For pid_t
#include <unistd.h>	   // For sysconf

#if defined(__linux__)
#include <linux/version.h> // Linux kernel version
#include <mntent.h>		   // Mount table entries
#include <sys/statvfs.h>   // File system information
#include <sys/sysinfo.h>   // System information
#endif

#if defined(__APPLE__)
#include <libproc.h>			// Process information
#include <mach/mach.h>			// Mach system calls
#include <mach/mach_host.h>		// Host information
#include <mach/mach_init.h>		// Mach initialization
#include <mach/mach_types.h>	// Mach types
#include <mach/vm_statistics.h> // VM statistics
#include <sys/mount.h>			// File system mount information
#include <sys/param.h>			// System parameters
#include <sys/proc_info.h>		// Process info
#include <sys/sysctl.h>			// System control interface
#endif

#endif // Windows vs Unix

#include <ace/OS.h>
#include <assert.h>

#include "../../common/Utility.h"
#include "process.hpp"

namespace os
{
	// RAII wrapper for FILE*
	class FileRAII
	{
	private:
		FILE *file_;

	public:
		explicit FileRAII(FILE *file = nullptr) : file_(file) {}

		~FileRAII()
		{
			if (file_)
			{
				fclose(file_);
			}
		}

		// Non-copyable
		FileRAII(const FileRAII &) = delete;
		FileRAII &operator=(const FileRAII &) = delete;

		// Movable
		FileRAII(FileRAII &&other) noexcept : file_(other.file_)
		{
			other.file_ = nullptr;
		}

		FileRAII &operator=(FileRAII &&other) noexcept
		{
			if (this != &other)
			{
				reset();
				file_ = other.file_;
				other.file_ = nullptr;
			}
			return *this;
		}

		FILE *get() const { return file_; }
		FILE *release()
		{
			FILE *temp = file_;
			file_ = nullptr;
			return temp;
		}

		void reset(FILE *newFile = nullptr)
		{
			if (file_)
			{
				fclose(file_);
			}
			file_ = newFile;
		}

		bool valid() const { return file_ != nullptr; }
	};

#ifdef __linux__
	// RAII wrapper for mount table operations
	class MountTableRAII
	{
	private:
		FILE *mountFile_;

	public:
		explicit MountTableRAII(const char *filename, const char *mode)
			: mountFile_(setmntent(filename, mode)) {}

		~MountTableRAII()
		{
			if (mountFile_)
			{
				endmntent(mountFile_);
			}
		}

		// Non-copyable
		MountTableRAII(const MountTableRAII &) = delete;
		MountTableRAII &operator=(const MountTableRAII &) = delete;

		// Movable
		MountTableRAII(MountTableRAII &&other) noexcept : mountFile_(other.mountFile_)
		{
			other.mountFile_ = nullptr;
		}

		MountTableRAII &operator=(MountTableRAII &&other) noexcept
		{
			if (this != &other)
			{
				reset();
				mountFile_ = other.mountFile_;
				other.mountFile_ = nullptr;
			}
			return *this;
		}

		FILE *get() const { return mountFile_; }
		bool valid() const { return mountFile_ != nullptr; }

	private:
		void reset()
		{
			if (mountFile_)
			{
				endmntent(mountFile_);
				mountFile_ = nullptr;
			}
		}
	};
#endif

	/**
	 * @brief List files in a directory.
	 *
	 * Retrieves the names of all files and directories in the specified directory.
	 * If the directory cannot be accessed, returns an empty vector.
	 *
	 * @param directory Path to the directory.
	 * @return A vector of file and directory names within the specified directory.
	 */
	inline std::vector<std::string> ls(const std::string &directory)
	{
		const static char fname[] = "os::ls() ";
		std::vector<std::string> result;

#if defined(_WIN32)
		// Windows implementation
		std::string searchPath = directory + "\\*";
		WIN32_FIND_DATAA findData;
		HandleRAII hFind(FindFirstFileA(searchPath.c_str(), &findData));

		if (!hFind.valid())
		{
			DWORD error = GetLastError();
			LOG_WAR << fname << "Failed to open directory: " << directory
					<< " (error=" << error << ")";
			return result;
		}

		do
		{
			std::string name = findData.cFileName;
			if (name != "." && name != "..")
			{
				result.push_back(std::move(name));
			}
		} while (FindNextFileA(hFind.get(), &findData));

		DWORD error = GetLastError();
		if (error != ERROR_NO_MORE_FILES)
		{
			LOG_WAR << fname << "Failed to read directory: " << directory
					<< " (error=" << error << ")";
		}

#else
		// Unix implementation
		std::unique_ptr<DIR, void (*)(DIR *)> dir(opendir(directory.c_str()),
												  [](DIR *d)
												  { if (d) closedir(d); });
		if (!dir)
		{
			LOG_WAR << fname << "Failed to open directory: " << directory
					<< " (errno=" << errno << ": " << last_error_msg() << ")";
			return result;
		}

		struct dirent *entry;
		errno = 0;

		while ((entry = readdir(dir.get())) != nullptr)
		{
			const std::string name = entry->d_name;
			if (name == "." || name == "..")
			{
				continue;
			}
			result.push_back(name);
		}

		if (errno != 0)
		{
			LOG_WAR << fname << "Failed to read directory: " << directory
					<< " (errno=" << errno << ": " << last_error_msg() << ")";
			return {};
		}
#endif
		return result;
	}

	// Snapshot of a process (cross-platform process status).
	struct ProcessStatus
	{
		ProcessStatus(
			pid_t _pid,
			const std::string &_comm,
			char _state,
			pid_t _ppid,
			pid_t _pgrp,
			pid_t _session,
			unsigned long _utime,
			unsigned long _stime,
			long _cutime,
			long _cstime,
			unsigned long long _starttime,
			unsigned long _vsize,
			long _rss)
			: pid(_pid),
			  comm(_comm),
			  state(_state),
			  ppid(_ppid),
			  pgrp(_pgrp),
			  session(_session),
			  utime(_utime),
			  stime(_stime),
			  cutime(_cutime),
			  cstime(_cstime),
			  starttime(_starttime),
			  vsize(_vsize),
			  rss(_rss)
		{
		}

		// get process start time
		std::chrono::system_clock::time_point get_starttime() const
		{
#if defined(_WIN32)
			// Windows: starttime is already a time_t
			return std::chrono::system_clock::from_time_t(static_cast<time_t>(starttime));

#elif defined(__linux__)
			static const long ticks_per_second = sysconf(_SC_CLK_TCK);
			// Read system uptime from /proc/uptime
			static std::atomic<double> uptime_seconds{0.0};
			static std::once_flag init_flag;
			std::call_once(init_flag, []()
						   {
				std::ifstream uptime_file("/proc/uptime");
				if (uptime_file)
				 {
					double temp_uptime = 0.0;
					uptime_file >> temp_uptime;
					uptime_seconds.store(temp_uptime);
				} });

			// Calculate system boot time in seconds
			time_t system_boot_time = time(nullptr) - static_cast<time_t>(uptime_seconds.load());
			// Calculate start time since system boot in seconds + boot time
			double start_time_seconds = system_boot_time + (static_cast<double>(starttime) / ticks_per_second);

			// Convert start time
			return std::chrono::system_clock::from_time_t(static_cast<time_t>(start_time_seconds));

#elif defined(__APPLE__)
			return std::chrono::system_clock::from_time_t(static_cast<time_t>(starttime));
#endif
		}

		const pid_t pid;
		const std::string comm;
		const char state;
		const pid_t ppid;
		const pid_t pgrp;
		const pid_t session;

		const unsigned long utime;
		const unsigned long stime;
		const long cutime;
		const long cstime;
		const unsigned long long starttime;
		const unsigned long vsize;
		const long rss;
	};

	/**
	 * @brief Get total system CPU time.
	 *
	 * Cross-platform implementation to get total CPU time.
	 *
	 * @return Total system CPU time in appropriate units, or 0 on error.
	 */
	inline int64_t cpuTotalTime()
	{
#if defined(_WIN32)
		FILETIME idleTime, kernelTime, userTime;
		if (GetSystemTimes(&idleTime, &kernelTime, &userTime))
		{
			auto fileTimeToInt64 = [](const FILETIME &ft) -> int64_t
			{
				ULARGE_INTEGER uli;
				uli.LowPart = ft.dwLowDateTime;
				uli.HighPart = ft.dwHighDateTime;
				return static_cast<int64_t>(uli.QuadPart / 10000); // Convert to milliseconds
			};

			return fileTimeToInt64(idleTime) + fileTimeToInt64(kernelTime) + fileTimeToInt64(userTime);
		}
		return 0;

#elif defined(__linux__)
		std::ifstream stat_file("/proc/stat");
		if (!stat_file)
			return 0;

		std::string line;
		std::getline(stat_file, line);

		unsigned long u, n, s, i, w, x, y, z; // as represented in /proc/stat
		std::string _;						  // For ignoring fields.
		std::istringstream data(line);
		// Parse all fields from stat.
		data >> _ >> u >> n >> s >> i >> w >> x >> y >> z;

		// Check for parsing errors
		if (data.fail())
		{
			return 0;
		}

		return u + n + s + i + w + x + y + z;

#elif defined(__APPLE__)
		host_cpu_load_info_data_t cpuinfo;
		mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
		if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO,
							(host_info_t)&cpuinfo, &count) == KERN_SUCCESS)
		{
			return cpuinfo.cpu_ticks[CPU_STATE_USER] +
				   cpuinfo.cpu_ticks[CPU_STATE_SYSTEM] +
				   cpuinfo.cpu_ticks[CPU_STATE_IDLE] +
				   cpuinfo.cpu_ticks[CPU_STATE_NICE];
		}
		return 0;
#endif
	}

	/**
	 * @brief Get the status of a process.
	 *
	 * Cross-platform process status retrieval.
	 *
	 * @param pid Process ID.
	 * @return A shared pointer to a `ProcessStatus` object, or `nullptr` if the process does not exist or an error occurs.
	 */
	inline std::shared_ptr<ProcessStatus> status(pid_t pid)
	{
		const static char fname[] = "proc::status() ";

		if (pid <= 0)
		{
			return nullptr;
		}

#if defined(_WIN32)
		HandleRAII hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
		if (!hProcess.valid())
		{
			LOG_DBG << fname << "Failed to open process: " << pid << " (error=" << GetLastError() << ")";
			return nullptr;
		}

		// Get process times
		FILETIME createTime, exitTime, kernelTime, userTime;
		if (!GetProcessTimes(hProcess.get(), &createTime, &exitTime, &kernelTime, &userTime))
		{
			return nullptr;
		}

		// Get process memory info
		PROCESS_MEMORY_COUNTERS memInfo;
		if (!GetProcessMemoryInfo(hProcess.get(), &memInfo, sizeof(memInfo)))
		{
			return nullptr;
		}

		// Get process name
		char processName[MAX_PATH] = {};
		DWORD nameSize = MAX_PATH;
		if (!QueryFullProcessImageNameA(hProcess.get(), 0, processName, &nameSize))
		{
			// Fallback to GetModuleBaseName
			GetModuleBaseNameA(hProcess.get(), NULL, processName, MAX_PATH);
		}

		// Extract just the filename from full path
		std::string comm = processName;
		size_t lastSlash = comm.find_last_of("\\/");
		if (lastSlash != std::string::npos)
		{
			comm = comm.substr(lastSlash + 1);
		}

		// Get parent process ID (requires toolhelp32)
		pid_t ppid = 0;
		HandleRAII hSnapshot(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0));
		if (hSnapshot.valid())
		{
			PROCESSENTRY32 pe32;
			pe32.dwSize = sizeof(PROCESSENTRY32);
			if (Process32First(hSnapshot.get(), &pe32))
			{
				do
				{
					if (pe32.th32ProcessID == static_cast<DWORD>(pid))
					{
						ppid = pe32.th32ParentProcessID;
						break;
					}
				} while (Process32Next(hSnapshot.get(), &pe32));
			}
		}

		// Convert FILETIME to time_t
		auto fileTimeToTimeT = [](const FILETIME &ft) -> time_t
		{
			ULARGE_INTEGER uli;
			uli.LowPart = ft.dwLowDateTime;
			uli.HighPart = ft.dwHighDateTime;
			return static_cast<time_t>((uli.QuadPart - 116444736000000000ULL) / 10000000ULL);
		};

		auto fileTimeToTicks = [](const FILETIME &ft) -> unsigned long
		{
			ULARGE_INTEGER uli;
			uli.LowPart = ft.dwLowDateTime;
			uli.HighPart = ft.dwHighDateTime;
			return static_cast<unsigned long>(uli.QuadPart / 10000); // Convert to milliseconds
		};

		return std::make_shared<ProcessStatus>(
			pid,
			comm,
			'R', // Windows doesn't have direct equivalent, default to running
			ppid,
			0, // Process group not applicable on Windows
			0, // Session not applicable on Windows
			fileTimeToTicks(userTime),
			fileTimeToTicks(kernelTime),
			0, // cutime not available
			0, // cstime not available
			fileTimeToTimeT(createTime),
			static_cast<unsigned long>(memInfo.PagefileUsage),
			static_cast<long>(memInfo.WorkingSetSize / 4096)); // Convert to pages

#elif defined(__linux__)
		// Linux implementation
		const std::string path = "/proc/" + std::to_string(pid) + "/stat";

		std::ifstream statFile(path);
		if (!statFile.is_open())
			return nullptr;

		std::string content;
		content.reserve(512); // typical size < 512 bytes
		content.assign(std::istreambuf_iterator<char>(statFile), std::istreambuf_iterator<char>());
		if (content.empty())
		{
			LOG_DBG << fname << "Process does not exist or file is empty: " << path;
			return nullptr;
		}

		// Parse /proc/[pid]/stat file format: pid (command) state ppid ...
		// The command field is enclosed in parentheses and can contain spaces
		std::string comm;
		char state;
		pid_t ppid;
		pid_t pgrp;
		pid_t session;
		int tty_nr;
		pid_t tpgid;
		unsigned int flags;
		unsigned long minflt;
		unsigned long cminflt;
		unsigned long majflt;
		unsigned long cmajflt;
		unsigned long utime;
		unsigned long stime;
		long cutime;
		long cstime;
		long priority;
		long nice;
		long num_threads;
		long itrealvalue;
		unsigned long long starttime;
		unsigned long vsize;
		long rss; // Resident Set Size (RSS) in pages, rss_linux_bytes = rss_linux_pages * linux_page_size;
		unsigned long rsslim;
		unsigned long startcode;
		unsigned long endcode;
		unsigned long startstack;
		unsigned long kstkeip;
		unsigned long signal;
		unsigned long blocked;
		unsigned long sigcatch;
		unsigned long wchan;
		unsigned long nswap;
		unsigned long cnswap;

		// Find the last ')' to handle command names with spaces/parentheses
		size_t lastParenPos = content.find_last_of(')');
		if (lastParenPos == std::string::npos)
		{
			LOG_DBG << fname << "Malformed stat file: " << path;
			return nullptr;
		}

		// Parse PID from the beginning
		pid_t parsedPid;
		if (sscanf(content.c_str(), "%d", &parsedPid) != 1)
		{
			LOG_WAR << fname << "Failed to parse PID from stat file: " << path;
			return nullptr;
		}

		// Extract command name (between first '(' and last ')')
		size_t firstParenPos = content.find('(');
		if (firstParenPos == std::string::npos || firstParenPos >= lastParenPos)
		{
			LOG_WAR << fname << "Malformed command name in stat file: " << path;
			return nullptr;
		}
		comm = content.substr(firstParenPos + 1, lastParenPos - firstParenPos - 1);

		// Parse all fields after the last ')'
		const char *afterParen = content.c_str() + lastParenPos + 1;
		if (sscanf(afterParen, " %c %d %d %d %d %d %u %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu %lu %ld %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
				   &state, &ppid, &pgrp, &session, &tty_nr, &tpgid, &flags, &minflt, &cminflt, &majflt, &cmajflt,
				   &utime, &stime, &cutime, &cstime, &priority, &nice, &num_threads, &itrealvalue, &starttime,
				   &vsize, &rss, &rsslim, &startcode, &endcode, &startstack, &kstkeip, &signal, &blocked,
				   &sigcatch, &wchan, &nswap, &cnswap) != 33)
		{
			LOG_WAR << fname << "Failed to parse all fields from stat file: " << path;
			return nullptr;
		}

		return std::make_shared<ProcessStatus>(
			pid, comm, state, ppid, pgrp, session, utime, stime, cutime, cstime, starttime, vsize, rss);

#elif defined(__APPLE__)
		// macOS implementation
		struct proc_taskinfo task_info;
		struct proc_bsdinfo bsd_info;

		// Get task information
		if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &task_info, sizeof(task_info)) <= 0)
		{
			LOG_DBG << fname << "Failed to fetch task info for PID: " << pid;
			return nullptr;
		}

		// Get BSD process info
		if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd_info, sizeof(bsd_info)) <= 0)
		{
			LOG_DBG << fname << "Failed to fetch BSD info for PID: " << pid;
			return nullptr;
		}

		// Get the process name
		char name[MAXCOMLEN + 1] = {};
		proc_name(pid, name, sizeof(name));

		// Map macOS process state to Linux-compatible state char
		char state = 'R'; // Default to running
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
			0,							// Session ID not available or use getsid(pid)
			task_info.pti_total_user,	// User time in clock ticks
			task_info.pti_total_system, // System time in clock ticks
			0,							// cutime
			0,							// cstime
			bsd_info.pbi_start_tvsec,
			task_info.pti_virtual_size,
			task_info.pti_resident_size / getpagesize());
#endif
		return nullptr;
	}

	/**
	 * @brief Get the command line of a process.
	 *
	 * Cross-platform command line retrieval.
	 *
	 * @param pid Process ID (default is 0, which represents the current process).
	 * @return A string containing the command line of the specified process.
	 */
	inline std::string cmdline(const pid_t &pid = 0)
	{
		const static char fname[] = "proc::cmdline() ";

#if defined(_WIN32)
		if (pid == 0)
		{
			// Get current process command line
			char *cmdLine = GetCommandLineA();
			return cmdLine ? std::string(cmdLine) : "";
		}

		HandleRAII hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
		if (!hProcess.valid())
		{
			LOG_WAR << fname << "Failed to open process (pid=" << pid << ") error: " << GetLastError();
			return "";
		}

		// HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
		if (!hNtDll)
		{
			LOG_ERR << fname << "Failed to get handle to ntdll.dll";
			return "";
		}

		auto NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(hNtDll, "NtQueryInformationProcess");
		if (!NtQueryInformationProcess)
		{
			LOG_WAR << fname << "Failed to get NtQueryInformationProcess address";
			return "";
		}

		// Query the PEB address
		PROCESS_BASIC_INFORMATION pbi;
		ULONG len;
		NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), &len);
		if (status != 0)
			return "";

		// Step 1: Read PEB
		PEB peb;
		if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), nullptr))
			return "";

		// Step 2: Read RTL_USER_PROCESS_PARAMETERS
		RTL_USER_PROCESS_PARAMETERS upp;
		if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &upp, sizeof(upp), nullptr))
			return "";

		// Step 3: Allocate buffer for the command line
		std::wstring cmd(upp.CommandLine.Length / sizeof(wchar_t), L'\0');

		// Step 4: Read the actual command line string from the remote process
		if (!ReadProcessMemory(hProcess, upp.CommandLine.Buffer, cmd.data(), upp.CommandLine.Length, nullptr))
			return "";

		// Step 5: Convert to UTF-8
		int size_needed = WideCharToMultiByte(CP_UTF8, 0, cmd.c_str(), (int)cmd.size(), nullptr, 0, nullptr, nullptr);
		std::string cmdline(size_needed, 0);
		WideCharToMultiByte(CP_UTF8, 0, cmd.c_str(), (int)cmd.size(), cmdline.data(), size_needed, nullptr, nullptr);

		return cmdline;

#elif defined(__linux__)
		// Linux implementation
		const std::string path = (pid > 0)
									 ? "/proc/" + std::to_string(pid) + "/cmdline"
									 : "/proc/cmdline";

		// Attempt to open the file
		std::ifstream file(path.c_str());
		if (!file.is_open())
		{
			// Check if the file exists to differentiate between missing files and other errors
			if (!Utility::isFileExist(path))
			{
				LOG_WAR << fname << "Process (pid=" << pid << ") may have terminated, file does not exist: " << path;
			}
			else
			{
				LOG_WAR << fname << "Failed to open <" << path << "> with error: " << last_error_msg();
			}
			return "";
		}

		std::stringbuf buffer;

		// Read the command line arguments separated by null bytes
		while (!file.eof())
		{
			file.get(buffer, '\0');

			if (file.fail() && !file.eof())
			{
				LOG_DBG << fname << "Read error occurred while accessing <" << path << ">, possibly incomplete data.";
				return "";
			}
			if (!file.eof())
			{
				file.get();		   // Consume the null byte
				buffer.sputc(' '); // Add space between arguments
			}
		}

		return buffer.str();

#elif defined(__APPLE__)
		// macOS implementation
		if (pid == 0)
		{
			LOG_DBG << fname << "No PID specified, returning empty cmdline.";
			return "";
		}

		char pathbuf[PROC_PIDPATHINFO_MAXSIZE];

		// Get the process path
		if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0)
		{
			LOG_WAR << fname << "Failed to retrieve path for PID=" << pid << " with error: " << last_error_msg();
			return "";
		}

		return std::string(pathbuf);
#endif
	}

#if defined(_WIN32)

#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

	// TODO: need check windows 32 bit definition
	// Ensure we have the correct structure definition
	typedef struct _SYSTEM_PROCESS_INFORMATION
	{
		ULONG NextEntryOffset;
		ULONG NumberOfThreads;
		LARGE_INTEGER WorkingSetPrivateSize;
		ULONG HardFaultCount;
		ULONG NumberOfThreadsHighWatermark;
		ULONGLONG CycleTime;
		LARGE_INTEGER CreateTime;
		LARGE_INTEGER UserTime;
		LARGE_INTEGER KernelTime;
		UNICODE_STRING ImageName;
		KPRIORITY BasePriority;
		HANDLE UniqueProcessId;
		HANDLE InheritedFromUniqueProcessId;
		ULONG HandleCount;
		ULONG SessionId;
		ULONG_PTR UniqueProcessKey;
		SIZE_T PeakVirtualSize;
		SIZE_T VirtualSize;
		ULONG PageFaultCount;
		SIZE_T PeakWorkingSetSize;
		SIZE_T WorkingSetSize;
		SIZE_T QuotaPeakPagedPoolUsage;
		SIZE_T QuotaPagedPoolUsage;
		SIZE_T QuotaPeakNonPagedPoolUsage;
		SIZE_T QuotaNonPagedPoolUsage;
		SIZE_T PagefileUsage;
		SIZE_T PeakPagefileUsage;
		SIZE_T PrivatePageCount;
		LARGE_INTEGER ReadOperationCount;
		LARGE_INTEGER WriteOperationCount;
		LARGE_INTEGER OtherOperationCount;
		LARGE_INTEGER ReadTransferCount;
		LARGE_INTEGER WriteTransferCount;
		LARGE_INTEGER OtherTransferCount;
	} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

	typedef NTSTATUS(NTAPI *NtQuerySystemInformation_t)(
		ULONG SystemInformationClass,
		PVOID SystemInformation,
		ULONG SystemInformationLength,
		PULONG ReturnLength);

	inline std::unordered_set<pid_t> child_pids(pid_t rootPid)
	{
		const static char fname[] = "proc::child_pids() ";
		std::unordered_set<pid_t> pids;

		// HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
		if (!hNtDll)
		{
			LOG_ERR << fname << "Failed to get handle to ntdll.dll";
			return pids;
		}

		auto NtQuerySystemInformation = (NtQuerySystemInformation_t)GetProcAddress(hNtDll, "NtQuerySystemInformation");
		if (!NtQuerySystemInformation)
		{
			LOG_ERR << fname << "Failed to get NtQuerySystemInformation address";
			return pids;
		}

		// Start with a reasonable size - 256KB is usually sufficient
		ULONG bufferSize = 256 * 1024; // 256KB
		std::vector<BYTE> buffer(bufferSize);
		ULONG returnLength = 0;
		NTSTATUS status;

		// Retry until buffer is large enough
		while ((status = NtQuerySystemInformation(SystemProcessInformation,
												  buffer.data(), bufferSize,
												  &returnLength)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			// Use the returned length plus some padding
			bufferSize = returnLength + 16 * 1024; // Add 16KB padding
			buffer.resize(bufferSize);
		}

		if (status < 0)
		{
			LOG_ERR << fname << "NtQuerySystemInformation failed, status=" << status;
			return pids;
		}

		// Build process tree using InheritedFromUniqueProcessId
		std::unordered_map<DWORD, std::vector<DWORD>> tree;
		std::unordered_set<DWORD> validPids;

		BYTE *ptr = buffer.data();
		while (true)
		{
			auto spi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION *>(ptr);
			DWORD pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->UniqueProcessId));
			DWORD ppid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(spi->InheritedFromUniqueProcessId));

			// Validate PID (skip System process and Idle process)
			if (pid != 0 && pid != 4)
			{
				validPids.insert(pid);
				tree[ppid].push_back(pid);
			}

			if (spi->NextEntryOffset == 0)
				break;

			ptr += spi->NextEntryOffset;
		}

		// BFS to collect all descendants
		std::queue<DWORD> q;
		q.push(rootPid);

		while (!q.empty())
		{
			DWORD parent = q.front();
			q.pop();

			auto it = tree.find(parent);
			if (it != tree.end())
			{
				for (DWORD child : it->second)
				{
					if (pids.insert(child).second)
					{
						q.push(child);
					}
				}
			}
		}

		return pids;
	}
#elif defined(__linux__)
	inline std::unordered_set<pid_t> child_pids(pid_t rootPid)
	{
		std::unordered_set<pid_t> pids;

		// Step 1: build parent -> children map
		std::unordered_map<pid_t, std::vector<pid_t>> children;
		std::unique_ptr<DIR, decltype(&closedir)> dir(opendir("/proc"), &closedir);
		if (!dir)
			return pids;

		struct dirent *entry;
		while ((entry = readdir(dir.get())) != nullptr)
		{
			char *end;
			long pid = strtol(entry->d_name, &end, 10);
			if (*end != '\0' || pid <= 0)
				continue;

			char statPath[64];
			snprintf(statPath, sizeof(statPath), "/proc/%ld/stat", pid);

			// RAII for FILE*
			std::unique_ptr<FILE, int (*)(FILE *)> f(fopen(statPath, "r"), fclose);
			if (!f)
				continue;

			pid_t curPid, ppid;
			char line[1024];
			if (fgets(line, sizeof(line), f.get()) != nullptr)
			{
				// Find the last ')' to handle command names with spaces/parentheses
				char *lastParen = strrchr(line, ')');
				if (lastParen != nullptr)
				{
					char state;
					if (sscanf(line, "%d", &curPid) == 1 &&
						sscanf(lastParen + 1, " %c %d", &state, &ppid) == 2)
					{
						children[ppid].push_back(curPid);
					}
				}
			}
		}

		// Step 2: BFS to collect descendants
		std::queue<pid_t> q;
		q.push(rootPid);

		while (!q.empty())
		{
			pid_t p = q.front();
			q.pop();

			auto it = children.find(p);
			if (it != children.end())
			{
				for (pid_t child : it->second)
				{
					if (pids.insert(child).second)
						q.push(child);
				}
			}
		}

		return pids;
	}
#elif defined(__APPLE__)
	inline std::unordered_set<pid_t> child_pids(pid_t rootPid)
	{
		std::unordered_set<pid_t> pids;

		std::unordered_map<pid_t, std::vector<pid_t>> children;

		// Step 1: get all processes using sysctl
		int mib[3] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL};
		size_t size = 0;
		if (sysctl(mib, 3, nullptr, &size, nullptr, 0) != 0)
			return pids;

		// Allocate buffer with some extra space in case process list grows
		size += sizeof(struct kinfo_proc) * 10;
		std::unique_ptr<char[]> buf(new char[size]);
		if (sysctl(mib, 3, buf.get(), &size, nullptr, 0) != 0)
			return pids;

		size_t nproc = size / sizeof(struct kinfo_proc);
		struct kinfo_proc *procs = reinterpret_cast<struct kinfo_proc *>(buf.get());

		// Step 2: build parent -> children map
		for (size_t i = 0; i < nproc; ++i)
		{
			pid_t pid = procs[i].kp_proc.p_pid;
			pid_t ppid = procs[i].kp_eproc.e_ppid;
			children[ppid].push_back(pid);
		}

		// Step 3: BFS from rootPid
		std::queue<pid_t> q;
		q.push(rootPid);

		while (!q.empty())
		{
			pid_t p = q.front();
			q.pop();

			auto it = children.find(p);
			if (it != children.end())
			{
				for (pid_t child : it->second)
				{
					if (pids.insert(child).second)
						q.push(child);
				}
			}
		}

		return pids;
	}
#endif

	/**
	 * @brief Get a list of all running process IDs.
	 *
	 * Cross-platform process enumeration.
	 *
	 * @return A set containing the PIDs of all running processes.
	 */
	inline std::unordered_set<pid_t> pids(pid_t rootPid = ACE_OS::getpid())
	{
		auto result = child_pids(rootPid);
		result.insert(rootPid);
		return result;
	}

	// Structure containing memory information
	struct Memory
	{
		Memory() : total_bytes(0), free_bytes(0), totalSwap_bytes(0), freeSwap_bytes(0) {}
		uint64_t total_bytes;
		uint64_t free_bytes;
		uint64_t totalSwap_bytes;
		uint64_t freeSwap_bytes;
	};

	inline std::ostream &operator<<(std::ostream &stream, const Memory &mem)
	{
		return stream << "Memory [total_bytes <" << mem.total_bytes << "> "
					  << "free_bytes <" << mem.free_bytes << "> "
					  << "totalSwap_bytes <" << mem.totalSwap_bytes << "> "
					  << "freeSwap_bytes <" << mem.freeSwap_bytes << ">]";
	}

	// Cross-platform page size
	inline size_t pagesize()
	{
#if defined(_WIN32)
		SYSTEM_INFO sysInfo;
		GetSystemInfo(&sysInfo);
		return static_cast<size_t>(sysInfo.dwPageSize);
#else
		long result = ::sysconf(_SC_PAGESIZE);
		assert(result >= 0);
		return static_cast<size_t>(result);
#endif
	}

	/**
	 * @brief Get process information for a given PID.
	 *
	 * Cross-platform process information retrieval.
	 *
	 * @param pid Process ID of the target process.
	 * @return Shared pointer to a Process struct containing the process details.
	 */
	inline std::shared_ptr<Process> process(pid_t pid)
	{
		// Page size, used for memory accounting.
		static const size_t pageSize = os::pagesize();

		const std::shared_ptr<os::ProcessStatus> processStatus = os::status(pid);
		if (nullptr == processStatus)
		{
			return nullptr;
		}

		// The command line from 'status->comm' is only "arg0" from "argv"
		// To get the entire command line we grab the full command line
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

	// Returns the total size of main and free memory.
	inline std::shared_ptr<Memory> memory()
	{
		auto memory = std::make_shared<Memory>();

#if defined(_WIN32)
		MEMORYSTATUSEX memStatus;
		memStatus.dwLength = sizeof(memStatus);
		if (GlobalMemoryStatusEx(&memStatus))
		{
			memory->total_bytes = memStatus.ullTotalPhys;
			memory->free_bytes = memStatus.ullAvailPhys;
			memory->totalSwap_bytes = memStatus.ullTotalPageFile - memStatus.ullTotalPhys;
			memory->freeSwap_bytes = memStatus.ullAvailPageFile - memStatus.ullAvailPhys;
		}
		else
		{
			return nullptr;
		}

#elif defined(__linux__)
		struct sysinfo info;
		if (sysinfo(&info) != 0)
		{
			return nullptr;
		}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 3, 23))
		memory->total_bytes = (info.totalram * info.mem_unit);
		memory->free_bytes = (info.freeram * info.mem_unit);
		memory->totalSwap_bytes = (info.totalswap * info.mem_unit);
		memory->freeSwap_bytes = (info.freeswap * info.mem_unit);
#else
		memory->total_bytes = (info.totalram);
		memory->free_bytes = (info.freeram);
		memory->totalSwap_bytes = (info.totalswap);
		memory->freeSwap_bytes = (info.freeswap);
#endif

#elif defined(__APPLE__)
		vm_size_t page_size;
		mach_port_t mach_port = mach_host_self();
		vm_statistics64_data_t vm_stats;
		mach_msg_type_number_t count = sizeof(vm_stats) / sizeof(natural_t);

		host_page_size(mach_port, &page_size);

		if (host_statistics64(mach_port, HOST_VM_INFO64,
							  (host_info64_t)&vm_stats, &count) != KERN_SUCCESS)
		{
			return nullptr;
		}

		uint64_t total_memory;
		size_t len = sizeof(total_memory);
		sysctlbyname("hw.memsize", &total_memory, &len, NULL, 0);

		memory->total_bytes = total_memory;
		memory->free_bytes = (uint64_t)vm_stats.free_count * (uint64_t)page_size;

		// Get swap information
		xsw_usage swap_usage;
		size_t swap_size = sizeof(swap_usage);
		if (sysctlbyname("vm.swapusage", &swap_usage, &swap_size, NULL, 0) == 0)
		{
			memory->totalSwap_bytes = swap_usage.xsu_total;
			memory->freeSwap_bytes = swap_usage.xsu_avail;
		}
#endif

		return memory;
	}

	inline std::list<Process> processes()
	{
		const auto pidList = os::pids();

		std::list<Process> result;
		for (pid_t pid : pidList)
		{
			auto processPtr = os::process(pid);

			// Ignore any processes that disappear between enumeration and now.
			if (processPtr != nullptr)
			{
				result.push_back(*(processPtr.get()));
			}
		}
		return result;
	}

	inline std::shared_ptr<Process> process(
		pid_t pid,
		const std::list<Process> &processes)
	{
		const auto iter = std::find_if(processes.begin(), processes.end(), [&pid](const Process &p)
									   { return p.pid == pid; });
		if (iter != processes.end())
			return std::make_shared<Process>(*iter);
		return nullptr;
	}

	//************************CPU****************************************
	// Representation of a processor (cross-platform)
	struct CPU
	{
		CPU(unsigned int _id, unsigned int _core, unsigned int _socket)
			: id(_id), core(_core), socket(_socket) {}

		// These are non-const because we need the default assignment operator.
		unsigned int id;	 // "processor"
		unsigned int core;	 // "core id"
		unsigned int socket; // "physical id"
	};

	inline std::ostream &operator<<(std::ostream &stream, const CPU &cpu)
	{
		return stream << "CPU [id <" << cpu.id << "> "
					  << "core <" << cpu.core << "> "
					  << "socket <" << cpu.socket << ">]";
	}

	/**
	 * @brief Get information about all CPUs in the system.
	 *
	 * Cross-platform CPU information retrieval.
	 * Thread-safe implementation using double-checked locking pattern.
	 *
	 * @return List of CPU objects containing processor ID, core ID and socket ID.
	 */
	inline std::list<CPU> cpus()
	{
		const static char fname[] = "proc::cpus() ";

		// Use double-checked locking pattern for thread-safe lazy initialization
		static std::atomic<bool> initialized(false);
		static std::mutex mutex;
		static std::list<CPU> results;

		// First check without locking
		if (!initialized.load(std::memory_order_acquire))
		{
			std::lock_guard<std::mutex> lock(mutex);
			// Second check after acquiring lock
			if (!initialized.load(std::memory_order_relaxed))
			{
#if defined(_WIN32)
				SYSTEM_INFO sysInfo;
				GetSystemInfo(&sysInfo);

				// Get logical processor information
				DWORD bufferSize = 0;
				GetLogicalProcessorInformation(NULL, &bufferSize);

				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					std::vector<SYSTEM_LOGICAL_PROCESSOR_INFORMATION> buffer(bufferSize / sizeof(SYSTEM_LOGICAL_PROCESSOR_INFORMATION));

					if (GetLogicalProcessorInformation(&buffer[0], &bufferSize))
					{
						unsigned int processorId = 0;
						for (const auto &info : buffer)
						{
							if (info.Relationship == RelationProcessorCore)
							{
								// Count set bits to determine number of logical processors per core
								DWORD_PTR mask = info.ProcessorMask;
								while (mask)
								{
									if (mask & 1)
									{
										results.push_back(CPU(processorId, processorId, 0)); // Simplified mapping
									}
									mask >>= 1;
									processorId++;
								}
							}
						}
					}
				}

				// Fallback: use simple numbering based on system info
				if (results.empty())
				{
					for (DWORD i = 0; i < sysInfo.dwNumberOfProcessors; ++i)
					{
						results.push_back(CPU(i, i, 0));
					}
				}

#elif defined(__linux__)
				std::ifstream file("/proc/cpuinfo");
				if (!file.is_open())
				{
					LOG_ERR << fname << "Failed to open /proc/cpuinfo";
					initialized.store(true, std::memory_order_release);
					return results;
				}

				// Map to store CPU information: id -> {core_id, socket_id}
				std::map<int, std::pair<int, int>> cpuInfo;
				int currentId = -1;

				std::string line;
				while (std::getline(file, line))
				{
					// Parse key-value pairs from /proc/cpuinfo
					size_t pos = line.find(':');
					if (pos == std::string::npos)
					{
						continue;
					}

					std::string key = Utility::stdStringTrim(line.substr(0, pos));
					std::string value = Utility::stdStringTrim(line.substr(pos + 1));

					// Process CPU information fields
					if (key == "processor")
					{
						try
						{
							currentId = std::stoi(value);
							cpuInfo[currentId] = std::make_pair(-1, -1); // Initialize with invalid IDs
						}
						catch (...)
						{
							currentId = -1; // Reset on parsing error
						}
					}
					else if (currentId >= 0)
					{
						try
						{
							if (key == "core id")
							{
								cpuInfo[currentId].first = std::stoi(value);
							}
							else if (key == "physical id")
							{
								cpuInfo[currentId].second = std::stoi(value);
							}
						}
						catch (...)
						{
							// Ignore parsing errors for individual fields
						}
					}
				}

				// Build CPU list from collected information
				for (const auto &it : cpuInfo)
				{
					results.push_back(CPU(
						it.first,
						it.second.first >= 0 ? it.second.first : 0,	 // Default core ID to 0 if not found
						it.second.second >= 0 ? it.second.second : 0 // Default socket ID to 0 if not found
						));
				}

#elif defined(__APPLE__)
				// Query CPU information using sysctl on macOS
				int num_cores = 0, num_threads = 0;
				size_t len = sizeof(int);

				// Get physical core count
				if (sysctlbyname("hw.physicalcpu", &num_cores, &len, NULL, 0) != 0)
				{
					LOG_ERR << fname << "Failed to query physical CPU count";
					initialized.store(true, std::memory_order_release);
					return results;
				}

				// Get logical thread count
				if (sysctlbyname("hw.logicalcpu", &num_threads, &len, NULL, 0) != 0)
				{
					LOG_ERR << fname << "Failed to query logical CPU count";
					initialized.store(true, std::memory_order_release);
					return results;
				}

				// Create CPU entries mapping logical threads to physical cores
				for (int i = 0; i < num_threads; ++i)
				{
					results.push_back(CPU(i, i % num_cores, i / num_cores));
				}
#endif
				initialized.store(true, std::memory_order_release);
			}
		}

		return results;
	}
	//************************CPU****************************************

	// Structure returned by loadavg(). Encodes system load average
	// for the last 1, 5 and 15 minutes.
	struct Load
	{
		double one;
		double five;
		double fifteen;
	};

	/**
	 * @brief Get system load averages for the last 1, 5, and 15 minutes.
	 *
	 * Cross-platform load average implementation.
	 * Note: Windows doesn't have a direct equivalent to Unix load average,
	 * so we approximate using CPU usage.
	 *
	 * @return Shared pointer to Load struct with the average loads for the last 1, 5, and 15 minutes.
	 */
	inline std::shared_ptr<Load> loadavg()
	{
		const static char fname[] = "loadavg() ";

#if defined(_WIN32)
		// Windows doesn't have load average, approximate with CPU usage
		// This is a simplified implementation - a real implementation would
		// need to maintain historical CPU usage data
		auto load = std::make_shared<Load>();

		// Query CPU usage (simplified approximation)
		FILETIME idleTime, kernelTime, userTime;
		if (GetSystemTimes(&idleTime, &kernelTime, &userTime))
		{
			// This is a very basic approximation - ideally you'd track over time
			// For now, just return a reasonable default
			load->one = 0.0;
			load->five = 0.0;
			load->fifteen = 0.0;
		}
		else
		{
			LOG_ERR << fname << "Failed to get system times";
			return nullptr;
		}

		return load;

#else
		double loadArray[3];
		if (getloadavg(loadArray, 3) == -1)
		{
			LOG_ERR << fname << "Failed to determine system load averages";
			return nullptr;
		}

		auto load = std::make_shared<Load>();
		load->one = loadArray[0];
		load->five = loadArray[1];
		load->fifteen = loadArray[2];
		return load;
#endif
	}

	struct FilesystemUsage
	{
		uint64_t totalSize = 0;		  // Total size in bytes
		uint64_t usedSize = 0;		  // Used size in bytes
		double usagePercentage = 0.0; // Usage as a percentage (0.0 to 1.0)
	};

	/**
	 * @brief Get filesystem usage statistics.
	 *
	 * Cross-platform disk usage information.
	 *
	 * @param path Directory path (default is "/" on Unix, "C:\\" on Windows).
	 * @return Shared pointer to FilesystemUsage containing size, used space, and usage.
	 */
	inline std::shared_ptr<FilesystemUsage> df(const std::string &path =
#if defined(_WIN32)
												   "C:\\"
#else
												   "/"
#endif
	)
	{
		const static char fname[] = "proc::df() ";
		auto df = std::make_shared<FilesystemUsage>();

#if defined(_WIN32)
		ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;

		if (GetDiskFreeSpaceExA(path.c_str(), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes))
		{
			df->totalSize = totalNumberOfBytes.QuadPart;
			df->usedSize = totalNumberOfBytes.QuadPart - totalNumberOfFreeBytes.QuadPart;
			if (totalNumberOfBytes.QuadPart > 0)
			{
				df->usagePercentage = static_cast<double>(df->usedSize) / df->totalSize;
			}
		}
		else
		{
			LOG_ERR << fname << "Failed to get disk space for path: " << path
					<< " Error: " << GetLastError();
			return nullptr;
		}

#elif defined(__linux__)
		struct statvfs buf;
		if (::statvfs(path.c_str(), &buf) != 0)
		{
			LOG_ERR << fname << "Failed to call statvfs for path: " << path << " Error: " << last_error_msg();
			return nullptr;
		}

		if (buf.f_blocks <= 0)
		{
			LOG_ERR << fname << "Invalid block count (f_blocks) returned by statvfs for path: " << path;
			return nullptr;
		}

		df->totalSize = static_cast<uint64_t>(buf.f_frsize) * buf.f_blocks;
		df->usedSize = static_cast<uint64_t>(buf.f_frsize) * (buf.f_blocks - buf.f_bfree);
		df->usagePercentage = static_cast<double>(buf.f_blocks - buf.f_bfree) / buf.f_blocks;

#elif defined(__APPLE__)
		struct statfs buf;
		if (::statfs(path.c_str(), &buf) != 0)
		{
			LOG_ERR << fname << "Failed to call statfs for path: " << path << " Error: " << last_error_msg();
			return nullptr;
		}

		if (buf.f_blocks <= 0)
		{
			LOG_ERR << fname << "Invalid block count (f_blocks) returned by statfs for path: " << path;
			return nullptr;
		}

		df->totalSize = static_cast<uint64_t>(buf.f_bsize) * buf.f_blocks;
		df->usedSize = static_cast<uint64_t>(buf.f_bsize) * (buf.f_blocks - buf.f_bfree);
		df->usagePercentage = static_cast<double>(buf.f_blocks - buf.f_bfree) / buf.f_blocks;
#endif

		return df;
	}

	/**
	 * @brief Get mount points and their devices.
	 *
	 * Cross-platform mount point enumeration.
	 *
	 * @return Map of mount points and devices.
	 */
	inline std::map<std::string, std::string> getMountPoints()
	{
		const static char fname[] = "proc::getMountPoints() ";
		std::map<std::string, std::string> mountPointsMap;

#if defined(_WIN32)
		// Windows: Get logical drives
		DWORD drives = GetLogicalDrives();
		char driveLetter = 'A';

		for (int i = 0; i < 26; i++)
		{
			if (drives & (1 << i))
			{
				std::string drivePath = std::string(1, driveLetter + i) + ":\\";
				UINT driveType = GetDriveTypeA(drivePath.c_str());

				// Only include fixed drives (hard disks)
				if (driveType == DRIVE_FIXED)
				{
					char volumeName[MAX_PATH + 1] = {0};
					if (GetVolumeInformationA(drivePath.c_str(), volumeName, MAX_PATH,
											  NULL, NULL, NULL, NULL, 0))
					{
						std::string deviceName = volumeName[0] ? volumeName : drivePath;
						mountPointsMap[drivePath] = deviceName;
					}
					else
					{
						mountPointsMap[drivePath] = drivePath; // Use drive path as device name
					}
				}
			}
		}

#elif defined(__linux__)
		// Linux implementation with RAII
		MountTableRAII mountsFile("/proc/mounts", "r");
		if (!mountsFile.valid())
		{
			// Fallback to /etc/mtab
			MountTableRAII fallbackFile("/etc/mtab", "r");
			if (!fallbackFile.valid())
			{
				LOG_ERR << fname << "Failed to open both /proc/mounts and /etc/mtab: " << last_error_msg();
				return mountPointsMap;
			}
			LOG_WAR << fname << "Using fallback /etc/mtab";
			mountsFile = std::move(fallbackFile);
		}

		struct mntent *currentMountEntry;
		struct mntent tempMountEntry;
		char entryBuffer[4096];

		// Enhanced ignore list for Linux
		std::set<std::string> ignoredFileSystems = {
			"tmpfs", "romfs", "ramfs", "devtmpfs", "overlay", "squashfs",
			"sysfs", "proc", "devpts", "securityfs", "cgroup", "cgroup2",
			"pstore", "debugfs", "hugetlbfs", "mqueue", "fusectl",
			"configfs", "fuse", "binfmt_misc"};

		while ((currentMountEntry = getmntent_r(mountsFile.get(), &tempMountEntry, entryBuffer, sizeof(entryBuffer))) != nullptr)
		{
			const char *devicePath = currentMountEntry->mnt_fsname;
			const char *mountDir = currentMountEntry->mnt_dir;
			const char *fileSystemType = currentMountEntry->mnt_type;

			if (!devicePath || !mountDir || !fileSystemType)
			{
				LOG_WAR << fname << "Skipped an invalid mount entry";
				continue;
			}

			// Skip if filesystem type is in ignore list or device path doesn't start with '/'
			if (ignoredFileSystems.count(fileSystemType) > 0 || devicePath[0] != '/')
			{
				LOG_DBG << fname << "Skipping " << (devicePath[0] != '/' ? "non-device" : "ignored")
						<< " filesystem: " << fileSystemType << " at " << mountDir;
				continue;
			}

			struct statvfs fileSystemStats;
			if (::statvfs(mountDir, &fileSystemStats) != 0)
			{
				LOG_WAR << fname << "Failed to get filesystem stats for " << mountDir << ": " << last_error_msg();
				continue;
			}

			// Skip filesystems with no blocks (pseudo filesystems)
			if (fileSystemStats.f_blocks <= 0)
			{
				LOG_WAR << fname << "Skipping mount point with no blocks: " << mountDir;
				continue;
			}

			// Skip bind mounts by checking mountflags
			if (strstr(currentMountEntry->mnt_opts, "bind"))
			{
				LOG_DBG << fname << "Skipping bind mount: " << mountDir;
				continue;
			}

			LOG_DBG << fname << "device: " << devicePath << " mountDir: " << mountDir << " fileSystemType: " << fileSystemType;
			mountPointsMap[mountDir] = devicePath;
		}

#elif defined(__APPLE__)
		// macOS implementation
		struct statfs *mountEntries;
		int totalMounts = getmntinfo(&mountEntries, MNT_NOWAIT);
		if (totalMounts <= 0)
		{
			LOG_ERR << fname << "Failed to retrieve mount points using getmntinfo: " << last_error_msg();
			return mountPointsMap;
		}

		// Enhanced ignore list for macOS
		std::set<std::string> ignoredFileSystems = {
			"autofs", "devfs", "volfs", "tmpfs", "vmware_fusion",
			"com.apple.TimeMachine", "synthetics", "com.apple.filesystems.apfs.serviceroot",
			"com.apple.os.update-", "com.apple.system.clock",
			"com.apple.system.background-task", "com.apple.system.ql-cache"};

		for (int i = 0; i < totalMounts; ++i)
		{
			std::string devicePath = mountEntries[i].f_mntfromname;
			std::string mountDir = mountEntries[i].f_mntonname;
			std::string mountFsType = mountEntries[i].f_fstypename;

			// Skip if filesystem type is in ignore list
			if (ignoredFileSystems.find(mountFsType) != ignoredFileSystems.end())
			{
				LOG_DBG << fname << "Skipping ignored filesystem type: " << mountFsType;
				continue;
			}

			// Check if it's a valid device path and has available space
			if (!devicePath.empty() && devicePath[0] == '/')
			{
				struct statfs fileSystemStats;
				if (statfs(mountDir.c_str(), &fileSystemStats) != 0)
				{
					LOG_WAR << fname << "Failed to get filesystem stats for " << mountDir << ": " << last_error_msg();
					continue;
				}

				if (fileSystemStats.f_blocks <= 0)
				{
					LOG_WAR << fname << "Skipping mount point with no blocks: " << mountDir;
					continue;
				}

				// Skip read-only filesystems
				if (fileSystemStats.f_flags & MNT_RDONLY)
				{
					LOG_DBG << fname << "Skipping read-only filesystem: " << mountDir;
					continue;
				}

				LOG_DBG << fname << "device: " << devicePath << " mountDir: " << mountDir << " mountFsType: " << mountFsType;
				mountPointsMap[mountDir] = devicePath;
			}
			else
			{
				LOG_DBG << fname << "Skipping invalid device path: " << devicePath;
			}
		}
#endif

		return mountPointsMap;
	}

	/**
	 * @brief Get file mode, user ID, and group ID.
	 * Cross-platform file stat information.
	 *
	 * @param path File path.
	 * @return Tuple containing file mode (permissions), user ID, and group ID. Returns (-1, -1, -1) on failure.
	 */
	inline std::tuple<int, int, int> fileStat(const std::string &path)
	{
		const static char fname[] = "fileStat() ";

#if defined(_WIN32)
		// Windows implementation
		return std::make_tuple(-1, -1, -1);

#else
		// Unix implementation
		struct stat fileStat{};
		if (::stat(path.c_str(), &fileStat) == 0)
		{
			// Extract permission bits using bitwise AND
			int permissionBits = fileStat.st_mode & 0777;
			return std::make_tuple(permissionBits, fileStat.st_uid, fileStat.st_gid);
		}
		else
		{
			LOG_WAR << fname << "Failed stat <" << path << "> with error: " << last_error_msg();
			return std::make_tuple(-1, -1, -1);
		}
#endif
	}

	/**
	 * @brief Change file permissions using a numeric mode value.
	 * Cross-platform file permission modification.
	 *
	 * @param path File path.
	 * @param mode Permissions mode in octal (e.g., 0755).
	 * @return True if successful, false otherwise.
	 */
	inline bool fileChmod(const std::string &path, uint16_t mode)
	{
		const static char fname[] = "fileChmod() ";

		// Validate mode value
		constexpr uint16_t MAX_FILE_MODE = 0777;
		if (mode > MAX_FILE_MODE)
		{
			LOG_WAR << fname << "Invalid mode value <" << mode << "> for chmod <" << path << ">";
			return false;
		}

#if defined(_WIN32)
		// Windows implementation
		return false;

#else
		// Unix implementation
		if (::chmod(path.c_str(), mode) == 0)
		{
			return true;
		}
		else
		{
			LOG_WAR << fname << "Failed chmod <" << path << "> with error: " << last_error_msg();
			return false;
		}
#endif
	}

	/**
	 * @brief Change file permissions using a numeric shorthand value (e.g., 755).
	 * Cross-platform permission modification with shorthand notation.
	 *
	 * @param path File path.
	 * @param mode Shorthand permissions mode (e.g., 755).
	 * @return True if successful, false otherwise.
	 */
	inline bool chmod(const std::string &path, uint16_t mode)
	{
		const static char fname[] = "chmod() ";

		// Validate shorthand mode
		if (mode > 777)
		{
			LOG_WAR << fname << "Invalid shorthand mode value <" << mode << "> for chmod <" << path << ">";
			return false;
		}

		if (mode == 0)
		{
			LOG_WAR << fname << "Warning: mode 0 will remove all permissions for path <" << path << ">";
		}

		// Convert shorthand mode (e.g., 755) to octal mode (e.g., 0755)
		uint16_t mode_u = mode / 100;
		uint16_t mode_g = (mode / 10) % 10;
		uint16_t mode_o = mode % 10;
		uint16_t octalMode = (mode_u << 6) | (mode_g << 3) | mode_o;

		return fileChmod(path, octalMode);
	}

	// SID to UID conversion for Windows simulation
	inline unsigned int hashSidToUid(const std::string &sidString)
	{
		// Use FNV-1a hash for better distribution
		constexpr uint32_t FNV_OFFSET_BASIS = 2166136261U;
		constexpr uint32_t FNV_PRIME = 16777619U;

		uint32_t hash = FNV_OFFSET_BASIS;
		for (char c : sidString)
		{
			hash ^= static_cast<uint32_t>(c);
			hash *= FNV_PRIME;
		}

		// Ensure positive value and reasonable range
		return (hash & 0x7FFFFFFF) % 1000000 + 1000; // Range: 1000-1000999
	}

	inline bool getUidByName(const std::string &userName, unsigned int &uid, unsigned int &groupid)
	{
		const static char fname[] = "os::getUidByName() ";

		if (userName.empty())
		{
			LOG_ERR << fname << "Empty username provided";
			return false;
		}

#if defined(_WIN32)
		// Windows implementation
		PSID userSid = nullptr;
		DWORD sidSize = 0;
		DWORD domainSize = 0;
		SID_NAME_USE sidType;

		// First call to get required buffer sizes
		if (!LookupAccountNameA(nullptr, userName.c_str(), nullptr, &sidSize, nullptr, &domainSize, &sidType))
		{
			DWORD error = GetLastError();
			if (error != ERROR_INSUFFICIENT_BUFFER)
			{
				LOG_ERR << fname << "User does not exist: " << userName << " Error: " << error;
				return false;
			}
		}

		// Allocate buffers
		std::vector<BYTE> sidBuffer(sidSize);
		std::vector<char> domainBuffer(domainSize);
		userSid = reinterpret_cast<PSID>(sidBuffer.data());

		// Get the actual SID
		if (!LookupAccountNameA(nullptr, userName.c_str(), userSid, &sidSize, domainBuffer.data(), &domainSize, &sidType))
		{
			LOG_ERR << fname << "Failed to lookup account: " << userName << " Error: " << GetLastError();
			return false;
		}

		// Convert SID to string
		LPSTR sidString = nullptr;
		if (!ConvertSidToStringSidA(userSid, &sidString))
		{
			LOG_ERR << fname << "Failed to convert SID to string for user: " << userName;
			return false;
		}

		// RAII for SID string
		std::unique_ptr<void, decltype(&LocalFree)> sidStringPtr(sidString, LocalFree);

		// Generate consistent UID from SID
		uid = hashSidToUid(std::string(sidString));

		groupid = 1000; // Default group ID for Windows users

		LOG_DBG << fname << "Windows user " << userName << " mapped to UID: " << uid << " GID: " << groupid;
		return true;

#else
		// Unix/Linux implementation
		struct passwd pwd;
		struct passwd *result = nullptr;
		static auto bufsize = ACE_OS::sysconf(_SC_GETPW_R_SIZE_MAX);
		if (bufsize == -1)
			bufsize = 16384;
		std::shared_ptr<char> buff(new char[bufsize], std::default_delete<char[]>());
		ACE_OS::getpwnam_r(userName.c_str(), &pwd, buff.get(), bufsize, &result);
		if (result)
		{
			uid = pwd.pw_uid;
			groupid = pwd.pw_gid;
			return true;
		}

		LOG_ERR << fname << "User does not exist: " << userName;
		return false;
#endif
	}

	// Get uid for Windows and Linux
	inline uid_t get_uid()
	{
#if defined(_WIN32)
		HandleRAII hToken;
		HANDLE tempToken = nullptr;

		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tempToken))
		{
			return static_cast<uid_t>(-1);
		}
		hToken.reset(tempToken);

		DWORD size = 0;
		if (!GetTokenInformation(hToken.get(), TokenUser, nullptr, 0, &size))
		{
			if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
			{
				return static_cast<uid_t>(-1);
			}
		}

		std::vector<BYTE> buffer(size);
		TOKEN_USER *user = reinterpret_cast<TOKEN_USER *>(buffer.data());
		if (!GetTokenInformation(hToken.get(), TokenUser, user, size, &size))
		{
			return static_cast<uid_t>(-1);
		}

		LPSTR sidString = nullptr;
		if (!ConvertSidToStringSidA(user->User.Sid, &sidString))
		{
			return static_cast<uid_t>(-1);
		}

		// RAII for SID string
		std::unique_ptr<void, decltype(&LocalFree)> sidStringPtr(sidString, LocalFree);

		return hashSidToUid(std::string(sidString));

#else
		return ACE_OS::getuid();
#endif
	}

	inline std::string getUsernameByUid(uid_t uid = get_uid())
	{
		const static char fname[] = "os::getUsernameByUid() ";

		if (uid == static_cast<uid_t>(-1))
		{
			LOG_WAR << fname << "Invalid UID provided";
			return "";
		}

#if defined(_WIN32)
		// Windows implementation
		// Note: This is a simplified approach since Windows doesn't have direct UID->username mapping
		// In a production system, you might want to maintain a cache/registry of UID mappings

		// For current user, get username directly
		uid_t currentUid = get_uid();
		if (uid == currentUid)
		{
			DWORD bufferSize = UNLEN + 1;
			std::vector<char> username(bufferSize);

			if (GetUserNameA(username.data(), &bufferSize))
			{
				std::string result(username.data());

				// Verify and cache the mapping
				unsigned int verifyUid, verifyGid;
				if (getUidByName(result, verifyUid, verifyGid) && verifyUid == uid)
				{
					return result;
				}
			}
		}

		// For other users, we'd need a more complex lookup mechanism
		// This could involve enumerating all users or maintaining a mapping cache
		LOG_WAR << fname << "Cannot resolve UID " << uid << " on Windows (not current user)";

		// Alternative: Try to enumerate local users (requires additional Windows API calls)
		// This is more complex and would require NetUserEnum or similar functions

		return "";

#else
		// Unix/Linux implementation
		long bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
		if (bufsize == -1)
			bufsize = 16384;

		std::vector<char> buffer(bufsize);
		struct passwd pwd;
		struct passwd *result = nullptr;

		int ret = getpwuid_r(uid, &pwd, buffer.data(), buffer.size(), &result);

		if (ret == 0 && result != nullptr)
		{
			LOG_DBG << fname << "User name for " << uid << " is " << pwd.pw_name;
			return std::string(pwd.pw_name);
		}

		LOG_WAR << fname << "User not found for UID: " << uid;
		return "";
#endif
	}

} // namespace os
