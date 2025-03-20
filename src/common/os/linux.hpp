#pragma once

// This file contains Unix (Linux/macOS) OS utilities.
#if !defined(__linux__) && !defined(__APPLE__)
#error "only available on Unix-like systems (Linux/macOS)."
#endif

// Common headers
#include <dirent.h>		 // Directory operations
#include <errno.h>		 // Error codes
#include <stdlib.h>		 // General utilities
#include <sys/stat.h>	 // File status and permissions
#include <sys/statvfs.h> // File system information

#include <sys/types.h> // For pid_t
#include <unistd.h>	   // For sysconf

// Linux-specific headers
#if defined(__linux__)
#include <linux/version.h> // Linux kernel version
#include <mntent.h>		   // Mount table entries
#include <sys/sysinfo.h>   // System information
#endif

// macOS-specific headers
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

#include <assert.h>
#include <atomic>
#include <fstream>
#include <list>
#include <memory>
#include <pwd.h>
#include <set>
#include <string>

#include "../../common/Utility.h"
#include "process.hpp"

namespace os
{

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

		// Open the directory with RAII-style resource management.
		std::unique_ptr<DIR, void (*)(DIR *)> dir(opendir(directory.c_str()),
												  [](DIR *d)
												  { if (d) closedir(d); });
		if (!dir)
		{
			LOG_WAR << fname << "Failed to open directory: " << directory
					<< " (errno=" << errno << ": " << std::strerror(errno) << ")";
			return {};
		}

		std::vector<std::string> result;
		struct dirent *entry;

		// Clear errno before calling readdir
		errno = 0;

		while ((entry = readdir(dir.get())) != nullptr)
		{
			const std::string name = entry->d_name;
			if (name == "." || name == "..")
			{
				continue;
			}
			result.push_back(std::move(name));
		}

		// Check for `readdir` errors.
		if (errno != 0)
		{
			LOG_WAR << fname << "Failed to read directory: " << directory
					<< " (errno=" << errno << ": " << std::strerror(errno) << ")";
			return {};
		}

		// `closedir` is automatically called by `std::unique_ptr` when it goes out of scope.
		return result;
	}

	// Snapshot of a process (modeled after /proc/[pid]/stat).
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
		std::chrono::system_clock::time_point get_starttime()
		{
#ifdef __linux__
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
			time_t system_boot_time = time(nullptr) - static_cast<time_t>(uptime_seconds);
			// Calculate start time since system boot in seconds + boot time
			double start_time_seconds = system_boot_time + (starttime / ticks_per_second);

			// Convert start time
			return std::chrono::system_clock::from_time_t(static_cast<time_t>(start_time_seconds));
#elif defined(__APPLE__)
			// struct timeval tv;
			// size_t len = sizeof(tv);
			// int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, pid};
			// if (sysctl(mib, 4, &tv, &len, nullptr, 0) == 0)
			//{
			//	return std::chrono::system_clock::from_time_t(tv.tv_sec);
			// }
			return std::chrono::system_clock::from_time_t(starttime);
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
	 * On Linux, retrieves the total CPU time (in clock ticks) from `/proc/stat`, which includes time spent
	 * in user, system, idle, and other states. On macOS, uses `host_statistics` to fetch CPU load information.
	 * The returned value is the sum of CPU times across various states (user, system, idle, etc.).
	 *
	 * @return Total system CPU time in clock ticks, or 0 on error.
	 */
	inline int64_t cpuTotalTime()
	{
#ifdef __linux__
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
	 * Retrieves the process statistics from `/proc/[pid]/stat` (Linux) or an equivalent source on macOS.
	 * Returns a shared pointer to a `ProcessStatus` object, or `nullptr` if the process does not exist or an error occurs.
	 *
	 * @param pid Process ID.
	 * @return A shared pointer to a `ProcessStatus` object, or `nullptr` if the process does not exist or an error occurs.
	 */
	inline std::shared_ptr<ProcessStatus> status(pid_t pid)
	{
		const static char fname[] = "proc::status() ";

		if (pid <= 0)
		{
			// LOG_DBG << fname << "Invalid PID: " << pid;
			return nullptr;
		}

#ifdef __linux__
		// Construct the /proc/[pid]/stat path
		const std::string path = "/proc/" + std::to_string(pid) + "/stat";

		// Read the contents of the file
		std::string content = Utility::readFile(path);
		if (content.empty())
		{
			LOG_DBG << fname << "Process does not exist or file is empty: " << path;
			return nullptr;
		}

		std::istringstream data(content);

		// Define variables to parse /proc/[pid]/stat fields
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

		// NOTE: The following are unused for now.
		// int exit_signal;
		// int processor;
		// unsigned int rt_priority;
		// unsigned int policy;
		// unsigned long long delayacct_blkio_ticks;
		// unsigned long guest_time;
		// unsigned int cguest_time;

		std::string _; // For ignoring fields.

		// Parse all fields from stat.
		data >> _ >> comm >> state >> ppid >> pgrp >> session >> tty_nr >> tpgid >> flags >> minflt >> cminflt >> majflt >> cmajflt >> utime >> stime >> cutime >> cstime >> priority >> nice >> num_threads >> itrealvalue >> starttime >> vsize >> rss >> rsslim >> startcode >> endcode >> startstack >> kstkeip >> signal >> blocked >> sigcatch >> wchan >> nswap >> cnswap;

		// Check for parsing errors
		if (data.fail())
		{
			LOG_WAR << fname << "Failed to parse content for PID: " << pid << " at " << path;
			return nullptr;
		}

		// Validate the length of the command string
		if (comm.size() > MAX_COMMAND_LINE_LENGTH)
		{
			LOG_WAR << fname << "Command length invalid for PID: " << pid;
			return nullptr;
		}

		// Clean up parentheses around the command name
		comm = Utility::stdStringTrim(comm, '(', true, false);
		comm = Utility::stdStringTrim(comm, ')', false, true);

		return std::make_shared<ProcessStatus>(
			pid, comm, state, ppid, pgrp, session, utime, stime, cutime, cstime, starttime, vsize, rss);

#elif defined(__APPLE__)
		struct proc_taskinfo task_info;
		struct proc_bsdinfo bsd_info;
		// struct rusage_info_v2 rusage;

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

		// Get resource usage information
		// if (proc_pid_rusage(pid, RUSAGE_INFO_V2, reinterpret_cast<rusage_info_t *>(&rusage)) != 0)
		//{
		//	LOG_DBG << fname << "Failed to fetch resource usage for PID: " << pid;
		//	return nullptr;
		//}

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

		// Convert time values from nanoseconds to clock ticks
		// static const long ticks_per_second = sysconf(_SC_CLK_TCK);
		// unsigned long utime = (rusage.ri_user_time / (1000000000 / ticks_per_second));
		// unsigned long stime = (rusage.ri_system_time / (1000000000 / ticks_per_second));

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
#else
		LOG_WAR << fname << "Platform not supported for PID: " << pid;
		return nullptr;
#endif
	}

	/**
	 * @brief Get the command line of a process.
	 *
	 * Retrieves the command line arguments of a process specified by its PID. If no PID is provided,
	 * it defaults to the current process.
	 *
	 * @param pid Process ID (default is 0, which represents the current process).
	 * @return A string containing the command line of the specified process.
	 */
	inline std::string cmdline(const pid_t &pid = 0)
	{
		const static char fname[] = "proc::cmdline() ";
#if defined(__linux__)
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
				LOG_WAR << fname << "Failed to open <" << path << "> with error: " << std::strerror(errno);
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
		if (pid == 0)
		{
			LOG_DBG << fname << "No PID specified, returning empty cmdline.";
			return "";
		}

		char pathbuf[PROC_PIDPATHINFO_MAXSIZE];

		// Get the process path
		if (proc_pidpath(pid, pathbuf, sizeof(pathbuf)) <= 0)
		{
			LOG_WAR << fname << "Failed to retrieve path for PID=" << pid << " with error: " << std::strerror(errno);
			return "";
		}

		std::string result = pathbuf;

		// Retrieve process arguments
		// TODO: use open-source solution: libproc or psutil

		return result;

#else
		LOG_DBG << fname << "Unsupported platform, returning empty cmdline.";
		return "";
#endif
	}

	/**
	 * @brief Get a list of all running process IDs.
	 *
	 * Retrieves the process IDs (PIDs) of all currently running processes.
	 *
	 * @return A set containing the PIDs of all running processes.
	 */
	inline std::set<pid_t> pids()
	{
		const static char fname[] = "proc::pids() ";
		std::set<pid_t> pids;

#if defined(__linux__)
		// List entries in /proc directory
		auto entries = os::ls("/proc");
		if (entries.empty())
		{
			LOG_ERR << fname << "Failed to list files in /proc. Error: " << std::strerror(errno);
			return pids; // Return an empty set on failure
		}

		// Filter numeric entries (representing PIDs)
		for (const std::string &entry : entries)
		{
			if (Utility::isNumber(entry))
			{
				try
				{
					pids.insert(std::stoi(entry)); // Convert to integer and add to set
				}
				catch (const std::exception &e)
				{
					LOG_ERR << fname << "Failed to convert entry '" << entry << "' to PID. Error: " << e.what();
				}
			}
		}

		if (pids.empty())
		{
			LOG_ERR << fname << "No PIDs found in /proc. This might indicate an unusual system state.";
		}

#elif defined(__APPLE__)
		int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
		size_t size;

		// Get size of process list
		if (sysctl(mib, 4, NULL, &size, NULL, 0) < 0)
		{
			LOG_ERR << fname << "Failed to query process list size with error: " << std::strerror(errno);
			return pids;
		}

		// Allocate memory for process list
		auto proc_list = static_cast<struct kinfo_proc *>(malloc(size));
		if (!proc_list)
		{
			LOG_ERR << fname << "Memory allocation failed for process list.";
			return pids;
		}

		// Retrieve process list
		if (sysctl(mib, 4, proc_list, &size, NULL, 0) < 0)
		{
			LOG_ERR << fname << "Failed to retrieve process list with error: " << std::strerror(errno);
			free(proc_list);
			return pids;
		}

		size_t nprocs = size / sizeof(struct kinfo_proc);

		// Extract PIDs from process list
		for (size_t i = 0; i < nprocs; i++)
		{
			pids.insert(proc_list[i].kp_proc.p_pid);
		}

		free(proc_list); // Free allocated memory
#endif

		return pids;
	}

	// Structure returned by memory() containing the total size of main
	// and free memory.
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

	// The alternative `getpagesize()` is not defined by POSIX.
	inline size_t pagesize()
	{
		// We assume that `sysconf` will not fail in practice.
		long result = ::sysconf(_SC_PAGESIZE);
		assert(result >= 0);
		return static_cast<size_t>(result);
	}

	/**
	 * @brief Get process information for a given PID.
	 *
	 * Retrieves information about a process specified by its PID.
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
		// (i.e., the canonical executable name). To get the entire command
		// line we grab '/proc/[pid]/cmdline'.
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

#if defined(__linux__)
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
		const std::set<pid_t> pidList = os::pids();

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
	// Representation of a processor (really an execution unit since this
	// captures "hardware threads" as well) modeled after /proc/cpuinfo.
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
	 * This function reads CPU information from /proc/cpuinfo on Linux or uses sysctl on macOS.
	 * The results are cached after first call for better performance.
	 * Thread-safe implementation using double-checked locking pattern for C++11.
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
#if defined(__linux__)
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
				for (std::map<int, std::pair<int, int>>::const_iterator it = cpuInfo.begin();
					 it != cpuInfo.end(); ++it)
				{
					results.push_back(CPU(
						it->first,
						it->second.first >= 0 ? it->second.first : 0,  // Default core ID to 0 if not found
						it->second.second >= 0 ? it->second.second : 0 // Default socket ID to 0 if not found
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
	 * Returns a struct containing the system load averages, typically retrieved
	 * from the `uptime` command.
	 *
	 * @return Shared pointer to Load struct with the average loads for the last 1, 5, and 15 minutes.
	 */
	inline std::shared_ptr<Load> loadavg()
	{
		const static char fname[] = "loadavg() ";

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
	 * Returns the total size, used space, and usage percentage for the given path.
	 *
	 * @param path Directory path (default is "/").
	 * @return Shared pointer to FilesystemUsage containing size, used space, and usage.
	 */
	inline std::shared_ptr<FilesystemUsage> df(const std::string &path = "/")
	{
		const static char fname[] = "proc::df() ";
		auto df = std::make_shared<FilesystemUsage>();

#if defined(__linux__)
		struct statvfs buf;
		if (::statvfs(path.c_str(), &buf) != 0)
		{
			LOG_ERR << fname << "Failed to call statvfs for path: " << path << " Error: " << std::strerror(errno);
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
			LOG_ERR << fname << "Failed to call statfs for path: " << path << " Error: " << std::strerror(errno);
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
	 * Returns a map of mount points to devices, excluding temporary filesystems.
	 *
	 * @return Map of mount points and devices.
	 */
	inline std::map<std::string, std::string> getMountPoints()
	{
		const static char fname[] = "proc::getMountPoints() ";
		std::map<std::string, std::string> mountPointsMap;

#if defined(__linux__)
		// Try /proc/mounts first as it's more reliable than /etc/mtab
		FILE *mountsFile = setmntent("/proc/mounts", "r");
		if (!mountsFile)
		{
			// Fallback to /etc/mtab
			mountsFile = setmntent("/etc/mtab", "r");
			if (!mountsFile)
			{
				LOG_ERR << fname << "Failed to open both /proc/mounts and /etc/mtab: " << std::strerror(errno);
				return mountPointsMap;
			}
			LOG_WAR << fname << "Using fallback /etc/mtab";
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

		while ((currentMountEntry = getmntent_r(mountsFile, &tempMountEntry, entryBuffer, sizeof(entryBuffer))) != nullptr)
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
				LOG_WAR << fname << "Failed to get filesystem stats for " << mountDir << ": " << std::strerror(errno);
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

		endmntent(mountsFile);

#elif defined(__APPLE__)
		struct statfs *mountEntries;
		int totalMounts = getmntinfo(&mountEntries, MNT_NOWAIT);
		if (totalMounts <= 0)
		{
			LOG_ERR << fname << "Failed to retrieve mount points using getmntinfo: " << strerror(errno);
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
					LOG_WAR << fname << "Failed to get filesystem stats for " << mountDir << ": " << strerror(errno);
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
	 * @param path File path.
	 * @return Tuple containing file mode (permissions), user ID, and group ID. Returns (-1, -1, -1) on failure.
	 */
	inline std::tuple<int, int, int> fileStat(const std::string &path)
	{
		const static char fname[] = "fileStat() ";

		struct stat fileStat{};
		if (::stat(path.c_str(), &fileStat) == 0)
		{
			// Extract permission bits using bitwise AND
			int permissionBits = fileStat.st_mode & 0777;
			return std::make_tuple(permissionBits, fileStat.st_uid, fileStat.st_gid);
		}
		else
		{
			LOG_WAR << fname << "Failed stat <" << path << "> with error: " << std::strerror(errno);
			return std::make_tuple(-1, -1, -1);
		}
	}

	/**
	 * @brief Change file permissions using a numeric mode value.
	 * @param path File path.
	 * @param mode Permissions mode in octal (e.g., 0755).
	 * @return True if successful, false otherwise.
	 */
	inline bool fileChmod(const std::string &path, uint16_t mode)
	{
		const static char fname[] = "fileChmod() ";

		// Validate mode value
		if (mode > 0777 || mode < 0)
		{
			LOG_WAR << fname << "Invalid mode value <" << mode << "> for chmod <" << path << ">";
			return false;
		}

		if (::chmod(path.c_str(), mode) == 0)
		{
			return true;
		}
		else
		{
			LOG_WAR << fname << "Failed chmod <" << path << "> with error: " << std::strerror(errno);
			return false;
		}
	}

	/**
	 * @brief Change file permissions using a numeric shorthand value (e.g., 755).
	 * @param path File path.
	 * @param mode Shorthand permissions mode (e.g., 755).
	 * @return True if successful, false otherwise.
	 */
	inline bool chmod(const std::string &path, uint16_t mode)
	{
		const static char fname[] = "chmod() ";

		// Validate shorthand mode
		if (mode > 777 || mode < 0)
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

} // namespace os
