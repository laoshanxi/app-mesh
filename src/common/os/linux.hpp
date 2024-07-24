#pragma once

// This file contains Linux-only OS utilities.
#ifndef __linux__
#error "os/linux.hpp is only available on Linux systems."
#else
#include <dirent.h>
#include <errno.h>
#include <mntent.h>
#include <stdlib.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/types.h> // For pid_t.
#include <unistd.h>	   // For sysconf
#endif				   // __linux__

#ifdef __linux__
#include <linux/version.h>
#include <sys/sysinfo.h>
#endif // __linux__

#include <assert.h>
#include <atomic>
#include <fstream>
#include <list>
#include <memory>
#include <pwd.h>
#include <set>
#include <string>
#include <sys/stat.h>

#include "../../common//Utility.h"
#include "process.hpp"

namespace os
{

	inline std::list<std::string> ls(const std::string &directory)
	{
		const static char fname[] = "os::ls() ";

		DIR *dir = opendir(directory.c_str());

		if (dir == nullptr)
		{
			LOG_WAR << fname << "Failed to opendir:" << directory;
			return std::list<std::string>();
		}

		std::list<std::string> result;
		struct dirent *entry;

		// Zero `errno` before starting to call `readdir`. This is necessary
		// to allow us to determine when `readdir` returns an error.
		errno = 0;

		while ((entry = readdir(dir)) != nullptr)
		{
			if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			{
				continue;
			}
			result.push_back(entry->d_name);
		}

		if (errno != 0)
		{
			// Preserve `readdir` error.
			LOG_WAR << fname << "Failed to read directory:" << directory;
			closedir(dir);
			return std::list<std::string>();
		}

		if (closedir(dir) == -1)
		{
			LOG_WAR << fname << "Failed to read close:" << directory;
		}

		return result;
	}

	// Snapshot of a process (modeled after /proc/[pid]/stat).
	// For more information, see:
	// http://www.kernel.org/doc/Documentation/filesystems/proc.txt
	// https://blog.csdn.net/qq_34409701/article/details/52638631
	struct ProcessStatus
	{
		ProcessStatus(
			pid_t _pid,
			const std::string &_comm,
			char _state,
			pid_t _ppid,
			pid_t _pgrp,
			pid_t _session,
			int _tty_nr,
			pid_t _tpgid,
			unsigned int _flags,
			unsigned long _minflt,
			unsigned long _cminflt,
			unsigned long _majflt,
			unsigned long _cmajflt,
			unsigned long _utime,
			unsigned long _stime,
			long _cutime,
			long _cstime,
			long _priority,
			long _nice,
			long _num_threads,
			long _itrealvalue,
			unsigned long long _starttime,
			unsigned long _vsize,
			long _rss,
			unsigned long _rsslim,
			unsigned long _startcode,
			unsigned long _endcode,
			unsigned long _startstack,
			unsigned long _kstkeip,
			unsigned long _signal,
			unsigned long _blocked,
			unsigned long _sigcatch,
			unsigned long _wchan,
			unsigned long _nswap,
			unsigned long _cnswap)
			: pid(_pid),
			  comm(_comm),
			  state(_state),
			  ppid(_ppid),
			  pgrp(_pgrp),
			  session(_session),
			  tty_nr(_tty_nr),
			  tpgid(_tpgid),
			  flags(_flags),
			  minflt(_minflt),
			  cminflt(_cminflt),
			  majflt(_majflt),
			  cmajflt(_cmajflt),
			  utime(_utime),
			  stime(_stime),
			  cutime(_cutime),
			  cstime(_cstime),
			  priority(_priority),
			  nice(_nice),
			  num_threads(_num_threads),
			  itrealvalue(_itrealvalue),
			  starttime(_starttime),
			  vsize(_vsize),
			  rss(_rss),
			  rsslim(_rsslim),
			  startcode(_startcode),
			  endcode(_endcode),
			  startstack(_startstack),
			  kstkeip(_kstkeip),
			  signal(_signal),
			  blocked(_blocked),
			  sigcatch(_sigcatch),
			  wchan(_wchan),
			  nswap(_nswap),
			  cnswap(_cnswap) {}

		std::chrono::system_clock::time_point get_starttime()
		{
			static const long ticks_per_second = sysconf(_SC_CLK_TCK);
			// Read system uptime from /proc/uptime
			static double uptime_seconds = 0;
			static std::atomic_flag flag = ATOMIC_FLAG_INIT;
			if (!flag.test_and_set(std::memory_order_acquire))
			{
				std::ifstream uptime_file("/proc/uptime");
				if (!uptime_file)
				{
					LOG_WAR << "Error opening /proc/uptime";
					return {};
				}
				uptime_file >> uptime_seconds;
				uptime_file.close();
			}
			// Calculate system boot time in seconds
			time_t system_boot_time = time(nullptr) - static_cast<time_t>(uptime_seconds);
			// Calculate start time since system boot in seconds + boot time
			double start_time_seconds = system_boot_time + (starttime / ticks_per_second);

			// Convert start time
			return std::chrono::system_clock::from_time_t(static_cast<time_t>(start_time_seconds));
		}

		const pid_t pid;
		const std::string comm;
		const char state;
		const pid_t ppid;
		const pid_t pgrp;
		const pid_t session;
		const int tty_nr;
		const pid_t tpgid;
		const unsigned int flags;
		const unsigned long minflt;
		const unsigned long cminflt;
		const unsigned long majflt;
		const unsigned long cmajflt;
		const unsigned long utime;
		const unsigned long stime;
		const long cutime;
		const long cstime;
		const long priority;
		const long nice;
		const long num_threads;
		const long itrealvalue;
		const unsigned long long starttime;
		const unsigned long vsize;
		const long rss;
		const unsigned long rsslim;
		const unsigned long startcode;
		const unsigned long endcode;
		const unsigned long startstack;
		const unsigned long kstkeip;
		const unsigned long signal;
		const unsigned long blocked;
		const unsigned long sigcatch;
		const unsigned long wchan;
		const unsigned long nswap;
		const unsigned long cnswap;
	};

	// get system cpu statictic from /proc/stat
	inline int64_t cpuTotalTime()
	{
		std::string path = "/proc/stat";
		std::string read = Utility::readFile(path);
		if (read.length() == 0)
		{
			return 0;
		}
		unsigned long u, n, s, i, w, x, y, z; // as represented in /proc/stat

		std::string _; // For ignoring fields.
		std::istringstream data(read);
		// Parse all fields from stat.
		data >> _ >> u >> n >> s >> i >> w >> x >> y >> z;
		return u + n + s + i + w + x + y + z;
	}

	// Returns the process statistics from /proc/[pid]/stat.
	// The return value is None if the process does not exist.
	inline std::shared_ptr<ProcessStatus> status(pid_t pid)
	{
		const static char fname[] = "proc::status() ";
		if (pid <= 0)
			return nullptr;
		std::string path = "/proc/" + std::to_string(pid) + "/stat";

		std::string read = Utility::readFile(path);
		if (read.length() == 0)
		{
			return nullptr;
		}

		std::istringstream data(read);

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
		long rss;
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

		// Check for any read/parse errors.
		if (data.fail() && !data.eof())
		{
			LOG_WAR << fname << "Failed to read/parse:" << path;
			return nullptr;
		}
		if (comm.length() > MAX_COMMAND_LINE_LENGTH)
		{
			LOG_WAR << fname << "invalid length of process command";
			return nullptr;
		}
		// Remove the parentheses that is wrapped around 'comm' (when
		// printing out the process in a process tree we use parentheses to
		// indicate "zombie" processes).
		comm = Utility::stdStringTrim(comm, '(', true, false);
		comm = Utility::stdStringTrim(comm, ')', false, true);

		return std::make_shared<ProcessStatus>(pid, comm, state, ppid, pgrp, session, tty_nr,
											   tpgid, flags, minflt, cminflt, majflt, cmajflt,
											   utime, stime, cutime, cstime, priority, nice,
											   num_threads, itrealvalue, starttime, vsize, rss,
											   rsslim, startcode, endcode, startstack, kstkeip,
											   signal, blocked, sigcatch, wchan, nswap, cnswap);
	}

	inline std::string cmdline(const pid_t &pid = 0)
	{
		const static char fname[] = "proc::cmdline() ";

		const std::string path = pid > 0
									 ? "/proc/" + std::to_string(pid) + "/cmdline"
									 : "/proc/cmdline";

		std::ifstream file(path.c_str());

		if (!file.is_open())
		{
			// Need to check if file exists AFTER we open it to guarantee
			// process hasn't terminated (or if it has, we at least have a
			// file which the kernel _should_ respect until a close).
			if (!Utility::isFileExist(path))
			{
				LOG_WAR << fname << "process already exit, failed to open:" << path;
				return "";
			}
			LOG_WAR << fname << "Failed to open <" << path << "> with error: " << std::strerror(errno);
			return "";
		}

		std::stringbuf buffer;

		do
		{
			// Read each argument in "argv", separated by null bytes.
			file.get(buffer, '\0');

			// Check for any read errors.
			if (file.fail() && !file.eof())
			{
				// TODO:
				// LOG_DBG << fname << "Failed to read:" << path;
				return "";
			}
			else if (!file.eof())
			{
				file.get();		   // Read the null byte.
				buffer.sputc(' '); // Put a space between each command line argument.
			}
		} while (!file.eof());

		return buffer.str();
	}

	// Reads from /proc and returns a list of all running processes.
	inline std::set<pid_t> pids()
	{
		const static char fname[] = "proc::pids() ";

		std::set<pid_t> pids;

		std::list<std::string> entries = os::ls("/proc");
		if (entries.size() == 0)
		{
			LOG_ERR << fname << "Failed to list files in /proc with error: " << std::strerror(errno);
			return std::set<pid_t>();
		}

		for (const std::string &entry : entries)
		{
			if (Utility::isNumber(entry))
			{
				pids.insert(std::stoi(entry)); // Ignore entries that can't be numified.
			}
		}

		if (pids.empty())
		{
			LOG_ERR << fname << "Failed to determine pids from /proc" << std::strerror(errno);
		}
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
		return result;
	}

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
		Memory memory;

		struct sysinfo info;
		if (sysinfo(&info) != 0)
		{
			return nullptr;
		}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 3, 23))
		memory.total_bytes = (info.totalram * info.mem_unit);
		memory.free_bytes = (info.freeram * info.mem_unit);
		memory.totalSwap_bytes = (info.totalswap * info.mem_unit);
		memory.freeSwap_bytes = (info.freeswap * info.mem_unit);
#else
		memory.total_bytes = (info.totalram);
		memory.free_bytes = (info.freeram);
		memory.totalSwap_bytes = (info.totalswap);
		memory.freeSwap_bytes = (info.freeswap);
#endif

		return std::make_shared<Memory>(memory);
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

	// lscpu | grep -E '^Thread|^Core|^Socket|^CPU\('
	// Reads from /proc/cpuinfo and returns a list of CPUs.
	inline std::list<CPU> cpus()
	{
		const static char fname[] = "proc::cpus() ";

		static std::list<CPU> results;
		if (results.size())
			return results;

		std::ifstream file("/proc/cpuinfo");

		if (!file.is_open())
		{
			LOG_ERR << fname << "Failed to open /proc/cpuinfo";
			return results;
		}

		// Placeholders as we parse the file.
		int id = -1;
		int core = -1;
		int socket = -1;

		std::string line;
		while (std::getline(file, line))
		{
			if (line.find("processor") == 0 ||
				line.find("physical id") == 0 ||
				line.find("core id") == 0)
			{
				// Get out and parse the value.
				std::vector<std::string> tokens = Utility::splitString(line, ": ");

				if (tokens.size() < 2)
				{
					LOG_ERR << fname << "Unexpected format in /proc/cpuinfo : " << line;
					return std::list<CPU>();
				}

				if (tokens.back().length() == 0 || !Utility::isNumber(tokens.back()))
				{
					LOG_ERR << fname << "Not integer type, unexpected format in /proc/cpuinfo : " << line;
					return std::list<CPU>();
				}
				unsigned int value = std::stoi(tokens.back());

				// Now save the value.
				if (line.find("processor") == 0)
				{
					if (id >= 0)
					{
						// The physical id and core id are not present in this case.
						results.push_back(CPU(id, 0, 0));
					}
					id = value;
				}
				else if (line.find("physical id") == 0)
				{
					if (socket >= 0)
					{
						LOG_ERR << fname << "Unexpected format in /proc/cpuinfo  : " << line;
						return std::list<CPU>();
					}
					socket = value;
				}
				else if (line.find("core id") == 0)
				{
					if (core >= 0)
					{
						LOG_ERR << fname << "Unexpected format in /proc/cpuinfo  : " << line;
						return std::list<CPU>();
					}
					core = value;
				}

				// And finally create a CPU if we have all the information.
				if (id >= 0 && core >= 0 && socket >= 0)
				{
					results.push_back(CPU(id, core, socket));
					id = -1;
					core = -1;
					socket = -1;
				}
			}
		}

		// Add the last processor if the physical id and core id were not present.
		if (id >= 0)
		{
			// The physical id and core id are not present.
			results.push_back(CPU(id, 0, 0));
		}

		if (file.fail() && !file.eof())
		{
			LOG_ERR << fname << "Failed to read /proc/cpuinfo";
			return std::list<CPU>();
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
	// Returns load struct with average system loads for the last
	// 1, 5 and 15 minutes respectively.
	// Load values should be interpreted as usual average loads from
	// uptime(1).
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

	struct FSusage
	{
		unsigned long size;
		unsigned long used;
		double usage;
	};

	inline std::shared_ptr<FSusage> df(const std::string &path = "/")
	{
		const static char fname[] = "df() ";

		struct statvfs buf;
		if (::statvfs(path.c_str(), &buf) < 0 && buf.f_blocks <= 0)
		{
			LOG_ERR << fname << "Failed to call statvfs";
			return nullptr;
		}
		auto df = std::make_shared<FSusage>();
		df->size = (buf.f_frsize) * buf.f_blocks;
		df->used = (buf.f_frsize) * (buf.f_blocks - buf.f_bfree);
		df->usage = (double)(buf.f_blocks - buf.f_bfree) / buf.f_blocks;
		return df;
	}

	inline std::map<std::string, std::string> getMoundPoints()
	{
		const static char fname[] = "getMoundPoints() ";
		std::map<std::string, std::string> points;
		struct mntent *mountEntryPtr;
		struct mntent mountEntry;
		char buffer[4094] = {0};
		FILE *mountTable = setmntent("/etc/mtab", "r");
		while (true)
		{
			const char *device = NULL;
			const char *mountPoint;
			if (mountTable)
			{
				if (nullptr == (mountEntryPtr = getmntent_r(mountTable, &mountEntry, buffer, sizeof(buffer))))
				{
					endmntent(mountTable);
					break;
				}
			}
			else
			{
				continue;
			}
			device = mountEntryPtr->mnt_fsname;
			mountPoint = mountEntryPtr->mnt_dir;

			struct statvfs buf;
			if (::statvfs(mountPoint, &buf) != 0 || buf.f_blocks <= 0)
			{
				continue;
			}

			std::set<std::string> ignoreFsList = {"tmpfs", "romfs", "ramfs", "devtmpfs", "overlay", "squashfs"};
			if (device && strlen(device) && ignoreFsList.count(mountEntryPtr->mnt_type) == 0 && device[0] == '/')
			{
				LOG_DBG << fname << "device:" << device << " mountPoint:" << mountPoint;
				points[mountPoint] = device;
			}
		}
		return points;
	}

	/**
	 * @brief  get file mode, user and group id
	 * @note
	 * @param  &path: file path
	 * @retval file mode, user id, file group id
	 */
	inline std::tuple<int, int, int> fileStat(const std::string &path)
	{
		const static char fname[] = "fileStat() ";

		struct stat fileStat;
		if (::stat(path.c_str(), &fileStat) >= 0)
		{
			return std::make_tuple(fileStat.st_mode, fileStat.st_uid, fileStat.st_gid);
		}
		else
		{
			LOG_WAR << fname << "Failed stat <" << path << "> with error: " << std::strerror(errno);
			return std::make_tuple(-1, -1, -1);
		}
	}

	inline bool fileChmod(const std::string &path, __mode_t mode)
	{
		const static char fname[] = "fileChmod() ";

		if (mode <= 0U)
		{
			LOG_WAR << fname << "invalid __mode_t: <" << mode << ">";
			return false;
		}

		if (::chmod(path.c_str(), mode) >= 0)
		{
			return true;
		}
		else
		{
			LOG_WAR << fname << "Failed chmod <" << path << "> with error: " << std::strerror(errno);
			return false;
		}
	}

	// chmod with such 755, 777
	inline bool chmod(const std::string &path, int mode)
	{
		const static char fname[] = "chmod() ";

		if ((mode > 777) || (mode < 0))
		{
			LOG_WAR << fname << "Failed chmod <" << path << "> invlid mode value : " << mode;
			return false;
		}
		int mode_u, mode_g, mode_o;
		mode_u = mode / 100;
		mode_g = mode / 10 % 10;
		mode_o = mode % 10;
		mode = (mode_u * 8 * 8) + (mode_g * 8) + mode_o;
		return fileChmod(path, mode);
	}

} // namespace os
