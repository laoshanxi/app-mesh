// src/common/os/sysinfo.h
#pragma once

#include <cstdint>
#include <list>
#include <memory>
#include <ostream>

namespace os
{
	/// Structure containing memory information.
	struct Memory
	{
		Memory();
		uint64_t total_bytes;
		uint64_t free_bytes;
		uint64_t totalSwap_bytes;
		uint64_t freeSwap_bytes;
	};

	std::ostream &operator<<(std::ostream &stream, const Memory &mem);

	/// Returns the total size of main and free memory.
	std::shared_ptr<Memory> memory();

	/// Get total system CPU time.
	int64_t cpuTotalTime();

	/// Representation of a processor (cross-platform).
	struct CPU
	{
		CPU(unsigned int _id, unsigned int _core, unsigned int _socket);
		unsigned int id;
		unsigned int core;
		unsigned int socket;
	};

	std::ostream &operator<<(std::ostream &stream, const CPU &cpu);

	/// Get information about all CPUs in the system.
	std::list<CPU> cpus();

	/// Structure returned by loadavg(). Encodes system load average
	/// for the last 1, 5 and 15 minutes.
	struct Load
	{
		double one;
		double five;
		double fifteen;
	};

	/// Get system load averages for the last 1, 5, and 15 minutes.
	std::shared_ptr<Load> loadavg();

} // namespace os
