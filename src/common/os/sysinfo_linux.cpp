// src/common/os/sysinfo_linux.cpp
// Linux-specific system information using /proc and sysinfo.

#include "sysinfo.h"

#include <atomic>
#include <cstdlib>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>

#include <linux/version.h>
#include <sys/sysinfo.h>

#include "../Utility.h"

namespace os
{

	std::shared_ptr<Memory> memory()
	{
		auto mem = std::make_shared<Memory>();

		struct sysinfo info;
		if (sysinfo(&info) != 0)
		{
			return nullptr;
		}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 3, 23))
		mem->total_bytes = static_cast<uint64_t>(info.totalram) * info.mem_unit;
		mem->free_bytes = static_cast<uint64_t>(info.freeram) * info.mem_unit;
		mem->totalSwap_bytes = static_cast<uint64_t>(info.totalswap) * info.mem_unit;
		mem->freeSwap_bytes = static_cast<uint64_t>(info.freeswap) * info.mem_unit;
		mem->swapAvailable = true;
#else
		mem->total_bytes = (info.totalram);
		mem->free_bytes = (info.freeram);
		mem->totalSwap_bytes = (info.totalswap);
		mem->freeSwap_bytes = (info.freeswap);
		mem->swapAvailable = true;
#endif

		// MemAvailable includes reclaimable memory.
		std::ifstream meminfo("/proc/meminfo");
		std::string line;
		std::string key;
		uint64_t valueKb = 0;
		bool availableParsed = false;
		while (std::getline(meminfo, line))
		{
			std::istringstream entry(line);
			if (entry >> key >> valueKb && key == "MemAvailable:")
			{
				mem->available_bytes = valueKb * 1024ULL;
				availableParsed = true;
				break;
			}
		}
		if (!availableParsed)
			mem->available_bytes = mem->free_bytes;

		return mem;
	}

	std::list<CPU> cpus()
	{
		const static char fname[] = "proc::cpus() ";

		static std::atomic<bool> initialized(false);
		static std::mutex mutex;
		static std::list<CPU> results;

		if (!initialized.load(std::memory_order_acquire))
		{
			std::lock_guard<std::mutex> lock(mutex);
			if (!initialized.load(std::memory_order_relaxed))
			{
				std::ifstream file("/proc/cpuinfo");
				if (!file.is_open())
				{
					LOG_ERR << fname << "Failed to open /proc/cpuinfo";
					initialized.store(true, std::memory_order_release);
					return results;
				}

				std::map<int, std::pair<int, int>> cpuInfo;
				int currentId = -1;

				std::string line;
				while (std::getline(file, line))
				{
					size_t pos = line.find(':');
					if (pos == std::string::npos)
					{
						continue;
					}

					std::string key = Utility::stdStringTrim(line.substr(0, pos));
					std::string value = Utility::stdStringTrim(line.substr(pos + 1));

					if (key == "processor")
					{
						try
						{
							currentId = std::stoi(value);
							cpuInfo[currentId] = std::make_pair(-1, -1);
						}
						catch (...)
						{
							currentId = -1;
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
						}
					}
				}

				for (const auto &it : cpuInfo)
				{
					const int cpu = it.first;
					auto topologyValue = [cpu](const char *name) -> int {
						std::ifstream topologyFile("/sys/devices/system/cpu/cpu" + std::to_string(cpu) + "/topology/" + name);
						int value = -1;
						return topologyFile >> value ? value : -1;
					};
					const int core = it.second.first >= 0 ? it.second.first : topologyValue("core_id");
					const int socket = it.second.second >= 0 ? it.second.second : topologyValue("physical_package_id");
					results.push_back(CPU(
						it.first,
						core >= 0 ? core : it.first,
						socket >= 0 ? socket : 0));
				}

				initialized.store(true, std::memory_order_release);
			}
		}

		return results;
	}

	std::shared_ptr<Load> loadavg()
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

} // namespace os
