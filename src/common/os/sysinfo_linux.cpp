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

	int64_t cpuTotalTime()
	{
		std::ifstream stat_file("/proc/stat");
		if (!stat_file)
			return 0;

		std::string line;
		std::getline(stat_file, line);

		unsigned long u, n, s, i, w, x, y, z;
		std::string _;
		std::istringstream data(line);
		data >> _ >> u >> n >> s >> i >> w >> x >> y >> z;

		if (data.fail())
		{
			return 0;
		}

		return u + n + s + i + w + x + y + z;
	}

	std::shared_ptr<Memory> memory()
	{
		auto mem = std::make_shared<Memory>();

		struct sysinfo info;
		if (sysinfo(&info) != 0)
		{
			return nullptr;
		}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 3, 23))
		mem->total_bytes = (info.totalram * info.mem_unit);
		mem->free_bytes = (info.freeram * info.mem_unit);
		mem->totalSwap_bytes = (info.totalswap * info.mem_unit);
		mem->freeSwap_bytes = (info.freeswap * info.mem_unit);
#else
		mem->total_bytes = (info.totalram);
		mem->free_bytes = (info.freeram);
		mem->totalSwap_bytes = (info.totalswap);
		mem->freeSwap_bytes = (info.freeswap);
#endif

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
					results.push_back(CPU(
						it.first,
						it.second.first >= 0 ? it.second.first : 0,
						it.second.second >= 0 ? it.second.second : 0));
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
