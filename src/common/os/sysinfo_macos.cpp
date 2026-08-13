// src/common/os/sysinfo_macos.cpp
// macOS-specific system information using mach and sysctl.

#include "sysinfo.h"

#include <algorithm>
#include <atomic>
#include <cstdlib>
#include <mutex>

#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/mach_init.h>
#include <mach/mach_types.h>
#include <mach/vm_statistics.h>
#include <sys/sysctl.h>

#include "../Utility.h"

namespace os
{

	std::shared_ptr<Memory> memory()
	{
		auto mem = std::make_shared<Memory>();

		vm_size_t page_size;
		static const auto hostPort = mach_host_self();
		vm_statistics64_data_t vm_stats;
		mach_msg_type_number_t count = sizeof(vm_stats) / sizeof(natural_t);

		if (host_page_size(hostPort, &page_size) != KERN_SUCCESS)
			return nullptr;

		if (host_statistics64(hostPort, HOST_VM_INFO64,
							  (host_info64_t)&vm_stats, &count) != KERN_SUCCESS)
		{
			return nullptr;
		}

		uint64_t total_memory = 0;
		size_t len = sizeof(total_memory);
		if (sysctlbyname("hw.memsize", &total_memory, &len, NULL, 0) != 0)
			return nullptr;

		mem->total_bytes = total_memory;
		mem->free_bytes = (uint64_t)vm_stats.free_count * (uint64_t)page_size;
		mem->available_bytes = std::min<uint64_t>(
			mem->total_bytes,
			(static_cast<uint64_t>(vm_stats.free_count) + static_cast<uint64_t>(vm_stats.inactive_count)) * static_cast<uint64_t>(page_size));

		xsw_usage swap_usage;
		size_t swap_size = sizeof(swap_usage);
		if (sysctlbyname("vm.swapusage", &swap_usage, &swap_size, NULL, 0) == 0)
		{
			mem->totalSwap_bytes = swap_usage.xsu_total;
			mem->freeSwap_bytes = swap_usage.xsu_avail;
			mem->swapAvailable = true;
		}

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
				int num_cores = 0, num_threads = 0;
				size_t len = sizeof(int);

				if (sysctlbyname("hw.physicalcpu", &num_cores, &len, NULL, 0) != 0)
				{
					LOG_ERR << fname << "Failed to query physical CPU count";
					initialized.store(true, std::memory_order_release);
					return results;
				}

				if (sysctlbyname("hw.logicalcpu", &num_threads, &len, NULL, 0) != 0)
				{
					LOG_ERR << fname << "Failed to query logical CPU count";
					initialized.store(true, std::memory_order_release);
					return results;
				}
				if (num_cores <= 0 || num_threads <= 0)
				{
					LOG_ERR << fname << "Invalid physical/logical CPU count";
					initialized.store(true, std::memory_order_release);
					return results;
				}

				for (int i = 0; i < num_threads; ++i)
				{
					// sysctl does not expose per-thread socket IDs; report one package.
					results.push_back(CPU(i, i % num_cores, 0));
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
