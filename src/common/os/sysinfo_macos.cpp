// src/common/os/sysinfo_macos.cpp
// macOS-specific system information using mach and sysctl.

#include "sysinfo.h"

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

	int64_t cpuTotalTime()
	{
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
	}

	std::shared_ptr<Memory> memory()
	{
		auto mem = std::make_shared<Memory>();

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

		mem->total_bytes = total_memory;
		mem->free_bytes = (uint64_t)vm_stats.free_count * (uint64_t)page_size;

		xsw_usage swap_usage;
		size_t swap_size = sizeof(swap_usage);
		if (sysctlbyname("vm.swapusage", &swap_usage, &swap_size, NULL, 0) == 0)
		{
			mem->totalSwap_bytes = swap_usage.xsu_total;
			mem->freeSwap_bytes = swap_usage.xsu_avail;
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

				for (int i = 0; i < num_threads; ++i)
				{
					results.push_back(CPU(i, i % num_cores, i / num_cores));
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
