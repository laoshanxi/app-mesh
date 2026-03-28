// src/common/os/sysinfo_windows.cpp
// Windows-specific system information.

#include "sysinfo.h"

#include <atomic>
#include <mutex>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "../Utility.h"

namespace os
{

	int64_t cpuTotalTime()
	{
		FILETIME idleTime, kernelTime, userTime;
		if (GetSystemTimes(&idleTime, &kernelTime, &userTime))
		{
			auto fileTimeToInt64 = [](const FILETIME &ft) -> int64_t
			{
				ULARGE_INTEGER uli;
				uli.LowPart = ft.dwLowDateTime;
				uli.HighPart = ft.dwHighDateTime;
				return static_cast<int64_t>(uli.QuadPart / 10000);
			};

			// Note: kernelTime already includes idleTime per Windows API docs
			return fileTimeToInt64(kernelTime) + fileTimeToInt64(userTime);
		}
		return 0;
	}

	std::shared_ptr<Memory> memory()
	{
		auto mem = std::make_shared<Memory>();

		MEMORYSTATUSEX memStatus;
		memStatus.dwLength = sizeof(memStatus);
		if (GlobalMemoryStatusEx(&memStatus))
		{
			mem->total_bytes = memStatus.ullTotalPhys;
			mem->free_bytes = memStatus.ullAvailPhys;
			mem->totalSwap_bytes = (memStatus.ullTotalPageFile > memStatus.ullTotalPhys)
								   ? memStatus.ullTotalPageFile - memStatus.ullTotalPhys
								   : 0;
			mem->freeSwap_bytes = (memStatus.ullAvailPageFile > memStatus.ullAvailPhys)
								   ? memStatus.ullAvailPageFile - memStatus.ullAvailPhys
								   : 0;
		}
		else
		{
			return nullptr;
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
				SYSTEM_INFO sysInfo;
				GetSystemInfo(&sysInfo);

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
								DWORD_PTR mask = info.ProcessorMask;
								while (mask)
								{
									if (mask & 1)
									{
										results.push_back(CPU(processorId, processorId, 0));
									}
									mask >>= 1;
									processorId++;
								}
							}
						}
					}
				}

				if (results.empty())
				{
					for (DWORD i = 0; i < sysInfo.dwNumberOfProcessors; ++i)
					{
						results.push_back(CPU(i, i, 0));
					}
				}

				initialized.store(true, std::memory_order_release);
			}
		}

		return results;
	}

	std::shared_ptr<Load> loadavg()
	{
		const static char fname[] = "loadavg() ";

		auto load = std::make_shared<Load>();

		FILETIME idleTime, kernelTime, userTime;
		if (GetSystemTimes(&idleTime, &kernelTime, &userTime))
		{
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
	}

} // namespace os
