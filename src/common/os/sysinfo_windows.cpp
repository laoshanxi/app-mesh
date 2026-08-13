// src/common/os/sysinfo_windows.cpp
// Windows-specific system information.

#include "sysinfo.h"

#include <atomic>
#include <map>
#include <mutex>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>

#pragma comment(lib, "Psapi.lib")

#include "../Utility.h"

namespace os
{
	namespace
	{
		struct PageFileTotals
		{
			uint64_t pageSize = 0;
			uint64_t total = 0;
			uint64_t used = 0;
		};

		BOOL CALLBACK collectPageFile(LPVOID context, PENUM_PAGE_FILE_INFORMATION info, LPCWSTR)
		{
			auto &totals = *static_cast<PageFileTotals *>(context);
			totals.total += static_cast<uint64_t>(info->TotalSize) * totals.pageSize;
			totals.used += static_cast<uint64_t>(info->TotalInUse) * totals.pageSize;
			return TRUE;
		}
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
			mem->available_bytes = memStatus.ullAvailPhys;
			SYSTEM_INFO systemInfo{};
			GetSystemInfo(&systemInfo);
			PageFileTotals totals{systemInfo.dwPageSize, 0, 0};
			if (EnumPageFilesW(collectPageFile, &totals))
			{
				mem->totalSwap_bytes = totals.total;
				mem->freeSwap_bytes = totals.used < totals.total ? totals.total - totals.used : 0;
				mem->swapAvailable = true;
			}
		}
		else
		{
			return nullptr;
		}

		return mem;
	}

	std::list<CPU> cpus()
	{
		static std::atomic<bool> initialized(false);
		static std::mutex mutex;
		static std::list<CPU> results;

		if (!initialized.load(std::memory_order_acquire))
		{
			std::lock_guard<std::mutex> lock(mutex);
			if (!initialized.load(std::memory_order_relaxed))
			{
				DWORD bufferSize = 0;
				GetLogicalProcessorInformationEx(RelationAll, nullptr, &bufferSize);
				if (GetLastError() == ERROR_INSUFFICIENT_BUFFER)
				{
					std::vector<unsigned char> buffer(bufferSize);
					if (GetLogicalProcessorInformationEx(RelationAll,
						reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data()), &bufferSize))
					{
						constexpr unsigned int bitsPerGroup = sizeof(KAFFINITY) * 8;
						std::map<unsigned int, unsigned int> sockets;
						unsigned int socketId = 0;
						for (DWORD offset = 0; offset < bufferSize;)
						{
							auto *info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data() + offset);
							if (info->Relationship == RelationProcessorPackage)
							{
								for (WORD groupIndex = 0; groupIndex < info->Processor.GroupCount; ++groupIndex)
								{
									const auto &group = info->Processor.GroupMask[groupIndex];
									for (unsigned int bit = 0; bit < bitsPerGroup; ++bit)
									{
										if (group.Mask & (static_cast<KAFFINITY>(1) << bit))
											sockets[group.Group * bitsPerGroup + bit] = socketId;
									}
								}
								++socketId;
							}
							offset += info->Size;
						}

						unsigned int coreId = 0;
						for (DWORD offset = 0; offset < bufferSize;)
						{
							auto *info = reinterpret_cast<PSYSTEM_LOGICAL_PROCESSOR_INFORMATION_EX>(buffer.data() + offset);
							if (info->Relationship == RelationProcessorCore)
							{
								for (WORD groupIndex = 0; groupIndex < info->Processor.GroupCount; ++groupIndex)
								{
									const auto &group = info->Processor.GroupMask[groupIndex];
									for (unsigned int bit = 0; bit < bitsPerGroup; ++bit)
									{
										if (!(group.Mask & (static_cast<KAFFINITY>(1) << bit)))
											continue;
										const auto processorId = group.Group * bitsPerGroup + bit;
										results.push_back(CPU(processorId, coreId, sockets[processorId]));
									}
								}
								++coreId;
							}
							offset += info->Size;
						}
					}
				}

				if (results.empty())
				{
					const DWORD processorCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
					for (DWORD i = 0; i < processorCount; ++i)
						results.push_back(CPU(i, i, 0));
				}
				initialized.store(true, std::memory_order_release);
			}
		}
		return results;
	}

	std::shared_ptr<Load> loadavg()
	{
		// Windows has no Unix-compatible load average.
		return nullptr;
	}

} // namespace os
