// src/common/os/process_windows.cpp
// Windows-specific process utilities.

#include "process.h"

#include <unordered_map>
#include <vector>

#define WIN32_LEAN_AND_MEAN
#define UMDF_USING_NTSTATUS
#include <windows.h>
#include <ntstatus.h>
#include <process.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")

#include "../Utility.h"
#include "handler.hpp"

namespace os
{

	static inline HMODULE GetNtdll()
	{
		static HMODULE h = GetModuleHandleW(L"ntdll.dll");
		return h;
	}

	size_t pagesize()
	{
		SYSTEM_INFO sysInfo;
		GetSystemInfo(&sysInfo);
		return static_cast<size_t>(sysInfo.dwPageSize);
	}

	std::shared_ptr<ProcessStatus> status(pid_t pid)
	{
		const static char fname[] = "proc::status() ";

		if (pid <= 0)
		{
			return nullptr;
		}

		HandleRAII hProcess(OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid));
		if (!hProcess.valid())
		{
			LOG_DBG << fname << "Failed to open process: " << pid << " (error=" << GetLastError() << ")";
			return nullptr;
		}

		FILETIME createTime, exitTime, kernelTime, userTime;
		if (!GetProcessTimes(hProcess.get(), &createTime, &exitTime, &kernelTime, &userTime))
		{
			return nullptr;
		}

		PROCESS_MEMORY_COUNTERS memInfo;
		if (!GetProcessMemoryInfo(hProcess.get(), &memInfo, sizeof(memInfo)))
		{
			return nullptr;
		}

		char processName[MAX_PATH] = {};
		DWORD nameSize = MAX_PATH;
		if (!QueryFullProcessImageNameA(hProcess.get(), 0, processName, &nameSize))
		{
			GetModuleBaseNameA(hProcess.get(), NULL, processName, MAX_PATH);
		}

		std::string comm = processName;
		size_t lastSlash = comm.find_last_of("\\/");
		if (lastSlash != std::string::npos)
		{
			comm = comm.substr(lastSlash + 1);
		}

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
			return static_cast<unsigned long>(uli.QuadPart / 10000);
		};

		return std::make_shared<ProcessStatus>(
			pid,
			comm,
			'R',
			ppid,
			0,
			0,
			fileTimeToTicks(userTime),
			fileTimeToTicks(kernelTime),
			0,
			0,
			fileTimeToTimeT(createTime),
			static_cast<unsigned long>(memInfo.PagefileUsage),
			static_cast<long>(memInfo.WorkingSetSize / os::pagesize()));
	}

	std::string cmdline(pid_t pid /* = 0 */)
	{
		const static char fname[] = "proc::cmdline() ";

		if (pid == 0)
		{
			LPSTR cmd = GetCommandLineA();
			return cmd ? std::string(cmd) : std::string();
		}

		HandleRAII hProc(OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid)));
		if (!hProc.valid())
		{
			LOG_WAR << fname << "OpenProcess(pid=" << pid << ") failed: " << last_error_msg();
			return {};
		}

		HMODULE hNtdll = GetNtdll();
		using _NtQueryInformationProcess = NTSTATUS(NTAPI *)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
		static auto NtQueryInformationProcess = reinterpret_cast<_NtQueryInformationProcess>(GetProcAddress(hNtdll, "NtQueryInformationProcess"));
		if (!NtQueryInformationProcess)
		{
			LOG_WAR << fname << "GetProcAddress(NtQueryInformationProcess) failed: " << last_error_msg();
			return {};
		}

		PROCESS_BASIC_INFORMATION pbi = {};
		ULONG retLen = 0;
		NTSTATUS ntStatus = NtQueryInformationProcess(hProc, ProcessBasicInformation, &pbi, sizeof(pbi), &retLen);
		if (ntStatus != 0)
		{
			LOG_WAR << fname << "NtQueryInformationProcess(pid=" << pid << ") failed: " << last_error_msg();
			return {};
		}

		PEB remotePeb = {};
		SIZE_T bytesRead = 0;
		if (!ReadProcessMemory(hProc, pbi.PebBaseAddress, &remotePeb, sizeof(remotePeb), &bytesRead) || bytesRead != sizeof(remotePeb))
		{
			LOG_WAR << fname << "ReadProcessMemory(PEB, pid=" << pid << ") failed: " << last_error_msg();
			return {};
		}

		RTL_USER_PROCESS_PARAMETERS remoteUpp = {};
		if (!ReadProcessMemory(hProc, remotePeb.ProcessParameters, &remoteUpp, sizeof(remoteUpp), &bytesRead) || bytesRead != sizeof(remoteUpp))
		{
			LOG_WAR << fname << "ReadProcessMemory(RTL_USER_PROCESS_PARAMETERS, pid=" << pid << ") failed: " << last_error_msg();
			return {};
		}

		if (remoteUpp.CommandLine.Length == 0 || remoteUpp.CommandLine.Buffer == nullptr)
			return {};

		SIZE_T wcharCount = remoteUpp.CommandLine.Length / sizeof(wchar_t);
		std::wstring wbuf;
		wbuf.resize(wcharCount);

		if (!ReadProcessMemory(hProc, remoteUpp.CommandLine.Buffer, &wbuf[0], remoteUpp.CommandLine.Length, &bytesRead) || bytesRead != remoteUpp.CommandLine.Length)
		{
			LOG_WAR << fname << "ReadProcessMemory(command line, pid=" << pid << ") failed: " << last_error_msg();
			return {};
		}

		if (!wbuf.empty() && wbuf.back() == L'\0')
			wbuf.resize(std::wcslen(wbuf.c_str()));

		int needed = WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(), (int)wbuf.size(), nullptr, 0, nullptr, nullptr);
		if (needed <= 0)
			return {};

		std::string out;
		out.resize(needed);
		int written = WideCharToMultiByte(CP_UTF8, 0, wbuf.c_str(), (int)wbuf.size(), &out[0], needed, nullptr, nullptr);
		if (written <= 0)
			return {};
		return out;
	}

#if !defined(STATUS_INFO_LENGTH_MISMATCH)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004L)
#endif

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

	std::list<Process> processSnapshot(pid_t rootPid)
	{
		const static char fname[] = "proc::processSnapshot() ";
		std::list<Process> result;

		HMODULE hNtdll = GetNtdll();
		using _NtQuerySystemInformation = NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);
		static auto NtQuerySystemInformation = reinterpret_cast<_NtQuerySystemInformation>(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
		if (!NtQuerySystemInformation)
		{
			LOG_ERR << fname << "GetProcAddress(NtQuerySystemInformation) failed: " << last_error_msg();
			return result;
		}

		ULONG bufferSize = 256 * 1024;
		std::vector<BYTE> buffer(bufferSize);
		NTSTATUS ntStatus;
		ULONG needed = 0;
		while ((ntStatus = NtQuerySystemInformation(SystemProcessInformation, buffer.data(), bufferSize, &needed)) == STATUS_INFO_LENGTH_MISMATCH)
		{
			bufferSize = needed + 16 * 1024;
			buffer.resize(bufferSize);
		}
		if (ntStatus < 0)
		{
			LOG_ERR << fname << "NtQuerySystemInformation failed: " << last_error_msg();
			return result;
		}

		// SYSTEM_PROCESS_INFORMATION already carries times, memory, image name
		// and ppid for every process, so the per-process OpenProcess +
		// GetProcessTimes + GetProcessMemoryInfo + Toolhelp snapshot that
		// status() performed (the redundant re-query) is no longer needed.
		struct Light
		{
			pid_t ppid;
			unsigned long utime;
			unsigned long stime;
			long rss;
			std::string comm;
		};
		std::unordered_map<pid_t, Light> byPid;
		std::unordered_map<pid_t, std::vector<pid_t>> children;

		BYTE *ptr = buffer.data();
		while (true)
		{
			auto spi = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(ptr);
			DWORD pid = HandleToUlong(spi->UniqueProcessId);
			DWORD ppid = HandleToUlong(spi->InheritedFromUniqueProcessId);

			if (pid != 0 && pid != 4)
			{
				std::string comm;
				if (spi->ImageName.Buffer != nullptr && spi->ImageName.Length > 0)
				{
					const int wlen = static_cast<int>(spi->ImageName.Length / sizeof(wchar_t));
					const int need8 = WideCharToMultiByte(CP_UTF8, 0, spi->ImageName.Buffer, wlen, nullptr, 0, nullptr, nullptr);
					if (need8 > 0)
					{
						comm.resize(need8);
						WideCharToMultiByte(CP_UTF8, 0, spi->ImageName.Buffer, wlen, &comm[0], need8, nullptr, nullptr);
					}
				}

				Light l;
				l.ppid = static_cast<pid_t>(ppid);
				// 100ns units -> ms, matching status()'s fileTimeToTicks.
				l.utime = static_cast<unsigned long>(spi->UserTime.QuadPart / 10000);
				l.stime = static_cast<unsigned long>(spi->KernelTime.QuadPart / 10000);
				l.rss = static_cast<long>(spi->WorkingSetSize / os::pagesize());
				l.comm = comm;
				byPid[static_cast<pid_t>(pid)] = l;
				children[static_cast<pid_t>(ppid)].push_back(static_cast<pid_t>(pid));
			}

			if (spi->NextEntryOffset == 0)
				break;
			ptr += spi->NextEntryOffset;
		}

		auto selected = collectDescendants(rootPid, children);
		selected.insert(rootPid);

		// command from cmdline (PEB) when available, else the image base name.
		// starttime/vsize are unused by Process, so passed as 0.
		for (pid_t pid : selected)
		{
			auto it = byPid.find(pid);
			if (it == byPid.end())
				continue;
			const Light &l = it->second;
			ProcessStatus st(pid, l.comm, 'R', l.ppid, 0, 0, l.utime, l.stime, 0, 0, 0, 0, l.rss);
			result.push_back(makeProcess(st, os::cmdline(pid)));
		}
		return result;
	}

} // namespace os
