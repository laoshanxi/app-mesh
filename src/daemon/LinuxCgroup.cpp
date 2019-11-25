#include "LinuxCgroup.h"
#include <cstring>
#include <mntent.h>
#include "../common/Utility.h"


std::string LinuxCgroup::cgroupMemRootName;
std::string LinuxCgroup::cgroupCpuRootName;
const std::string LinuxCgroup::cgroupBaseDir = "/appmanager";
LinuxCgroup::LinuxCgroup(long long memLimitBytes, long long memSwapBytes, long long cpuShares)
	:m_memLimitMb(memLimitBytes), m_memSwapMb(memSwapBytes), m_cpuShares(cpuShares), m_pid(0), cgroupEnabled(false)
{
	const static char fname[] = "LinuxCgroup::LinuxCgroup() ";

	if (m_memLimitMb > 0 && m_memLimitMb < 4)
	{
		m_memLimitMb = 4;
		LOG_WAR << fname << "memory_mb should not less than 4M";
	}
	// It is important to set the "memory.limit_in_bytes" before setting the "memory.memsw.limit_in_bytes"
	if (m_memLimitMb == 0 && m_memSwapMb > 0)
	{
		m_memLimitMb = m_memSwapMb;
		LOG_WAR << fname << "m_memLimitMb is setting to m_memSwapMb";
	}
	cgroupEnabled = (m_memLimitMb > 0 || m_memSwapMb > 0 || m_cpuShares > 0);

	// Only need retrieve once for all
	static bool retrieved = false;
	static bool swapLimitSupport = true;
	if (cgroupEnabled && !retrieved)
	{
		retrieved = true;
		retrieveCgroupHeirarchy();
		// Check whether swap limit is enabled for OS, by default, Ubuntu does not enable swap limit
		if (m_memSwapMb > 0 && !Utility::isFileExist(cgroupMemRootName + "/memory.memsw.limit_in_bytes"))
		{
			LOG_WAR << fname << "Your kernel does not support swap limit capabilities or the cgroup is not mounted.";
			swapLimitSupport = false;
		}
		cgroupMemRootName += cgroupBaseDir;
		cgroupCpuRootName += cgroupBaseDir;
	}
	if (!swapLimitSupport) { m_memSwapMb = 0; }
}

LinuxCgroup::~LinuxCgroup()
{
	if (cgroupEnabled)
	{
		std::string force_empty_file = cgroupMemoryPath + "/" + "memory.force_empty";
		if (Utility::isDirExist(cgroupMemoryPath))
		{
			writeFile(force_empty_file, 0);
		}

		Utility::removeDir(cgroupMemoryPath);
		Utility::removeDir(cgroupCpuPath);
	}
}

void LinuxCgroup::setCgroup(const std::string& appName, int pid, int index)
{
	if (!cgroupEnabled) return;

	m_pid = pid;
	cgroupMemoryPath = cgroupMemRootName + "/" + appName + "/" + std::to_string(index);
	cgroupCpuPath = cgroupCpuRootName + "/" + appName + "/" + std::to_string(index);

	if (m_memLimitMb > 0 && Utility::createRecursiveDirectory(cgroupMemoryPath, 0711))
	{
		this->setPhysicalMemory(cgroupMemoryPath, m_memLimitMb * 1024 * 1024);
	}

	if (m_memSwapMb > 0 && Utility::createRecursiveDirectory(cgroupMemoryPath, 0711))
	{
		this->setSwapMemory(cgroupMemoryPath, m_memSwapMb * 1024 * 1024);
	}

	if (m_cpuShares > 0 && Utility::createRecursiveDirectory(cgroupCpuPath, 0711))
	{
		this->setCpuShares(cgroupCpuPath, m_cpuShares);
	}
}

void LinuxCgroup::retrieveCgroupHeirarchy()
{
	const static char fname[] = "LinuxCgroup::retrieveCgroupHeirarchy() ";

	// mount -t cgroup
	FILE* fp = fopen("/proc/mounts", "r");
	if (nullptr == fp)
	{
		LOG_ERR << fname << "Get file stream failed with error : " << std::strerror(errno);
		return;
	}

	struct mntent* entPtr = nullptr;
	struct mntent entObj;
	char buffer[4094] = { 0 };
	while (nullptr != (entPtr = getmntent_r(fp, &entObj, buffer, sizeof(buffer))))
	{
		if (std::string("cgroup") != entObj.mnt_type)
		{
			// Ignore none cgroup mount point
			continue;
		}

		if (hasmntopt(&entObj, "memory") && hasmntopt(&entObj, "rw") && hasmntopt(&entObj, "relatime"))
		{
			// cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
			cgroupMemRootName = entObj.mnt_dir;
			LOG_DBG << fname << "Get memory hierarchy dir : " << cgroupMemRootName;
		}

		if (hasmntopt(&entObj, "cpu") && hasmntopt(&entObj, "rw") && hasmntopt(&entObj, "relatime"))
		{
			// get the CPU hierarchy mount point.
			cgroupCpuRootName = entObj.mnt_dir;

			//handle "/sys/fs/cgroup/cpu,cpuacct"
			auto found = cgroupCpuRootName.find(',');
			if (found != std::string::npos)
			{
				cgroupCpuRootName[found] = '\0';
			}
			cgroupCpuRootName = cgroupCpuRootName.c_str();
			LOG_DBG << fname << "Get cpu hierarchy dir : " << cgroupCpuRootName;
		}
	}
	if (fp)	fclose(fp);
}

void LinuxCgroup::setPhysicalMemory(const std::string& cgroupPath, long long memLimitBytes)
{
	std::string specifiedHeirarchy = cgroupPath + "/" + "memory.limit_in_bytes";
	writeFile(specifiedHeirarchy, memLimitBytes);

	std::string tasksHeirarchy = cgroupPath + "/" + "tasks";
	writeFile(tasksHeirarchy, m_pid);
}

void LinuxCgroup::setSwapMemory(const std::string& cgroupPath, long long memSwapBytes)
{
	std::string specifiedHeirarchy = cgroupPath + "/" + "memory.memsw.limit_in_bytes";
	writeFile(specifiedHeirarchy, memSwapBytes);

	std::string tasksHeirarchy = cgroupPath + "/" + "tasks";
	writeFile(tasksHeirarchy, m_pid);
}

void LinuxCgroup::setCpuShares(const std::string& cgroupPath, long long cpuShares)
{
	std::string specifiedHeirarchy = cgroupPath + "/" + "cpu.shares";
	writeFile(specifiedHeirarchy, cpuShares);

	std::string tasksHeirarchy = cgroupPath + "/" + "tasks";
	writeFile(tasksHeirarchy, m_pid);
}

void LinuxCgroup::writeFile(const std::string& cgroupPath, long long value)
{
	const static char fname[] = "LinuxCgroup::writeFile() ";

	FILE* fp = fopen(cgroupPath.c_str(), "w+");
	if (fp)
	{
		if (fprintf(fp, "%lld", value))
		{
			LOG_DBG << fname << "Write <" << value << "> to file <" << cgroupPath << "> success.";
		}
		else
		{
			LOG_ERR << fname << "Write <" << value << "> to file <" << cgroupPath << "> failed with error :" << std::strerror(errno);
		}
		fclose(fp);
	}
	else
	{
		LOG_ERR << fname << "Failed open file <" << cgroupPath << ">, error :" << std::strerror(errno);
	}
}
