// src/daemon/process/LinuxCgroup.cpp
#include <cstring>
#if defined(__linux__)
#include <mntent.h>
#endif

#include "../../common/Utility.h"
#include "LinuxCgroup.h"

constexpr char CGROUP_APPMESH_DIR[] = "appmesh";
std::string LinuxCgroup::CGROUP_MEMORY_ROOT_DIR;
std::string LinuxCgroup::CGROUP_CPU_ROOT_DIR;
std::string LinuxCgroup::CGROUP_CPUSET_ROOT_DIR;

LinuxCgroup::LinuxCgroup(long long memLimitBytes, long long memSwapBytes, long long cpuShares)
	: m_memLimitMb(memLimitBytes), m_memSwapMb(memSwapBytes), m_cpuShares(cpuShares), m_pid(0), m_cgroupEnabled(false), m_swapLimitSupport(true)
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
#if defined(__linux__)
	m_cgroupEnabled = (m_memLimitMb > 0 || m_memSwapMb > 0 || m_cpuShares > 0);
#endif
	// Only need retrieve once for all
	static bool retrieved = false;
	if (m_cgroupEnabled && !retrieved)
	{
		retrieved = true;
		retrieveCgroupHeirarchy();
		// Check whether swap limit is enabled for OS, by default, Ubuntu does not enable swap limit
		if (!Utility::isFileExist(CGROUP_MEMORY_ROOT_DIR + "/memory.memsw.limit_in_bytes"))
		{
			m_swapLimitSupport = false;
			if (m_memSwapMb > 0)
			{
				LOG_WAR << fname << "Your kernel does not support swap limit capabilities or the cgroup is not mounted.";
			}
		}
	}
	if (!m_swapLimitSupport)
	{
		m_memSwapMb = 0;
	}
}

LinuxCgroup::~LinuxCgroup()
{
	if (m_cgroupEnabled)
	{
		std::string force_empty_file = m_cgroupMemoryPath + "/" + "memory.force_empty";
		if (Utility::isDirExist(m_cgroupMemoryPath))
		{
			writeValue(force_empty_file, 0);
		}

		Utility::removeDir(m_cgroupMemoryPath);
		Utility::removeDir(m_cgroupCpuPath);
	}
}

void LinuxCgroup::setCgroup(const std::string &appName, int pid, int index)
{
	if (!m_cgroupEnabled)
		return;

	m_pid = pid;
	m_cgroupMemoryPath = (fs::path(CGROUP_MEMORY_ROOT_DIR) / CGROUP_APPMESH_DIR / appName / std::to_string(index)).string();
	m_cgroupCpuPath = (fs::path(CGROUP_CPU_ROOT_DIR) / CGROUP_APPMESH_DIR / appName / std::to_string(index)).string();

	const auto perm = fs::perms::owner_all | fs::perms::group_exe | fs::perms::others_exe;
	if (m_memLimitMb > 0 && Utility::createRecursiveDirectory(m_cgroupMemoryPath, perm))
	{
		this->setPhysicalMemory(m_cgroupMemoryPath, m_memLimitMb * 1024 * 1024);
	}

	if (m_memSwapMb > 0 && Utility::createRecursiveDirectory(m_cgroupMemoryPath, perm))
	{
		this->setSwapMemory(m_cgroupMemoryPath, m_memSwapMb * 1024 * 1024);
	}

	if (m_cpuShares > 0 && Utility::createRecursiveDirectory(m_cgroupCpuPath, perm))
	{
		this->setCpuShares(m_cgroupCpuPath, m_cpuShares);
	}
}

long long LinuxCgroup::readHostMemValue(const std::string &cgroupFileName)
{
	return readValue(CGROUP_MEMORY_ROOT_DIR + "/" + cgroupFileName);
}

int LinuxCgroup::readHostCpuSet()
{
	const static char fname[] = "LinuxCgroup::readHostCpuSet() ";

	int cpus = 0;
	auto cpuSets = Utility::readFile(CGROUP_CPUSET_ROOT_DIR + "/" + "cpuset.cpus");
	LOG_DBG << fname << cpuSets;
	auto texts = Utility::splitString(cpuSets, "\r");
	for (auto &line : texts)
	{
		line = Utility::stdStringTrim(line);
		line = Utility::stdStringTrim(line, '\r');
		line = Utility::stdStringTrim(line, '\n');
		if (line.length())
		{
			LOG_DBG << fname << "line: " << line;
			auto comas = Utility::splitString(line, ",");
			for (auto &set : comas)
			{
				set = Utility::stdStringTrim(line);
				set = Utility::stdStringTrim(line, '\r');
				set = Utility::stdStringTrim(line, '\n');

				LOG_DBG << fname << "set: " << set;
				if (set.find("-") != std::string::npos)
				{
					auto duration = Utility::splitString(set, "-");
					if (duration.size() == 2 && Utility::isNumber(duration[0]) && Utility::isNumber(duration[1]))
					{
						cpus = cpus + (std::atoi(duration[1].c_str()) - atoi(duration[0].c_str())) + 1;
					}
					else
					{
						LOG_ERR << fname << "failed to parse duration cpu : " << set;
					}
				}
				else
				{
					if (Utility::isNumber(set))
					{
						cpus++;
					}
					else
					{
						LOG_ERR << fname << "failed to parse single cpu : " << set;
					}
				}
			}
		}
	}
	LOG_DBG << fname << "cpu cores: " << cpus;
	return cpus;
}

bool LinuxCgroup::swapSupport() const
{
	return m_swapLimitSupport;
}

void LinuxCgroup::retrieveCgroupHeirarchy()
{
	const static char fname[] = "LinuxCgroup::retrieveCgroupHeirarchy() ";

	// mount -t cgroup
	std::unique_ptr<FILE, void (*)(FILE *)> fp(fopen("/proc/mounts", "r"), [](FILE *fp)
											   { if (fp) fclose(fp); });
	if (!fp)
	{
		LOG_ERR << fname << "Get file stream failed with error : " << last_error_msg();
		return;
	}
#if defined(__linux__)
	struct mntent *entPtr = nullptr;
	struct mntent entObj;
	char buffer[4094] = {0};
	while (nullptr != (entPtr = getmntent_r(fp.get(), &entObj, buffer, sizeof(buffer))))
	{
		if (std::string("cgroup") != entObj.mnt_type)
		{
			// Ignore none cgroup mount point
			continue;
		}

		if (hasmntopt(&entObj, "memory") && hasmntopt(&entObj, "relatime"))
		{
			// cgroup on /sys/fs/cgroup/memory type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
			CGROUP_MEMORY_ROOT_DIR = entObj.mnt_dir;
			LOG_DBG << fname << "Get memory hierarchy dir : " << CGROUP_MEMORY_ROOT_DIR;
		}

		if (hasmntopt(&entObj, "cpuset") && hasmntopt(&entObj, "relatime"))
		{
			// cgroup on /sys/fs/cgroup/cpuset type cgroup (rw,nosuid,nodev,noexec,relatime,memory)
			CGROUP_CPUSET_ROOT_DIR = entObj.mnt_dir;
			LOG_DBG << fname << "Get cpuset hierarchy dir : " << CGROUP_CPUSET_ROOT_DIR;
		}

		if (hasmntopt(&entObj, "cpu") && hasmntopt(&entObj, "relatime"))
		{
			// get the CPU hierarchy mount point.
			CGROUP_CPU_ROOT_DIR = entObj.mnt_dir;

			// handle "/sys/fs/cgroup/cpu,cpuacct"
			auto found = CGROUP_CPU_ROOT_DIR.find(',');
			if (found != std::string::npos)
			{
				CGROUP_CPU_ROOT_DIR[found] = '\0';
			}
			CGROUP_CPU_ROOT_DIR = CGROUP_CPU_ROOT_DIR.c_str();
			LOG_DBG << fname << "Get cpu hierarchy dir : " << CGROUP_CPU_ROOT_DIR;
		}
	}
#endif
}

void LinuxCgroup::setPhysicalMemory(const std::string &cgroupPath, long long memLimitBytes)
{
	std::string specifiedHeirarchy = cgroupPath + "/" + "memory.limit_in_bytes";
	writeValue(specifiedHeirarchy, memLimitBytes);

	std::string tasksHeirarchy = cgroupPath + "/" + "tasks";
	writeValue(tasksHeirarchy, m_pid);
}

void LinuxCgroup::setSwapMemory(const std::string &cgroupPath, long long memSwapBytes)
{
	std::string specifiedHeirarchy = cgroupPath + "/" + "memory.memsw.limit_in_bytes";
	writeValue(specifiedHeirarchy, memSwapBytes);

	std::string tasksHeirarchy = cgroupPath + "/" + "tasks";
	writeValue(tasksHeirarchy, m_pid);
}

void LinuxCgroup::setCpuShares(const std::string &cgroupPath, long long cpuShares)
{
	std::string specifiedHeirarchy = cgroupPath + "/" + "cpu.shares";
	writeValue(specifiedHeirarchy, cpuShares);

	std::string tasksHeirarchy = cgroupPath + "/" + "tasks";
	writeValue(tasksHeirarchy, m_pid);
}

void LinuxCgroup::writeValue(const std::string &cgroupPath, long long value)
{
	const static char fname[] = "LinuxCgroup::writeValue() ";

	std::unique_ptr<FILE, void (*)(FILE *)> fp(fopen(cgroupPath.c_str(), "w+"), [](FILE *fp)
											   { if (fp) fclose(fp); });
	if (fp)
	{
		if (fprintf(fp.get(), "%lld", value))
		{
			LOG_DBG << fname << "Write <" << value << "> to file <" << cgroupPath << "> success.";
		}
		else
		{
			LOG_ERR << fname << "Write <" << value << "> to file <" << cgroupPath << "> failed with error: " << last_error_msg();
		}
	}
	else
	{
		LOG_ERR << fname << "Failed open file <" << cgroupPath << ">, error: " << last_error_msg();
	}
}

long long LinuxCgroup::readValue(const std::string &cgroupPath)
{
	const static char fname[] = "LinuxCgroup::readValue() ";

	long long value = 0;
	std::unique_ptr<FILE, void (*)(FILE *)> fp(fopen(cgroupPath.c_str(), "r"), [](FILE *fp)
											   { if (fp) fclose(fp); });
	if (fp)
	{
		if (fscanf(fp.get(), "%lld", &value))
		{
			LOG_DBG << fname << "read <" << value << "> from file <" << cgroupPath << "> success.";
		}
		else
		{
			LOG_ERR << fname << "read <" << value << "> from file <" << cgroupPath << "> failed with error: " << last_error_msg();
		}
	}
	else
	{
		LOG_ERR << fname << "Failed open file <" << cgroupPath << ">, error: " << last_error_msg();
	}
	return value;
}
