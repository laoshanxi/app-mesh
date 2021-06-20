#pragma once

#include <string>

/// </summary>
/// Linux Cgroup operate interface
/// </summary>
class LinuxCgroup
{
public:
	explicit LinuxCgroup(long long memLimitBytes, long long memSwapBytes, long long cpuShares);
	virtual ~LinuxCgroup();
	void setCgroup(const std::string &appName, int pid, int index);
	long long readHostMemValue(const std::string &cgroupFileName);
	int readHostCpuSet();
	bool swapSupport() const;
	static bool runningInContainer();

private:
	void retrieveCgroupHeirarchy();
	void setPhysicalMemory(const std::string &cgroupPath, long long memLimitBytes);
	void setSwapMemory(const std::string &cgroupPath, long long memSwapBytes);
	void setCpuShares(const std::string &cgroupPath, long long cpuShares);
	void writeValue(const std::string &cgroupPath, long long value);
	long long readValue(const std::string &cgroupPath);

private:
	long long m_memLimitMb;
	long long m_memSwapMb;
	long long m_cpuShares;

	int m_pid;
	std::string m_cgroupMemoryPath;
	std::string m_cgroupCpuPath;
	bool m_cgroupEnabled;
	bool m_swapLimitSupport;

	static std::string CGROUP_MEMORY_ROOT_DIR;
	static std::string CGROUP_CPU_ROOT_DIR;
	static std::string CGROUP_CPUSET_ROOT_DIR;
};
